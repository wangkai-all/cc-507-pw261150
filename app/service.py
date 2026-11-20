"""导出编排服务。

职责
====
1. 创建导出任务：实时评估权限，绑定固定数据快照，记录授权命中；
2. 排队/出队/生成：每个关键闸门重新评估权限，按 MASK / INVALIDATE
   策略脱敏或失效；
3. 失败重试：退避后重新入队，原子提交保证只有一个可用文件；
4. 下载：下载前最后一次权限复评，写下载审计；
5. 超时清理：排队/生成超时、文件保留到期、临时授权过期统一由 reaper 处理；
6. 并发控制：任务级 RLock + 服务级锁 + 每任务下载锁，支持并发撤权。
"""

from __future__ import annotations

import os
import queue
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .clock import Clock, RealClock
from .masking import render_csv
from .models import (
    AuditEntry,
    ExportTask,
    FileVersionRecord,
    PermissionDenied,
    Policy,
    Sensitivity,
    TaskNotReady,
    TaskState,
    VersionStatus,
    new_id,
)
from .permissions import FieldAccess, PermissionService
from .snapshots import SnapshotService
from .storage import FileStore


class PermissionRevoked(Exception):
    """渲染检查点发现 INVALIDATE 策略下权限已被收回。"""


@dataclass
class Dataset:
    id: str
    tenant_id: str
    columns: List[str]
    sensitivities: Dict[str, Sensitivity]
    rows: List[Dict[str, object]] = field(default_factory=list)


@dataclass
class ExportConfig:
    max_attempts: int = 3
    retry_backoff_seconds: float = 5.0
    queue_timeout_seconds: float = 300.0       # 排队最长等待
    run_timeout_seconds: float = 120.0         # 单次生成超时
    file_retention_seconds: float = 3600.0     # READY 文件保留期
    grant_grace_seconds: float = 0.0           # 授权过期宽限
    checkpoint_rows: int = 50


class ExportService:
    def __init__(
        self,
        permissions: PermissionService,
        snapshots: SnapshotService,
        store: FileStore,
        clock: Optional[Clock] = None,
        config: Optional[ExportConfig] = None,
    ) -> None:
        self.permissions = permissions
        self.snapshots = snapshots
        self.store = store
        self.clock = clock or RealClock()
        self.config = config or ExportConfig()

        self._lock = threading.RLock()
        self._tasks: Dict[str, ExportTask] = {}
        self._datasets: Dict[str, Dataset] = {}
        self._audit: List[AuditEntry] = []
        self._audit_lock = threading.RLock()

        self._queue: "queue.Queue[Optional[str]]" = queue.Queue()
        self._workers: List[threading.Thread] = []
        self._running = False
        # task_id -> 下载串行锁（防止并发下载重复渲染/重复提交）
        self._download_locks: Dict[str, threading.Lock] = {}

    # ---- 数据集注册 ---------------------------------------------------

    def register_dataset(self, dataset: Dataset) -> None:
        with self._lock:
            self._datasets[dataset.id] = dataset

    def _require_dataset(self, dataset_id: str) -> Dataset:
        ds = self._datasets.get(dataset_id)
        if ds is None:
            raise KeyError(f"数据集不存在: {dataset_id}")
        return ds

    # ---- 审计 ---------------------------------------------------------

    def audit(
        self,
        action: str,
        actor: str,
        task_id: Optional[str],
        detail: Optional[dict] = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            id=new_id("aud"),
            time=self.clock.now(),
            action=action,
            actor=actor,
            task_id=task_id,
            detail=dict(detail or {}),
        )
        with self._audit_lock:
            self._audit.append(entry)
        return entry

    def audit_log(self, task_id: Optional[str] = None) -> List[AuditEntry]:
        with self._audit_lock:
            if task_id is None:
                return list(self._audit)
            return [e for e in self._audit if e.task_id == task_id]

    # ---- 任务查询 -----------------------------------------------------

    def get_task(self, task_id: str) -> Optional[ExportTask]:
        with self._lock:
            return self._tasks.get(task_id)

    def require_task(self, task_id: str) -> ExportTask:
        t = self.get_task(task_id)
        if t is None:
            raise KeyError(f"导出任务不存在: {task_id}")
        return t

    def list_tasks(
        self, tenant_id: Optional[str] = None, user_id: Optional[str] = None
    ) -> List[ExportTask]:
        with self._lock:
            out = list(self._tasks.values())
        if tenant_id is not None:
            out = [t for t in out if t.tenant_id == tenant_id]
        if user_id is not None:
            out = [t for t in out if t.user_id == user_id]
        return sorted(out, key=lambda t: t.created_at)

    def _download_lock(self, task_id: str) -> threading.Lock:
        with self._lock:
            lk = self._download_locks.get(task_id)
            if lk is None:
                lk = threading.Lock()
                self._download_locks[task_id] = lk
            return lk

    # ---- 创建导出 -----------------------------------------------------

    def create_export(
        self,
        tenant_id: str,
        user_id: str,
        dataset_id: str,
        fields: List[str],
        policy: Policy = Policy.MASK,
    ) -> ExportTask:
        """创建导出任务。

        创建时即做一次完整权限评估：任一请求字段无访问权则拒绝（无论
        策略如何——MASK 是“之后被收回”的降级手段，不能用来越权申请）。
        通过后绑定固定快照并入队，授权命中记录随任务持久化用于页面展示。
        """
        dataset = self._require_dataset(dataset_id)
        if dataset.tenant_id != tenant_id:
            raise PermissionDenied("不能跨租户访问数据集")
        unknown = [f for f in fields if f not in dataset.columns]
        if unknown:
            raise PermissionDenied(f"字段不存在: {unknown}")
        if not fields:
            raise PermissionDenied("至少选择一个导出字段")

        access = self.permissions.evaluate(
            tenant_id, user_id, fields, dataset.sensitivities
        )
        denied = [a for a in access if not a.allowed]
        if denied:
            self.audit(
                "export.create_denied",
                user_id,
                None,
                {
                    "tenant_id": tenant_id,
                    "dataset_id": dataset_id,
                    "denied_fields": [a.field for a in denied],
                },
            )
            raise PermissionDenied(
                "以下字段无访问权: " + ", ".join(a.field for a in denied)
            )

        snapshot = self.snapshots.create(
            dataset_id, tenant_id, dataset.columns, dataset.sensitivities, dataset.rows
        )
        now = self.clock.now()
        task = ExportTask(
            id=new_id("task"),
            tenant_id=tenant_id,
            user_id=user_id,
            dataset_id=dataset_id,
            fields=list(fields),
            policy=policy,
            snapshot_id=snapshot.id,
            created_at=now,
            updated_at=now,
            last_checked_at=now,
            permission_version=self.permissions.permission_version,
            gate_hits=[a.as_hit() for a in access],
            grant_ids=[a.grant_id for a in access if a.grant_id],
        )
        with self._lock:
            self._tasks[task.id] = task
        self.audit(
            "export.created",
            user_id,
            task.id,
            {
                "snapshot_id": snapshot.id,
                "policy": policy.value,
                "fields": list(fields),
                "permission_version": task.permission_version,
                "grant_ids": list(task.grant_ids),
            },
        )
        self._enqueue(task.id)
        return task

    # ---- 队列与工作线程 ----------------------------------------------

    def _enqueue(self, task_id: str, delay: float = 0.0) -> None:
        if delay <= 0:
            self._queue.put(task_id)
            return

        def delayed() -> None:
            self.clock.sleep(delay)
            # 退避期间任务可能已被失效/清理，入队后由 worker 再校验
            self._queue.put(task_id)

        threading.Thread(target=delayed, daemon=True).start()

    def start_workers(self, count: int = 2) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            for i in range(count):
                t = threading.Thread(
                    target=self._worker_loop, name=f"export-worker-{i}", daemon=True
                )
                t.start()
                self._workers.append(t)

    def stop_workers(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
        for _ in self._workers:
            self._queue.put(None)

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                task = self.get_task(item)
                if task is None:
                    continue
                now = self.clock.now()
                with task.lock:
                    if task.state.terminal:
                        continue
                    if task.not_before and now < task.not_before:
                        # 退避时间还没到（虚拟时钟下可能出现），重新排队
                        self._enqueue(item, max(0.0, task.not_before - now))
                        continue
                self.run_task(item)
            finally:
                self._queue.task_done()

    def process_next_nowait(self) -> bool:
        """同步处理一个已到期任务（主要供测试使用）。返回是否取到任务。"""
        try:
            item = self._queue.get_nowait()
        except queue.Empty:
            return False
        try:
            if item is not None:
                self.run_task(item)
        finally:
            self._queue.task_done()
        return True

    def drain_queue(self) -> int:
        """同步排空当前队列中所有已到期任务，返回处理数量。"""
        processed = 0
        while self.process_next_nowait():
            processed += 1
        return processed

    # ---- 权限闸门 -----------------------------------------------------

    def _evaluate_task(self, task: ExportTask) -> List[FieldAccess]:
        dataset = self._require_dataset(task.dataset_id)
        return self.permissions.evaluate(
            task.tenant_id, task.user_id, task.fields, dataset.sensitivities
        )

    def _gate(self, task: ExportTask, stage: str) -> List[FieldAccess]:
        """在指定阶段（dequeue / render / download）重新评估权限。

        同时更新任务的权限版本戳与 stale 标记；INVALIDATE 策略下出现
        失权字段直接失效任务，MASK 策略下把访问结果交给调用方降级渲染。
        """
        now = self.clock.now()
        current_version = self.permissions.permission_version
        access = self._evaluate_task(task)
        lost = [a for a in access if not a.allowed]

        with task.lock:
            task.last_checked_at = now
            task.stale = current_version != task.permission_version
            task.permission_version = current_version
            if lost:
                if task.policy == Policy.INVALIDATE:
                    self._invalidate_locked(
                        task,
                        f"{stage} 阶段权限复评失败，失权字段: "
                        + ", ".join(a.field for a in lost),
                    )
                    raise PermissionRevoked(task.invalid_reason)
                self.audit(
                    "export.permission_degraded",
                    task.user_id,
                    task.id,
                    {"stage": stage, "masked_fields": [a.field for a in lost]},
                )
            else:
                task.gate_hits = [a.as_hit() for a in access]
                task.stale = False
        return access

    def _invalidate_locked(self, task: ExportTask, reason: str) -> None:
        """调用方必须持有 task.lock。"""
        if task.state.terminal:
            return
        had_file = task.active_blob is not None
        task.state = TaskState.INVALIDATED
        task.invalid_reason = reason
        task.updated_at = self.clock.now()
        task.progress = 0
        task.not_before = 0.0
        for v in task.versions:
            if v.state == VersionStatus.ACTIVE:
                v.state = VersionStatus.REVOKED
                v.reason = reason
        task.versions.append(
            FileVersionRecord(
                version=len(task.versions) + 1,
                state=VersionStatus.REVOKED,
                created_at=self.clock.now(),
                reason=reason,
            )
        )
        task.active_blob = None
        self.store.revoke(task.id)
        self.audit(
            "export.invalidated",
            task.user_id,
            task.id,
            {"reason": reason, "had_file": had_file},
        )

    def invalidate(self, task_id: str, reason: str) -> ExportTask:
        """外部主动失效（管理员撤权等），并发安全、幂等。"""
        task = self.require_task(task_id)
        with task.lock:
            self._invalidate_locked(task, reason)
        return task

    # ---- 生成 ---------------------------------------------------------

    def run_task(self, task_id: str) -> None:
        """执行一次任务处理（出队后调用，也可直接驱动）。"""
        task = self.require_task(task_id)
        with task.lock:
            if task.state.terminal:
                return
            if task.state == TaskState.READY:
                return
            task.state = TaskState.RUNNING
            task.started_at = self.clock.now()
            task.updated_at = task.started_at
            task.attempts += 1
            task.error = ""

        try:
            access = self._gate(task, "dequeue")
            self._produce_file(task, access)
        except PermissionRevoked as exc:
            self.audit(
                "export.aborted",
                task.user_id,
                task.id,
                {"reason": str(exc)},
            )
        except Exception as exc:  # 生成失败：重试或终结
            self._handle_failure(task, exc)

    def _handle_failure(self, task: ExportTask, exc: Exception) -> None:
        with task.lock:
            task.error = f"{type(exc).__name__}: {exc}"
            if task.attempts >= task.max_attempts:
                task.state = TaskState.FAILED
                task.updated_at = self.clock.now()
                task.not_before = 0.0
                task.versions.append(
                    FileVersionRecord(
                        version=len(task.versions) + 1,
                        state=VersionStatus.FAILED,
                        created_at=self.clock.now(),
                        reason=task.error,
                    )
                )
                self.audit(
                    "export.failed",
                    task.user_id,
                    task.id,
                    {"error": task.error, "attempts": task.attempts},
                )
                return
            backoff = self.config.retry_backoff_seconds * task.attempts
            task.state = TaskState.RETRY_WAIT
            task.updated_at = self.clock.now()
            task.not_before = self.clock.now() + backoff
            task.progress = 0
            self.audit(
                "export.retry_scheduled",
                task.user_id,
                task.id,
                {
                    "attempt": task.attempts,
                    "backoff_seconds": backoff,
                    "error": task.error,
                },
            )
        self._enqueue(task.id, delay=backoff)

    def _produce_file(self, task: ExportTask, initial_access: List[FieldAccess]) -> None:
        """渲染并原子提交文件。

        渲染分批进行，每批结束走检查点重新评估权限：MASK 策略下权限变化
        则带新结论整体重渲染（同一版本槽，旧临时文件丢弃）；INVALIDATE
        策略下直接失效。重启次数受 ``max_attempts`` 约束防止权限抖动死循环。
        """
        snapshot = self.snapshots.require(task.snapshot_id)
        access = initial_access
        restarts = 0
        max_restarts = max(0, task.max_attempts - 1)

        while True:
            tmp_path: Optional[str] = None

            def checkpoint() -> None:
                nonlocal access, restarts, tmp_path
                current_version = self.permissions.permission_version
                if current_version == task.permission_version and not task.stale:
                    return  # 权限无变化，继续渲染
                new_access = self._gate(task, "render")  # 可能抛 PermissionRevoked
                if _access_changed(access, new_access):
                    if restarts >= max_restarts:
                        raise PermissionRevoked("渲染期间权限多次变化，超过重渲染上限")
                    restarts += 1
                    if tmp_path is not None:
                        # 半成品临时文件丢弃，绝不进入提交环节
                        self.store.discard_temp(tmp_path)
                        tmp_path = None
                    access = new_access
                    self.audit(
                        "export.rerender",
                        task.user_id,
                        task.id,
                        {"restart": restarts},
                    )
                    raise _RestartRender()

            total = snapshot.row_count()

            def progress(done: int, n: int) -> None:
                with task.lock:
                    task.progress = 100 if n == 0 else int(done * 100 / n)

            try:
                # 先登记临时路径，检查点才能在权限变化时清理它
                tmp_path = self.store.write_temp(task.id, b"")
                data, hits, masked, checksum = render_csv(
                    task.fields,
                    snapshot.rows,
                    snapshot.sensitivities,
                    access,
                    progress_cb=progress,
                    checkpoint_cb=checkpoint,
                )
                # 覆盖占位临时文件（保持同一写入/提交流程）
                with open(tmp_path, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            except _RestartRender:
                continue
            except BaseException:
                # 渲染失败（含重试前的故障）必须清理临时文件，
                # 保证失败重试不会留下多个半成品文件
                if tmp_path is not None:
                    self.store.discard_temp(tmp_path)
                raise

            with task.lock:
                if task.state.terminal:
                    self.store.discard_temp(tmp_path)
                    return
                version_no = len(task.versions) + 1
                blob_name = self.store.commit(task.id, tmp_path, version_no)
                for v in task.versions:
                    if v.state == VersionStatus.ACTIVE:
                        v.state = VersionStatus.SUPERSEDED
                        v.reason = f"被版本 {version_no} 取代"
                record = FileVersionRecord(
                    version=version_no,
                    state=VersionStatus.ACTIVE,
                    created_at=self.clock.now(),
                    size=len(data),
                    row_count=total,
                    checksum=checksum,
                    masked_fields=masked,
                    reason="渲染期间权限降级，部分字段脱敏" if masked else "",
                    blob_name=blob_name,
                )
                task.versions.append(record)
                task.active_blob = blob_name
                task.render_hits = hits
                task.state = TaskState.READY
                task.progress = 100
                task.ready_at = self.clock.now()
                task.updated_at = task.ready_at
                task.expires_at = task.ready_at + self.config.file_retention_seconds
                self.audit(
                    "export.ready",
                    task.user_id,
                    task.id,
                    {
                        "version": version_no,
                        "blob": blob_name,
                        "size": len(data),
                        "checksum": checksum,
                        "masked_fields": masked,
                        "restarts": restarts,
                    },
                )
            return

    # ---- 下载 ---------------------------------------------------------

    def download(
        self, task_id: str, user_id: str, tenant_id: Optional[str] = None
    ) -> bytes:
        """下载导出文件。

        下载前做最后一次权限复评：
        * INVALIDATE：失权即失效并拒绝下载；
        * MASK：失权则按当前权限重新渲染、原子替换后再返回新文件；
        每次成功/拒绝尝试都写下载审计，文件版本记录下载次数。
        """
        task = self.require_task(task_id)
        if tenant_id is not None and task.tenant_id != tenant_id:
            raise PermissionDenied("跨租户访问被拒绝")
        if task.user_id != user_id:
            raise PermissionDenied("只能下载本人创建的导出任务")

        with self._download_lock(task.id):
            with task.lock:
                if task.state == TaskState.INVALIDATED:
                    self._record_download_denied(task, "任务已失效: " + task.invalid_reason)
                    raise TaskNotReady(task.invalid_reason)
                if task.state == TaskState.EXPIRED:
                    self._record_download_denied(task, "文件已过期清理")
                    raise TaskNotReady("文件已过期")
                if task.state != TaskState.READY:
                    self._record_download_denied(task, f"任务状态为 {task.state.value}")
                    raise TaskNotReady(f"任务尚未就绪: {task.state.label}")

            # 下载闸门复评（不持任务锁，避免渲染期间阻塞状态查询）
            access = self._evaluate_task(task)
            lost = [a for a in access if not a.allowed]
            now = self.clock.now()
            with task.lock:
                task.last_checked_at = now
                task.stale = (
                    self.permissions.permission_version != task.permission_version
                )
                task.permission_version = self.permissions.permission_version

            if lost:
                if task.policy == Policy.INVALIDATE:
                    with task.lock:
                        self._invalidate_locked(
                            task,
                            "下载阶段权限复评失败，失权字段: "
                            + ", ".join(a.field for a in lost),
                        )
                    self._record_download_denied(task, task.invalid_reason)
                    raise TaskNotReady(task.invalid_reason)
                # MASK：仅当当前 ACTIVE 文件的脱敏集合与最新失权集合不一致
                # 时才重新渲染；并发下载在下载锁内串行，已脱敏的版本直接复用，
                # 保证 N 个并发下载只产生一个新版本。
                lost_fields = sorted(a.field for a in lost)
                with task.lock:
                    active = task.active_version()
                    already_masked = (
                        active is not None
                        and sorted(active.masked_fields) == lost_fields
                    )
                if not already_masked:
                    self._rerender_for_download(task, access)
                else:
                    self.audit(
                        "export.download_reused_masked",
                        user_id,
                        task.id,
                        {"masked_fields": lost_fields},
                    )

            data = self.store.open_active(task.id)
            if data is None:
                self._record_download_denied(task, "磁盘上不存在可用文件")
                raise TaskNotReady("文件不存在或已被清理")

            with task.lock:
                active = task.active_version()
                if active is not None:
                    active.download_count += 1
                self.audit(
                    "export.downloaded",
                    user_id,
                    task.id,
                    {
                        "version": active.version if active else None,
                        "size": len(data),
                        "checksum": FileStore.checksum(data),
                    },
                )
            return data

    def _rerender_for_download(
        self, task: ExportTask, access: List[FieldAccess]
    ) -> None:
        snapshot = self.snapshots.require(task.snapshot_id)
        data, hits, masked, checksum = render_csv(
            task.fields, snapshot.rows, snapshot.sensitivities, access
        )
        tmp_path = self.store.write_temp(task.id, data)
        with task.lock:
            if task.state != TaskState.READY:
                self.store.discard_temp(tmp_path)
                return
            version_no = len(task.versions) + 1
            blob_name = self.store.commit(task.id, tmp_path, version_no)
            for v in task.versions:
                if v.state == VersionStatus.ACTIVE:
                    v.state = VersionStatus.SUPERSEDED
                    v.reason = f"下载前权限变化，被脱敏版本 {version_no} 取代"
            task.versions.append(
                FileVersionRecord(
                    version=version_no,
                    state=VersionStatus.ACTIVE,
                    created_at=self.clock.now(),
                    size=len(data),
                    row_count=snapshot.row_count(),
                    checksum=checksum,
                    masked_fields=masked,
                    reason="下载前权限降级，重新脱敏渲染",
                    blob_name=blob_name,
                )
            )
            task.active_blob = blob_name
            task.render_hits = hits
            task.updated_at = self.clock.now()
            self.audit(
                "export.download_rerender",
                task.user_id,
                task.id,
                {"version": version_no, "masked_fields": masked},
            )

    def _record_download_denied(self, task: ExportTask, reason: str) -> None:
        self.audit(
            "export.download_denied",
            task.user_id,
            task.id,
            {"reason": reason, "state": task.state.value},
        )

    # ---- 主动刷新与超时清理 ------------------------------------------

    def refresh_task(self, task_id: str) -> ExportTask:
        """按当前权限重新评估任务（页面轮询/定时检查调用）。

        非终态任务：INVALIDATE 失权即失效；MASK 失权标记 stale 并记录。
        READY 任务的文件替换仍延迟到下载时进行，避免无访问时产生多余渲染。
        """
        task = self.require_task(task_id)
        with task.lock:
            if task.state.terminal:
                return task
        access = self._evaluate_task(task)
        lost = [a for a in access if not a.allowed]
        now = self.clock.now()
        with task.lock:
            task.last_checked_at = now
            task.stale = (
                self.permissions.permission_version != task.permission_version
            )
            task.permission_version = self.permissions.permission_version
            if lost and task.policy == Policy.INVALIDATE:
                self._invalidate_locked(
                    task,
                    "权限刷新发现失权字段: " + ", ".join(a.field for a in lost),
                )
                return task
            if lost:
                self.audit(
                    "export.permission_degraded",
                    task.user_id,
                    task.id,
                    {"stage": "refresh", "masked_fields": [a.field for a in lost]},
                )
            elif task.state != TaskState.RUNNING:
                task.gate_hits = [a.as_hit() for a in access]
                task.stale = False
        return task

    def reap_timeouts(self) -> List[str]:
        """超时清理，返回被处理的任务 id 列表。幂等，可反复调用。

        * QUEUED 超过 ``queue_timeout_seconds`` 未被处理 → 失效；
        * RUNNING 超过 ``run_timeout_seconds`` → 按失败重试，次数耗尽则 FAILED；
        * READY 文件超过保留期（或绑定的临时授权全部失效且无宽限）→ 过期下线；
        * RETRY_WAIT 的退避时间已到 → 重新入队。
        """
        now = self.clock.now()
        handled: List[str] = []
        for task in self.list_tasks():
            with task.lock:
                state = task.state
                if state == TaskState.QUEUED:
                    if now - task.updated_at >= self.config.queue_timeout_seconds:
                        self._invalidate_locked(task, "排队超时，任务被清理")
                        handled.append(task.id)
                elif state == TaskState.RUNNING:
                    if task.started_at is not None and (
                        now - task.started_at >= self.config.run_timeout_seconds
                    ):
                        # 保持 RUNNING 状态交给统一失败处理（重试或终结）
                        self._handle_failure(
                            task, TimeoutError("生成超时，超过单次运行时限")
                        )
                        handled.append(task.id)
                elif state == TaskState.RETRY_WAIT:
                    if task.not_before and now >= task.not_before:
                        task.state = TaskState.QUEUED
                        task.updated_at = now
                        task.not_before = 0.0
                        self._enqueue(task.id)
                        handled.append(task.id)
                elif state == TaskState.READY:
                    expired = (
                        task.expires_at is not None and now >= task.expires_at
                    )
                    grants_dead = bool(task.grant_ids) and not (
                        self.permissions.depends_on_grants(
                            task.tenant_id, task.user_id, task.grant_ids
                        )
                    )
                    if grants_dead:
                        # 记录授权首次失效时间，宽限期从该点起算；
                        # 必须先更新再判定，否则发现失效的那一轮会被立刻清理
                        if task.grants_dead_since is None:
                            task.grants_dead_since = now
                        grace_elapsed = (
                            now - task.grants_dead_since
                            >= self.config.grant_grace_seconds
                        )
                    else:
                        task.grants_dead_since = None
                        grace_elapsed = False
                    if expired or (grants_dead and grace_elapsed):
                        reason = "文件保留期到期" if expired else "依赖的临时授权已全部失效"
                        self._expire_locked(task, reason)
                        handled.append(task.id)
        return handled

    def _expire_locked(self, task: ExportTask, reason: str) -> None:
        for v in task.versions:
            if v.state == VersionStatus.ACTIVE:
                v.state = VersionStatus.REVOKED
                v.reason = reason
        task.state = TaskState.EXPIRED
        task.invalid_reason = reason
        task.updated_at = self.clock.now()
        task.active_blob = None
        self.store.revoke(task.id)
        self.audit(
            "export.expired",
            task.user_id,
            task.id,
            {"reason": reason},
        )


class _RestartRender(Exception):
    """内部信号：检查点发现权限变化，需要带新结论从头重渲染。"""


def _access_changed(old: List[FieldAccess], new: List[FieldAccess]) -> bool:
    old_map = {a.field: a.allowed for a in old}
    return any(old_map.get(a.field) != a.allowed for a in new)
