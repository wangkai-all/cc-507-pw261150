"""并发验证：撤权与生成/下载同时发生时，策略与单一文件不变式仍然成立。

这些测试使用真实线程 + RealClock（虚拟时钟无法驱动真实 worker 线程），
通过 barrier/事件制造确定性的交错。
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.clock import RealClock
from app.models import Sensitivity, Policy, TaskState
from app.permissions import PermissionService
from app.service import Dataset, ExportConfig, ExportService
from app.snapshots import SnapshotService
from app.storage import FileStore
from tests.conftest import ALL_FIELDS, SENS, make_rows


@pytest.fixture
def real_svc(tmp_path):
    clk = RealClock()
    perms = PermissionService(clk)
    snaps = SnapshotService(clk)
    store = FileStore(str(tmp_path / "blobs"))
    svc = ExportService(
        perms, snaps, store, clock=clk,
        config=ExportConfig(retry_backoff_seconds=0.01, file_retention_seconds=3600),
    )
    svc.register_dataset(Dataset(
        id="employees", tenant_id="tenant-a",
        columns=list(SENS), sensitivities=dict(SENS), rows=make_rows(500),
    ))
    perms.set_baseline("tenant-a", "u1", __import__(
        "app.models", fromlist=["Sensitivity"]).Sensitivity.INTERNAL)
    g_card = perms.create_grant("tenant-a", "u1", Sensitivity.SECRET, 3600, field_name="id_card")
    g_sal = perms.create_grant("tenant-a", "u1", Sensitivity.SECRET, 3600, field_name="salary")
    return svc, perms, {"id_card": g_card, "salary": g_sal}


def _single_blob_invariant(svc, task_id: str) -> None:
    task = svc.require_task(task_id)
    d = svc.store._task_dir(task_id)
    blobs = [n for n in os.listdir(d) if not n.startswith(".tmp-")]
    if task.state == TaskState.READY:
        assert len(blobs) == 1
        assert blobs[0] == task.active_blob
    else:
        assert blobs == []


def test_concurrent_revocation_against_workers_invalidate(real_svc):
    svc, perms, grants = real_svc
    svc.start_workers(count=4)
    try:
        task_ids = []
        for _ in range(20):
            t = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                                  Policy.INVALIDATE)
            task_ids.append(t.id)

        def revoke_loop():
            for gid in grants.values():
                perms.revoke_grant(gid)

        revoker = threading.Thread(target=revoke_loop)
        revoker.start()
        revoker.join()
        svc._queue.join()

        for tid in task_ids:
            task = svc.require_task(tid)
            # 撤权与生成并发：每个任务要么在撤权前 READY（随后被下载闸门/刷新
            # 失效），要么直接 INVALIDATED——不存在“带着明文的就绪文件”
            assert task.state in (TaskState.READY, TaskState.INVALIDATED)
            if task.state == TaskState.READY:
                # READY 的文件只可能生成在撤权生效之前；刷新后必须失效
                svc.refresh_task(tid)
                assert svc.require_task(tid).state == TaskState.INVALIDATED
            _single_blob_invariant(svc, tid)
    finally:
        svc.stop_workers()


def test_concurrent_revocation_against_workers_mask(real_svc):
    svc, perms, grants = real_svc
    svc.start_workers(count=4)
    try:
        task_ids = []
        for _ in range(20):
            t = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                                  Policy.MASK)
            task_ids.append(t.id)
        for gid in grants.values():
            perms.revoke_grant(gid)
        svc._queue.join()

        import csv
        import io
        for tid in task_ids:
            task = svc.require_task(tid)
            assert task.state == TaskState.READY
            data = svc.download(tid, "u1")  # 下载闸门统一脱敏
            rows = list(csv.DictReader(io.StringIO(data.decode())))
            for row in rows:
                assert "MASKED" in row["salary"]
                assert row["id"]  # 公开字段仍明文
            _single_blob_invariant(svc, tid)
    finally:
        svc.stop_workers()


def test_concurrent_downloads_single_rerender(real_svc):
    svc, perms, grants = real_svc
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    svc.drain_queue()
    perms.revoke_grant(grants["salary"])

    results, errors = [], []

    def download():
        try:
            results.append(svc.download(task.id, "u1"))
        except Exception as exc:  # 并发下不应有异常
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(download) for _ in range(8)]
        for f in futures:
            f.result()

    assert errors == []
    t = svc.require_task(task.id)
    # 下载锁保证只重渲染一次：只有 v1（被取代）+ v2（ACTIVE）
    assert [v.version for v in t.versions] == [1, 2]
    assert t.active_version().version == 2
    assert t.active_version().download_count == 8
    _single_blob_invariant(svc, task.id)
    # 所有下载者拿到的是同一份脱敏内容
    assert len({svc.store.checksum(d) for d in results}) == 1


def test_concurrent_revoke_and_download_invalidate(real_svc):
    svc, perms, grants = real_svc
    outcomes = {"downloaded": 0, "denied": 0}
    start = threading.Event()

    def downloader():
        start.wait(timeout=5)
        try:
            svc.download(task_id_holder[0], "u1")
            outcomes["downloaded"] += 1
        except Exception:
            outcomes["denied"] += 1

    def revoker():
        start.wait(timeout=5)
        for gid in grants.values():
            perms.revoke_grant(gid)

    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                             Policy.INVALIDATE)
    svc.drain_queue()
    task_id_holder = [task.id]

    threads = [threading.Thread(target=downloader) for _ in range(6)]
    threads.append(threading.Thread(target=revoker))
    for t in threads:
        t.start()
    start.set()  # 所有线程同时起跑，制造真实交错
    for t in threads:
        t.join(timeout=10)
    assert all(not t.is_alive() for t in threads)

    task = svc.require_task(task.id)
    # 任何线程成功下载后，文件也必须已被失效；绝不能持续可下载明文
    if outcomes["downloaded"]:
        # 下载发生在撤权生效前的瞬间：任务此刻仍应可被刷新失效
        svc.refresh_task(task.id)
    assert svc.require_task(task.id).state == TaskState.INVALIDATED
    assert svc.store.open_active(task.id) is None
    assert outcomes["downloaded"] + outcomes["denied"] == 6


def test_concurrent_create_under_grant_flapping(real_svc):
    svc, perms, grants = real_svc
    stop = threading.Event()

    def flapper():
        # 反复创建/撤销一个新 grant，制造权限版本抖动
        while not stop.is_set():
            gid = perms.create_grant("tenant-a", "u1", Sensitivity.SECRET, 3600, field_name="note")
            perms.revoke_grant(gid)

    t = threading.Thread(target=flapper)
    t.start()
    try:
        for _ in range(30):
            task = svc.create_export("tenant-a", "u1", "employees",
                                     ["id", "name"], Policy.MASK)
            svc.drain_queue()
            assert svc.require_task(task.id).state == TaskState.READY
            _single_blob_invariant(svc, task.id)
    finally:
        stop.set()
        t.join()
