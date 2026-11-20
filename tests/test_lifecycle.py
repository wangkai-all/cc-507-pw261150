"""导出任务生命周期：创建、授权命中、进度、就绪、下载审计、重试不变式。"""

import csv
import io

import pytest

from app.models import (
    HitSource,
    PermissionDenied,
    Policy,
    TaskNotReady,
    TaskState,
    VersionStatus,
)
from tests.conftest import ALL_FIELDS, BASE_FIELDS


def _csv_rows(data: bytes):
    return list(csv.DictReader(io.StringIO(data.decode())))


def test_create_denied_without_clearance(svc):
    # u1 基线 INTERNAL，申请 SECRET 字段且无 grant → 拒绝
    with pytest.raises(PermissionDenied):
        svc.create_export("tenant-a", "u1", "employees", ["salary"], Policy.MASK)
    actions = [e.action for e in svc.audit_log()]
    assert "export.create_denied" in actions
    assert svc.list_tasks() == []  # 拒绝不产生任务


def test_cross_tenant_and_cross_user_denied(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)
    with pytest.raises(PermissionDenied):
        svc.create_export("tenant-b", "u1", "employees", BASE_FIELDS, Policy.MASK)
    svc.drain_queue()
    with pytest.raises(PermissionDenied):
        svc.download(task.id, "u2")
    with pytest.raises(PermissionDenied):
        svc.download(task.id, "u1", tenant_id="tenant-b")


def test_grant_hits_recorded_on_creation(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    sources = {h.field: h.source for h in task.gate_hits}
    assert sources["id"] == HitSource.BASELINE
    assert sources["id_card"] == HitSource.GRANT
    assert sources["salary"] == HitSource.GRANT
    grant_of_salary = next(h for h in task.gate_hits if h.field == "salary")
    assert grant_of_salary.grant_id == grants["salary"]
    assert set(task.grant_ids) == set(grants.values())


def test_happy_path_progress_ready_and_download_audit(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    assert task.state == TaskState.QUEUED
    assert svc.drain_queue() == 1
    task = svc.require_task(task.id)
    assert task.state == TaskState.READY
    assert task.progress == 100
    assert task.active_version().state == VersionStatus.ACTIVE
    assert task.active_version().row_count == 200
    assert task.active_version().masked_fields == []

    data = svc.download(task.id, "u1")
    rows = _csv_rows(data)
    assert len(rows) == 200
    assert rows[0]["salary"] == "20001"  # 授权有效，明文导出

    task = svc.require_task(task.id)
    assert task.active_version().download_count == 1
    downloaded = [e for e in svc.audit_log(task.id) if e.action == "export.downloaded"]
    assert len(downloaded) == 1
    assert downloaded[0].detail["checksum"] == task.active_version().checksum


def test_download_before_ready_rejected_and_audited(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)
    with pytest.raises(TaskNotReady):
        svc.download(task.id, "u1")
    assert any(
        e.action == "export.download_denied" for e in svc.audit_log(task.id)
    )


def test_failure_retry_eventually_succeeds_single_blob(svc, grants, monkeypatch):
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)

    calls = {"n": 0}
    real_render = __import__("app.masking", fromlist=["render_csv"]).render_csv

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("渲染器瞬时故障")
        return real_render(*args, **kwargs)

    monkeypatch.setattr("app.service.render_csv", flaky)
    svc.drain_queue()  # 第一次失败 → RETRY_WAIT
    task = svc.require_task(task.id)
    assert task.state == TaskState.RETRY_WAIT
    assert task.attempts == 1
    assert task.not_before > svc.clock.now()
    # 退避未到：reaper 不会提前重入队
    assert svc.reap_timeouts() == []
    svc.clock.advance(svc.config.retry_backoff_seconds + 1)
    assert svc.reap_timeouts() == [task.id]  # 退避到期重新入队
    svc.drain_queue()  # 第二次仍失败
    svc.clock.advance(svc.config.retry_backoff_seconds * 2 + 1)
    svc.reap_timeouts()
    svc.drain_queue()  # 第三次成功
    task = svc.require_task(task.id)
    assert task.state == TaskState.READY
    assert task.attempts == 3
    # 只有一个 ACTIVE 版本、磁盘只有一个 blob
    active = [v for v in task.versions if v.state == VersionStatus.ACTIVE]
    assert len(active) == 1
    assert svc.store.open_active(task.id) is not None
    # 没有遗留临时文件
    import os
    d = svc.store._task_dir(task.id)
    assert all(not n.startswith(".tmp-") for n in os.listdir(d))


def test_failure_exhausts_attempts_no_file_ever_available(svc, grants, monkeypatch):
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)

    def boom(*args, **kwargs):
        raise RuntimeError("永久故障")

    monkeypatch.setattr("app.service.render_csv", boom)
    for _ in range(5):  # 反复推进+排空，超过 max_attempts
        svc.drain_queue()
        svc.clock.advance(svc.config.retry_backoff_seconds * 3 + 1)
        svc.reap_timeouts()
    task = svc.require_task(task.id)
    assert task.state == TaskState.FAILED
    assert task.attempts == svc.config.max_attempts
    assert svc.store.open_active(task.id) is None
    with pytest.raises(TaskNotReady):
        svc.download(task.id, "u1")
    # FAILED 版本只留元数据，没有 blob
    failed = [v for v in task.versions if v.state == VersionStatus.FAILED]
    assert failed and failed[-1].blob_name is None


def test_run_task_is_idempotent_after_ready(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)
    svc.drain_queue()
    svc.run_task(task.id)  # 重复驱动不产生新版本
    task = svc.require_task(task.id)
    assert len(task.versions) == 1
    assert task.attempts == 1


def test_snapshot_fixed_even_when_dataset_mutates(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)
    svc.drain_queue()
    svc._datasets["employees"].rows = svc._datasets["employees"].rows[:5]
    data = svc.download(task.id, "u1")
    assert len(_csv_rows(data)) == 200  # 仍是快照里的 200 行
