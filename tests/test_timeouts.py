"""超时清理：排队超时、生成超时重试、文件保留期、授权过期清理。"""

import pytest

from app.models import Policy, TaskState, VersionStatus


def test_queued_task_timeout_invalidates(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name"], Policy.MASK)
    # 故意不 drain，让任务一直 QUEUED
    svc.clock.advance(svc.config.queue_timeout_seconds + 1)
    handled = svc.reap_timeouts()
    assert handled == [task.id]
    task = svc.require_task(task.id)
    assert task.state == TaskState.INVALIDATED
    assert "排队超时" in task.invalid_reason
    # 再跑一次 reaper 幂等，不重复处理
    assert svc.reap_timeouts() == []


def test_running_timeout_retries_then_succeeds(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name"], Policy.MASK)
    # 构造一个已超时的 RUNNING 任务（模拟 worker 卡死）
    task.state = TaskState.RUNNING
    task.started_at = svc.clock.now() - svc.config.run_timeout_seconds - 10
    task.updated_at = task.started_at
    task.attempts = 1

    handled = svc.reap_timeouts()
    assert task.id in handled
    task = svc.require_task(task.id)
    assert task.state == TaskState.RETRY_WAIT and task.attempts == 1
    assert "生成超时" in task.error

    # 退避到期后重新入队，正常渲染成功
    svc.clock.advance(svc.config.retry_backoff_seconds + 1)
    svc.reap_timeouts()
    svc.drain_queue()
    assert svc.require_task(task.id).state == TaskState.READY
    assert svc.require_task(task.id).attempts == 2


def test_running_timeout_exhausts_to_failed(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name"], Policy.MASK)
    for attempt in range(1, svc.config.max_attempts + 1):
        task.state = TaskState.RUNNING
        task.started_at = svc.clock.now() - svc.config.run_timeout_seconds - 1
        task.updated_at = task.started_at
        task.attempts = attempt
        svc.reap_timeouts()
        if attempt < svc.config.max_attempts:
            assert svc.require_task(task.id).state == TaskState.RETRY_WAIT
            svc.clock.advance(svc.config.retry_backoff_seconds * attempt + 1)
            svc.reap_timeouts()  # 退避到期重新入队
    task = svc.require_task(task.id)
    assert task.state == TaskState.FAILED
    assert task.attempts == svc.config.max_attempts
    assert svc.store.open_active(task.id) is None


def test_ready_file_expires_after_retention(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name"], Policy.MASK)
    svc.drain_queue()
    assert svc.require_task(task.id).state == TaskState.READY
    svc.clock.advance(svc.config.file_retention_seconds + 1)
    assert svc.reap_timeouts() == [task.id]
    task = svc.require_task(task.id)
    assert task.state == TaskState.EXPIRED
    assert svc.store.open_active(task.id) is None
    assert task.versions[-1].state == VersionStatus.REVOKED
    assert any(e.action == "export.expired" for e in svc.audit_log(task.id))
    # 过期后无法下载
    from app.models import TaskNotReady
    with pytest.raises(TaskNotReady):
        svc.download(task.id, "u1")


def test_grant_expiry_reaps_ready_file_with_zero_grace(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name", "salary"], Policy.MASK)
    svc.drain_queue()
    assert task.grant_ids  # 依赖 salary 的 grant
    svc.clock.advance(3601)  # grant 过期，但文件保留期未到
    assert svc.reap_timeouts() == [task.id]
    assert svc.require_task(task.id).state == TaskState.EXPIRED


def test_grant_expiry_respects_grace_period(svc, grants):
    svc.config.grant_grace_seconds = 120
    svc.config.file_retention_seconds = 7200  # 长于 grant TTL，确保由授权失效驱动
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name", "salary"], Policy.MASK)
    svc.drain_queue()
    svc.clock.advance(3601)
    assert svc.reap_timeouts() == []  # 宽限内不清理
    assert svc.require_task(task.id).state == TaskState.READY
    svc.clock.advance(121)
    assert svc.reap_timeouts() == [task.id]
    assert svc.require_task(task.id).state == TaskState.EXPIRED


def test_retry_wait_requeue_only_after_backoff(svc, grants, monkeypatch):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name"], Policy.MASK)

    def fail_once(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.service.render_csv", fail_once)
    svc.drain_queue()
    task = svc.require_task(task.id)
    assert task.state == TaskState.RETRY_WAIT
    # 未到退避点：reaper 不动它
    svc.clock.advance(svc.config.retry_backoff_seconds - 1)
    assert svc.reap_timeouts() == []
    assert svc.require_task(task.id).state == TaskState.RETRY_WAIT
