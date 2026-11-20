"""权限在排队、生成、下载之间变化时的 MASK / INVALIDATE 策略验证。"""

import csv
import io

import pytest

from app.models import (
    Policy,
    TaskState,
    VersionStatus,
)
from tests.conftest import ALL_FIELDS


def _csv_rows(data: bytes):
    return list(csv.DictReader(io.StringIO(data.decode())))


def _is_masked(value: str) -> bool:
    """脱敏判定：占位 token、打码串（含 *）均视为已脱敏。"""
    return "MASKED" in value or "*" in value


# ---- 排队阶段（出队闸门） ---------------------------------------------

def test_invalidate_while_queued_makes_task_terminal(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                             Policy.INVALIDATE)
    perms = svc.permissions
    perms.revoke_grant(grants["salary"])
    perms.revoke_grant(grants["id_card"])
    svc.drain_queue()
    task = svc.require_task(task.id)
    assert task.state == TaskState.INVALIDATED
    assert "salary" in task.invalid_reason
    assert svc.store.open_active(task.id) is None
    assert any(e.action == "export.invalidated" for e in svc.audit_log(task.id))


def test_mask_while_queued_renders_masked_file(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    svc.permissions.revoke_grant(grants["salary"])
    svc.drain_queue()
    task = svc.require_task(task.id)
    assert task.state == TaskState.READY
    assert task.active_version().masked_fields == ["salary"]
    data = svc.download(task.id, "u1")
    rows = _csv_rows(data)
    assert rows[0]["id"] == "1"                      # 公开字段保持明文
    assert "20001" not in rows[0]["salary"]          # 绝密字段已脱敏
    assert "MASKED" in rows[0]["salary"]


# ---- 生成阶段（渲染检查点） -------------------------------------------

def test_invalidate_during_render_aborts_generation(svc, grants, monkeypatch):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                             Policy.INVALIDATE)
    perms = svc.permissions

    real_render = __import__("app.masking", fromlist=["render_csv"]).render_csv

    def revoke_midway(columns, rows, sens, access, **kwargs):
        service_checkpoint = kwargs.get("checkpoint_cb")

        def checkpoint():
            perms.revoke_grant(grants["salary"])
            if service_checkpoint:
                service_checkpoint()  # 触发服务端复评闸门 → INVALIDATE

        return real_render(columns, rows, sens, access,
                           progress_cb=kwargs.get("progress_cb"),
                           checkpoint_cb=checkpoint)

    monkeypatch.setattr("app.service.render_csv", revoke_midway)
    svc.drain_queue()
    task = svc.require_task(task.id)
    assert task.state == TaskState.INVALIDATED
    assert svc.store.open_active(task.id) is None
    # 渲染中途的临时文件已被清理
    import os
    d = svc.store._task_dir(task.id)
    assert all(not n.startswith(".tmp-") for n in os.listdir(d))


def test_mask_during_render_restarts_and_commits_one_file(svc, grants, monkeypatch):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    perms = svc.permissions
    state = {"revoked": False}

    real_render = __import__("app.masking", fromlist=["render_csv"]).render_csv

    def revoke_on_first_checkpoint(columns, rows, sens, access, **kwargs):
        inner_checkpoint = kwargs.get("checkpoint_cb")
        progress = kwargs.get("progress_cb")

        def checkpoint():
            if not state["revoked"]:
                state["revoked"] = True
                perms.revoke_grant(grants["id_card"])
            if inner_checkpoint:
                inner_checkpoint()  # 触发服务端检查点 → 重渲染

        return real_render(columns, rows, sens, access,
                           progress_cb=progress, checkpoint_cb=checkpoint)

    monkeypatch.setattr("app.service.render_csv", revoke_on_first_checkpoint)
    svc.drain_queue()
    task = svc.require_task(task.id)
    assert task.state == TaskState.READY
    assert task.active_version().masked_fields == ["id_card"]
    # 重渲染被审计
    assert any(e.action == "export.rerender" for e in svc.audit_log(task.id))
    data = svc.download(task.id, "u1")
    rows = _csv_rows(data)
    assert rows[0]["id_card"].startswith("*")
    assert rows[0]["salary"] == "20001"  # salary 授权仍在，保持明文
    # 磁盘只有一个 blob
    import os
    files = [n for n in os.listdir(svc.store._task_dir(task.id))
             if not n.startswith(".tmp-")]
    assert files == [task.active_blob]


# ---- 下载阶段（下载闸门） ---------------------------------------------

def test_invalidate_on_download_revokes_file(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                             Policy.INVALIDATE)
    svc.drain_queue()
    assert svc.store.open_active(task.id) is not None
    svc.permissions.revoke_grant(grants["salary"])
    with pytest.raises(Exception):
        svc.download(task.id, "u1")
    task = svc.require_task(task.id)
    assert task.state == TaskState.INVALIDATED
    assert svc.store.open_active(task.id) is None
    # 原 ACTIVE 版本转为 REVOKED 元数据
    assert any(v.state == VersionStatus.REVOKED for v in task.versions)
    assert any(e.action == "export.download_denied"
               for e in svc.audit_log(task.id))


def test_mask_on_download_rerenders_and_supersedes_old_version(svc, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    svc.drain_queue()
    first_blob = task.active_blob
    first_checksum = task.active_version().checksum

    svc.permissions.revoke_grant(grants["salary"])
    data = svc.download(task.id, "u1")
    rows = _csv_rows(data)
    assert "MASKED" in rows[0]["salary"]

    task = svc.require_task(task.id)
    active = task.active_version()
    assert active.version == 2
    assert active.masked_fields == ["salary"]
    assert active.checksum != first_checksum
    # 旧版本被标记取代，旧 blob 已删除——任何时刻只有一个可用文件
    assert task.versions[0].state == VersionStatus.SUPERSEDED
    assert svc.store.active_blob_name(task.id) != first_blob
    import os
    files = os.listdir(svc.store._task_dir(task.id))
    assert first_blob not in files
    assert any(e.action == "export.download_rerender"
               for e in svc.audit_log(task.id))


def test_refresh_marks_stale_and_invalidates_per_policy(svc, grants):
    t_mask = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    t_inv = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS,
                              Policy.INVALIDATE)
    svc.drain_queue()
    svc.permissions.revoke_grant(grants["id_card"])
    svc.refresh_task(t_mask.id)
    svc.refresh_task(t_inv.id)
    t_mask = svc.require_task(t_mask.id)
    t_inv = svc.require_task(t_inv.id)
    assert t_mask.stale is True and t_mask.state == TaskState.READY
    assert t_inv.state == TaskState.INVALIDATED
    # MASK 任务的文件在下载时才替换，刷新不产生多余渲染
    assert len(t_mask.versions) == 1


def test_grant_expiry_treated_as_permission_change(svc, grants, clk):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    svc.drain_queue()
    clk.advance(3601)  # grant TTL 到期
    data = svc.download(task.id, "u1")
    rows = _csv_rows(data)
    assert _is_masked(rows[0]["salary"]) and _is_masked(rows[0]["id_card"])
    task = svc.require_task(task.id)
    assert task.active_version().version == 2


def test_baseline_revocation_also_gated(svc):
    # 只用基线字段的任务：降级基线同样触发闸门
    from tests.conftest import BASE_FIELDS
    task = svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS,
                             Policy.INVALIDATE)
    svc.drain_queue()
    svc.permissions.set_baseline("tenant-a", "u1", __import__(
        "app.models", fromlist=["Sensitivity"]).Sensitivity.PUBLIC)
    svc.refresh_task(task.id)
    assert svc.require_task(task.id).state == TaskState.INVALIDATED
