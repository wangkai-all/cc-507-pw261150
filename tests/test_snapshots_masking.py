"""快照不可变性与脱敏渲染规则。"""

from app.masking import MASK_TOKEN, mask_value, render_csv
from app.models import HitSource, Policy, Sensitivity
from app.permissions import FieldAccess


def test_snapshot_is_deep_copied_and_immutable(svc, snaps):
    rows = [{"id": 1, "name": "原始"}]
    snap = snaps.create("ds", "tenant-a", ["id", "name"],
                        {"id": Sensitivity.PUBLIC, "name": Sensitivity.INTERNAL}, rows)
    rows[0]["name"] = "被篡改"
    rows.append({"id": 2, "name": "新增"})
    assert snap.rows[0]["name"] == "原始"
    assert snap.row_count() == 1


def test_snapshot_bound_at_creation_stays_fixed(svc, snaps, grants):
    task = svc.create_export("tenant-a", "u1", "employees",
                             ["id", "name", "id_card"], Policy.MASK)
    snap = snaps.require(task.snapshot_id)
    # 源数据集之后变化，快照不受影响
    svc._datasets["employees"].rows.clear()
    svc.drain_queue()
    data = svc.download(task.id, "u1")
    lines = data.decode().strip().splitlines()
    assert len(lines) == snap.row_count() + 1  # 含表头


def test_mask_value_levels():
    assert mask_value("abc", Sensitivity.PUBLIC) == "abc"
    assert mask_value("abc", Sensitivity.INTERNAL) == MASK_TOKEN
    assert mask_value("123456", Sensitivity.CONFIDENTIAL) == "****56"
    assert mask_value("ab", Sensitivity.CONFIDENTIAL) == MASK_TOKEN
    secret = mask_value("123456789", Sensitivity.SECRET)
    assert "123" not in secret and "len=9" in secret
    assert mask_value(None, Sensitivity.SECRET) == ""


def _access(columns, sens, allowed_fields):
    return [
        FieldAccess(
            field=f,
            sensitivity=sens[f],
            allowed=f in allowed_fields,
            source=HitSource.BASELINE if f in allowed_fields else HitSource.DENIED,
            grant_id=None,
        )
        for f in columns
    ]


def test_render_csv_masks_denied_columns_and_reports_hits():
    cols = ["id", "name", "salary"]
    sens = {"id": Sensitivity.PUBLIC, "name": Sensitivity.INTERNAL,
            "salary": Sensitivity.SECRET}
    rows = [{"id": 1, "name": "张三", "salary": 9999}]
    data, hits, masked, checksum = render_csv(
        cols, rows, sens, _access(cols, sens, ["id", "name"])
    )
    text = data.decode()
    assert "张三" in text and "9999" not in text
    assert "salary" in text and MASK_TOKEN in text
    assert masked == ["salary"]
    assert {h.field: h.source for h in hits}["salary"] == HitSource.MASKED
    assert len(checksum) == 64


def test_render_progress_and_checkpoint_callbacks():
    cols = ["id"]
    sens = {"id": Sensitivity.PUBLIC}
    rows = [{"id": i} for i in range(250)]
    progress_calls = []
    checkpoints = []
    render_csv(
        cols, rows, sens, _access(cols, sens, ["id"]),
        progress_cb=lambda done, total: progress_calls.append((done, total)),
        checkpoint_cb=lambda: checkpoints.append(1),
    )
    assert progress_calls[-1] == (250, 250)
    assert progress_calls[0][0] <= 100  # 按批回调
    assert len(checkpoints) >= 3
