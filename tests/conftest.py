"""共享测试夹具：虚拟时钟 + 全套服务 + 示例数据集。"""

from __future__ import annotations


import pytest

from app.clock import FakeClock
from app.models import Sensitivity
from app.permissions import PermissionService
from app.service import Dataset, ExportConfig, ExportService
from app.snapshots import SnapshotService
from app.storage import FileStore

SENS = {
    "id": Sensitivity.PUBLIC,
    "name": Sensitivity.INTERNAL,
    "dept": Sensitivity.INTERNAL,
    "id_card": Sensitivity.CONFIDENTIAL,
    "salary": Sensitivity.SECRET,
}

COLUMNS = ["id", "name", "dept", "id_card", "salary"]


def make_rows(n: int = 200):
    return [
        {
            "id": i,
            "name": f"用户{i}",
            "dept": "平台部",
            "id_card": f"1101011990010{i:06d}",
            "salary": 20000 + i,
        }
        for i in range(1, n + 1)
    ]


@pytest.fixture
def clk() -> FakeClock:
    return FakeClock(start=1_000_000.0)


@pytest.fixture
def perms(clk) -> PermissionService:
    return PermissionService(clk)


@pytest.fixture
def snaps(clk) -> SnapshotService:
    return SnapshotService(clk)


@pytest.fixture
def store(tmp_path) -> FileStore:
    return FileStore(str(tmp_path / "blobs"))


@pytest.fixture
def config() -> ExportConfig:
    # 测试用短超时、短退避，配合 FakeClock 确定性推进
    return ExportConfig(
        max_attempts=3,
        retry_backoff_seconds=10.0,
        queue_timeout_seconds=300.0,
        run_timeout_seconds=60.0,
        file_retention_seconds=600.0,
        grant_grace_seconds=0.0,
    )


@pytest.fixture
def svc(perms, snaps, store, clk, config) -> ExportService:
    s = ExportService(perms, snaps, store, clock=clk, config=config)
    s.register_dataset(
        Dataset(
            id="employees",
            tenant_id="tenant-a",
            columns=list(COLUMNS),
            sensitivities=dict(SENS),
            rows=make_rows(200),
        )
    )
    # u1 基线 INTERNAL：id/name/dept 可见，id_card、salary 需要临时授权
    perms.set_baseline("tenant-a", "u1", Sensitivity.INTERNAL)
    return s


@pytest.fixture
def grants(perms):
    g_card = perms.create_grant(
        "tenant-a", "u1", Sensitivity.CONFIDENTIAL, 3600,
        field_name="id_card", reason="背调",
    )
    g_sal = perms.create_grant(
        "tenant-a", "u1", Sensitivity.SECRET, 3600,
        field_name="salary", reason="薪酬盘点",
    )
    return {"id_card": g_card, "salary": g_sal}


ALL_FIELDS = ["id", "name", "dept", "id_card", "salary"]
BASE_FIELDS = ["id", "name", "dept"]
SENSITIVE_FIELDS = ["id_card", "salary"]
