"""演示入口：装配一套带示例数据的权限感知导出服务并启动 Web 页面。

运行：``python run.py``，浏览器打开 http://127.0.0.1:8080/

场景设计（可直接在页面上验证）
==============================
* 用户 u1 的基线只有 INTERNAL 级；``id_card``（机密）与 ``salary``（绝密）
  靠两个**临时授权**才能导出；
* 创建任务后在总览页撤销对应 grant，再点“立即复评权限”或直接下载：
  MASK 任务得到脱敏新文件（新版本号），INVALIDATE 任务立即失效；
* 所有动作在详情页的“下载与处理审计”表格中可查。
"""

from __future__ import annotations

import sys

from app.api import build_server, serve_in_thread
from app.clock import RealClock
from app.models import Sensitivity
from app.permissions import PermissionService
from app.service import Dataset, ExportConfig, ExportService
from app.snapshots import SnapshotService
from app.storage import FileStore

DATASET_ROWS = [
    {"id": 1, "name": "张三", "dept": "平台部", "id_card": "110101199001011234", "salary": 38000},
    {"id": 2, "name": "李四", "dept": "风控部", "id_card": "310110199203054567", "salary": 27500},
    {"id": 3, "name": "王五", "dept": "数据部", "id_card": "440305199512127890", "salary": 42000},
]

SENS = {
    "id": Sensitivity.PUBLIC,
    "name": Sensitivity.INTERNAL,
    "dept": Sensitivity.INTERNAL,
    "id_card": Sensitivity.CONFIDENTIAL,
    "salary": Sensitivity.SECRET,
}


def build_demo_service(tmp_dir: str = "/tmp/permission-aware-export"):
    clock = RealClock()
    perms = PermissionService(clock)
    snaps = SnapshotService(clock)
    store = FileStore(tmp_dir)
    svc = ExportService(perms, snaps, store, clock=clock, config=ExportConfig())

    dataset = Dataset(
        id="employees",
        tenant_id="tenant-a",
        columns=list(SENS),
        sensitivities=dict(SENS),
        rows=DATASET_ROWS,
    )
    svc.register_dataset(dataset)

    # u1 基线只能看 INTERNAL 及以下
    perms.set_baseline("tenant-a", "u1", Sensitivity.INTERNAL)
    # 两个临时授权分别覆盖机密与绝密字段（1 小时有效）
    g1 = perms.create_grant(
        "tenant-a", "u1", Sensitivity.CONFIDENTIAL, 3600,
        field_name="id_card", reason="入职背调导出",
    )
    g2 = perms.create_grant(
        "tenant-a", "u1", Sensitivity.SECRET, 3600,
        field_name="salary", reason="薪酬盘点导出",
    )
    print(f"[demo] 临时授权: {g1} (id_card), {g2} (salary)")
    print("[demo] 在页面撤销 grant 后复评/下载，即可观察脱敏或失效策略")
    return svc, perms


def main() -> int:
    svc, perms = build_demo_service()
    svc.start_workers(count=2)
    server = build_server(svc, perms, host="127.0.0.1", port=8080)
    serve_in_thread(server)
    print("[demo] 页面: http://127.0.0.1:8080/  (Ctrl+C 退出)")
    try:
        threading_event_wait()
    except KeyboardInterrupt:
        print("\n[demo] 退出")
        svc.stop_workers()
        server.shutdown()
    return 0


def threading_event_wait() -> None:
    import threading

    threading.Event().wait()


if __name__ == "__main__":
    sys.exit(main())
