"""固定数据快照。

导出任务在创建时绑定一个不可变快照：之后源数据如何变化，导出的内容
都以快照为准。快照同时记录每个字段的敏感级别，作为权限评估与脱敏的依据。
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import Sensitivity, new_id


@dataclass
class Snapshot:
    id: str
    dataset_id: str
    tenant_id: str
    created_at: float
    columns: List[str]
    sensitivities: Dict[str, Sensitivity]
    rows: List[Dict[str, object]] = field(default_factory=list)

    def row_count(self) -> int:
        return len(self.rows)


class SnapshotService:
    def __init__(self, clock) -> None:
        self.clock = clock
        self._lock = threading.RLock()
        self._snapshots: Dict[str, Snapshot] = {}

    def create(
        self,
        dataset_id: str,
        tenant_id: str,
        columns: List[str],
        sensitivities: Dict[str, Sensitivity],
        rows: List[Dict[str, object]],
    ) -> Snapshot:
        snap = Snapshot(
            id=new_id("snap"),
            dataset_id=dataset_id,
            tenant_id=tenant_id,
            created_at=self.clock.now(),
            columns=list(columns),
            sensitivities=dict(sensitivities),
            # 深拷贝，确保外部后续修改源数据不会影响快照
            rows=copy.deepcopy(rows),
        )
        with self._lock:
            self._snapshots[snap.id] = snap
        return snap

    def get(self, snapshot_id: str) -> Optional[Snapshot]:
        with self._lock:
            return self._snapshots.get(snapshot_id)

    def require(self, snapshot_id: str) -> Snapshot:
        snap = self.get(snapshot_id)
        if snap is None:
            raise KeyError(f"快照不存在: {snapshot_id}")
        return snap
