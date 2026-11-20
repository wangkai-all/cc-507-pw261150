"""领域模型与枚举。"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Sensitivity(Enum):
    """字段敏感级别，数值越大越敏感。"""

    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    SECRET = 4

    @property
    def label(self) -> str:
        return {
            Sensitivity.PUBLIC: "公开",
            Sensitivity.INTERNAL: "内部",
            Sensitivity.CONFIDENTIAL: "机密",
            Sensitivity.SECRET: "绝密",
        }[self]


class Policy(str, Enum):
    """权限在排队/生成/下载之间被收回时的处置策略。"""

    MASK = "mask"        # 降级：对失去权限的字段脱敏后继续/继续提供
    INVALIDATE = "invalidate"  # 失效：任务或文件立即不可用


class TaskState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    READY = "ready"
    INVALIDATED = "invalidated"
    FAILED = "failed"
    EXPIRED = "expired"

    @property
    def label(self) -> str:
        return {
            TaskState.QUEUED: "排队中",
            TaskState.RUNNING: "生成中",
            TaskState.RETRY_WAIT: "等待重试",
            TaskState.READY: "可下载",
            TaskState.INVALIDATED: "已失效",
            TaskState.FAILED: "失败",
            TaskState.EXPIRED: "已过期清理",
        }[self]

    @property
    def terminal(self) -> bool:
        return self in (
            TaskState.INVALIDATED,
            TaskState.FAILED,
            TaskState.EXPIRED,
        )


class HitSource(str, Enum):
    """授权命中来源。"""

    BASELINE = "baseline"      # 租户/用户基线许可
    GRANT = "grant"            # 临时授权命中
    MASKED = "masked"          # 无权限，脱敏占位
    DENIED = "denied"          # 无权限（失效策略下拒绝）


class VersionStatus(str, Enum):
    ACTIVE = "active"      # 当前唯一可下载版本
    SUPERSEDED = "superseded"  # 被新版本取代（文件已删除，仅留元数据）
    REVOKED = "revoked"    # 因撤权/过期下线（文件已删除）
    FAILED = "failed"      # 生成失败的尝试，从未产生文件


@dataclass(frozen=True)
class AuthzHit:
    """单个字段在某次权限评估中的命中记录。"""

    field: str
    sensitivity: Sensitivity
    source: HitSource
    grant_id: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "sensitivity": self.sensitivity.name,
            "sensitivity_label": self.sensitivity.label,
            "source": self.source.value,
            "grant_id": self.grant_id,
            "detail": self.detail,
        }


@dataclass
class FileVersionRecord:
    """文件版本元数据。

    任意时刻一个任务至多有一个 ``ACTIVE`` 版本，且只有 ACTIVE 版本
    在磁盘上拥有对应 blob；其余状态只保留审计元数据。
    """

    version: int
    state: VersionStatus
    created_at: float
    size: int = 0
    row_count: int = 0
    checksum: str = ""
    masked_fields: List[str] = field(default_factory=list)
    reason: str = ""
    download_count: int = 0
    blob_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "state": self.state.value,
            "created_at": self.created_at,
            "size": self.size,
            "row_count": self.row_count,
            "checksum": self.checksum,
            "masked_fields": list(self.masked_fields),
            "reason": self.reason,
            "download_count": self.download_count,
            "blob_name": self.blob_name,
        }


@dataclass
class ExportTask:
    """导出任务聚合根。"""

    id: str
    tenant_id: str
    user_id: str
    dataset_id: str
    fields: List[str]
    policy: Policy
    snapshot_id: str
    created_at: float
    state: TaskState = TaskState.QUEUED
    progress: int = 0
    error: str = ""
    attempts: int = 0
    max_attempts: int = 3
    not_before: float = 0.0          # 重试退避 / 延迟出队时间点
    ready_at: Optional[float] = None
    expires_at: Optional[float] = None  # READY 文件的保留到期时间
    started_at: Optional[float] = None  # 最近一次进入 RUNNING 的时间
    updated_at: float = 0.0             # 最近一次状态变更时间（超时判定依据）
    grants_dead_since: Optional[float] = None  # 绑定授权首次全部失效的时间
    permission_version: int = 0
    last_checked_at: float = 0.0
    stale: bool = False             # 复评发现权限已变化
    invalid_reason: str = ""
    gate_hits: List[AuthzHit] = field(default_factory=list)
    render_hits: List[AuthzHit] = field(default_factory=list)
    grant_ids: List[str] = field(default_factory=list)
    versions: List[FileVersionRecord] = field(default_factory=list)
    active_blob: Optional[str] = None
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def active_version(self) -> Optional[FileVersionRecord]:
        for v in reversed(self.versions):
            if v.state == VersionStatus.ACTIVE:
                return v
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "dataset_id": self.dataset_id,
            "fields": list(self.fields),
            "policy": self.policy.value,
            "snapshot_id": self.snapshot_id,
            "state": self.state.value,
            "state_label": self.state.label,
            "progress": self.progress,
            "error": self.error,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "not_before": self.not_before,
            "ready_at": self.ready_at,
            "expires_at": self.expires_at,
            "permission_version": self.permission_version,
            "last_checked_at": self.last_checked_at,
            "stale": self.stale,
            "invalid_reason": self.invalid_reason,
            "grant_ids": list(self.grant_ids),
            "versions": [v.to_dict() for v in self.versions],
            "active_blob": self.active_blob,
        }


@dataclass
class AuditEntry:
    """审计日志条目，覆盖任务全生命周期与每一次下载。"""

    id: str
    time: float
    action: str
    actor: str
    task_id: Optional[str]
    detail: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "time": self.time,
            "action": self.action,
            "actor": self.actor,
            "task_id": self.task_id,
            "detail": self.detail,
        }


class ExportError(Exception):
    """导出业务错误基类。"""


class PermissionDenied(ExportError):
    """创建/下载时权限校验失败。"""


class TaskNotReady(ExportError):
    """任务当前不处于可下载状态。"""
