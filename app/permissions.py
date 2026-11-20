"""权限服务。

权限模型：

* 数据集的每个字段带一个敏感级别 :class:`~app.models.Sensitivity`；
* 用户在租户内拥有一个**基线许可级别**（可按字段单独提级）；
* **临时授权**（grant）有生效/过期时间，可按字段或按级别提权，可被撤销；
* 每次权限变化都会让 ``permission_version`` 自增，导出任务据此判断
  自己缓存的授权结论是否已经过期（``stale``）。

服务本身线程安全；评估结果 :class:`FieldAccess` 是不可变快照。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

from .clock import Clock, RealClock
from .models import AuthzHit, HitSource, Sensitivity, new_id


@dataclass
class Grant:
    """临时授权。

    ``field`` 为 ``None`` 时表示对租户内任意字段按级别提权；
    否则只对指定字段生效。
    """

    id: str
    tenant_id: str
    user_id: str
    field: Optional[str]
    level: Sensitivity
    granted_at: float
    expires_at: float
    revoked: bool = False
    reason: str = ""

    def active(self, now: float) -> bool:
        return not self.revoked and self.granted_at <= now < self.expires_at


@dataclass(frozen=True)
class FieldAccess:
    field: str
    sensitivity: Sensitivity
    allowed: bool
    source: HitSource
    grant_id: Optional[str]
    detail: str = ""

    def as_hit(self) -> AuthzHit:
        return AuthzHit(
            field=self.field,
            sensitivity=self.sensitivity,
            source=self.source,
            grant_id=self.grant_id,
            detail=self.detail,
        )


class PermissionService:
    def __init__(self, clock: Optional[Clock] = None) -> None:
        self.clock = clock or RealClock()
        self._lock = threading.RLock()
        # tenant -> user -> baseline level
        self._baselines: Dict[str, Dict[str, Sensitivity]] = {}
        # tenant -> user -> field -> level（字段级基线提权）
        self._field_overrides: Dict[str, Dict[str, Dict[str, Sensitivity]]] = {}
        self._grants: Dict[str, Grant] = {}
        self._version = 1

    # ---- 管理接口 -----------------------------------------------------

    def set_baseline(self, tenant_id: str, user_id: str, level: Sensitivity) -> None:
        with self._lock:
            self._baselines.setdefault(tenant_id, {})[user_id] = level
            self._bump()

    def add_field_clearance(
        self, tenant_id: str, user_id: str, field_name: str, level: Sensitivity
    ) -> None:
        with self._lock:
            self._field_overrides.setdefault(tenant_id, {}).setdefault(user_id, {})[
                field_name
            ] = level
            self._bump()

    def create_grant(
        self,
        tenant_id: str,
        user_id: str,
        level: "Sensitivity | int",
        ttl_seconds: float,
        field_name: Optional[str] = None,
        reason: str = "",
    ) -> str:
        now = self.clock.now()
        if not isinstance(level, Sensitivity):
            level = Sensitivity(level)
        grant = Grant(
            id=new_id("grant"),
            tenant_id=tenant_id,
            user_id=user_id,
            field=field_name,
            level=level,
            granted_at=now,
            expires_at=now + ttl_seconds,
            reason=reason,
        )
        with self._lock:
            self._grants[grant.id] = grant
            self._bump()
        return grant.id

    def revoke_grant(self, grant_id: str) -> bool:
        """并发安全地撤销授权，返回是否实际发生了状态变化。"""
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant is None or grant.revoked:
                return False
            grant.revoked = True
            self._bump()
            return True

    def get_grant(self, grant_id: str) -> Optional[Grant]:
        with self._lock:
            return self._grants.get(grant_id)

    def active_grants(self, tenant_id: str, user_id: str) -> List[Grant]:
        now = self.clock.now()
        with self._lock:
            return [
                g
                for g in self._grants.values()
                if g.tenant_id == tenant_id
                and g.user_id == user_id
                and g.active(now)
            ]

    @property
    def permission_version(self) -> int:
        with self._lock:
            return self._version

    def _bump(self) -> None:
        self._version += 1

    # ---- 评估接口 -----------------------------------------------------

    def evaluate_field(
        self, tenant_id: str, user_id: str, field_name: str, sensitivity: Sensitivity
    ) -> FieldAccess:
        """评估单个字段的当前访问权（每次都实时计算，不缓存结论）。"""
        now = self.clock.now()
        with self._lock:
            baseline = self._baselines.get(tenant_id, {}).get(
                user_id, Sensitivity.PUBLIC
            )
            override = (
                self._field_overrides.get(tenant_id, {})
                .get(user_id, {})
                .get(field_name)
            )
            effective_base = (
                baseline if override is None or override.value <= baseline.value
                else override
            )
            if effective_base.value >= sensitivity.value:
                return FieldAccess(
                    field_name,
                    sensitivity,
                    True,
                    HitSource.BASELINE,
                    None,
                    f"基线许可 {effective_base.label} ≥ {sensitivity.label}",
                )

            # 命中任何一个覆盖该字段且级别足够的有效临时授权
            for g in self._grants.values():
                if (
                    g.tenant_id != tenant_id
                    or g.user_id != user_id
                    or not g.active(now)
                ):
                    continue
                if g.field is not None and g.field != field_name:
                    continue
                if g.level.value >= sensitivity.value:
                    return FieldAccess(
                        field_name,
                        sensitivity,
                        True,
                        HitSource.GRANT,
                        g.id,
                        f"临时授权 {g.id}（{g.level.label}）"
                        + (f"，原因：{g.reason}" if g.reason else ""),
                    )
            return FieldAccess(
                field_name,
                sensitivity,
                False,
                HitSource.DENIED,
                None,
                f"许可 {effective_base.label} < {sensitivity.label}，且无有效临时授权",
            )

    def evaluate(
        self,
        tenant_id: str,
        user_id: str,
        fields: List[str],
        sensitivities: Dict[str, Sensitivity],
    ) -> List[FieldAccess]:
        return [
            self.evaluate_field(tenant_id, user_id, f, sensitivities[f]) for f in fields
        ]

    def depends_on_grants(
        self, tenant_id: str, user_id: str, grant_ids: List[str]
    ) -> bool:
        """给定授权集合中是否仍有任意一个处于有效状态。"""
        now = self.clock.now()
        with self._lock:
            for gid in grant_ids:
                g = self._grants.get(gid)
                if g is not None and g.tenant_id == tenant_id and g.user_id == user_id:
                    if g.active(now):
                        return True
        return False
