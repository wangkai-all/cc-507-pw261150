"""脱敏渲染。

脱敏发生在两个时刻，且规则完全一致，保证“生成时脱敏”和“下载前复评
脱敏”产出同构的文件：

* 生成过程中权限被收回（MASK 策略）；
* READY 文件对应的权限在下载前被收回（MASK 策略，重新渲染替换）。
"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Dict, List, Sequence, Tuple

from .models import AuthzHit, HitSource, Sensitivity
from .permissions import FieldAccess

MASK_TOKEN = "***MASKED***"


def mask_value(value: object, sensitivity: Sensitivity) -> str:
    """按敏感级别对单个值脱敏。"""
    if value is None:
        return ""
    text = str(value)
    if sensitivity == Sensitivity.PUBLIC:
        return text
    if sensitivity == Sensitivity.INTERNAL:
        # 内部级：固定占位
        return MASK_TOKEN
    if sensitivity == Sensitivity.CONFIDENTIAL:
        # 机密级：保留末两位，其余打码
        if len(text) <= 2:
            return MASK_TOKEN
        return "*" * (len(text) - 2) + text[-2:]
    # SECRET：整段打码并标注长度，不泄露任何原值
    return f"{MASK_TOKEN}(len={len(text)})"


def render_csv(
    columns: Sequence[str],
    rows: Sequence[Dict[str, object]],
    sensitivities: Dict[str, Sensitivity],
    access: Sequence[FieldAccess],
    progress_cb=None,
    checkpoint_cb=None,
) -> Tuple[bytes, List[AuthzHit], List[str], str]:
    """把快照行渲染成 CSV 字节串。

    参数
    ----
    progress_cb: 可选回调 ``progress_cb(done, total)``，用于上报导出进度。
    checkpoint_cb: 可选回调，每处理一批数据调用一次；服务端用它在渲染
        期间插入权限复评检查点，回调抛异常会中止本次生成。

    返回 ``(csv_bytes, hits, masked_fields, checksum)``。
    """
    by_field = {a.field: a for a in access}
    hits: List[AuthzHit] = []
    masked: List[str] = []

    for name in columns:
        acc = by_field[name]
        if acc.allowed:
            hits.append(acc.as_hit())
        else:
            if name not in masked:
                masked.append(name)
            hits.append(
                AuthzHit(
                    field=name,
                    sensitivity=sensitivities[name],
                    source=HitSource.MASKED,
                    grant_id=None,
                    detail="当前无访问权，按 MASK 策略脱敏",
                )
            )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(list(columns))

    total = len(rows)
    batch = max(1, min(100, total or 1))
    for index, row in enumerate(rows, start=1):
        values = []
        for name in columns:
            if by_field[name].allowed:
                values.append("" if row.get(name) is None else row.get(name))
            else:
                values.append(mask_value(row.get(name), sensitivities[name]))
        writer.writerow(values)
        if index % batch == 0 or index == total:
            if progress_cb is not None:
                progress_cb(index, total)
            if checkpoint_cb is not None:
                checkpoint_cb()

    data = buffer.getvalue().encode("utf-8")
    checksum = hashlib.sha256(data).hexdigest()
    return data, hits, masked, checksum
