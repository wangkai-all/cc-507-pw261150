"""权限感知导出服务。

模块划分见 README：
- clock        时间抽象（真实/虚拟时钟）
- models       领域模型与枚举
- permissions  权限服务：用户/租户/字段敏感级别/临时授权
- snapshots    固定数据快照
- masking      脱敏渲染
- storage      文件版本存储（原子提交，单一可用文件不变式）
- service      导出编排：排队、闸门复评、重试、下载审计、超时清理
- api          HTTP 页面与 JSON 接口
"""

__all__ = [
    "clock",
    "models",
    "permissions",
    "snapshots",
    "masking",
    "storage",
    "service",
    "api",
]
