# 权限感知导出服务（Permission-Aware Export）

按**用户、租户、字段敏感级别、临时授权**生成导出任务，导出内容绑定**固定数据快照**；
当权限在排队、生成、下载之间发生变化时，按 `MASK`（脱敏降级）或 `INVALIDATE`
（立即失效）策略处理；失败重试保证**任何时刻只有一个可用文件**；页面展示授权命中、
导出进度、文件版本与下载审计，并覆盖并发撤权与超时清理。

仅依赖 Python 3.11 标准库；测试使用 pytest。

## 快速开始

```bash
python -m venv .venv && . .venv/bin/activate
pip install pytest

# 启动演示 Web 服务（内置示例数据集与临时授权）
python run.py
# 打开 http://127.0.0.1:8080/

# 运行全部 50 个测试
python -m pytest tests/ -q
```

## 架构

| 模块 | 职责 |
| --- | --- |
| `app/clock.py` | 时间抽象。`FakeClock` 让超时、授权过期、退避可确定性测试 |
| `app/models.py` | 领域模型：敏感级别、策略、任务状态机、文件版本、审计条目 |
| `app/permissions.py` | 租户/用户基线许可、字段级提级、带 TTL 的临时授权、撤销、权限版本号 |
| `app/snapshots.py` | 创建时深拷贝的不可变数据快照（含字段敏感级别） |
| `app/masking.py` | 按敏感级别脱敏 + CSV 渲染，支持进度回调与权限检查点 |
| `app/storage.py` | 临时文件 + 原子 rename 的 blob 存储，强制单文件不变式 |
| `app/service.py` | 编排核心：闸门复评、重试、下载复评、审计、超时清理 |
| `app/api.py` | 标准库 HTTP 服务：HTML 页面 + JSON 接口 |

### 权限模型

- 字段带 `PUBLIC / INTERNAL / CONFIDENTIAL / SECRET` 四级敏感度；
- 用户在租户内有基线许可级别，可对单个字段提级；
- **临时授权（grant）** 有生效/过期时间，可限定字段或全量提权，可撤销；
- 任意权限变更使 `permission_version` 自增，任务据此识别 `stale`。

### 状态机与权限闸门

```
QUEUED ──出队闸门复评──▶ RUNNING ──渲染检查点复评──▶ READY ──下载闸门复评──▶ 文件
   │                        │                          │
   │ 失败                    │ 失败（退避重试）          │ 撤权/过期
   ▼                        ▼                          ▼
INVALIDATED/超时        RETRY_WAIT ──退避到期──▶ QUEUED   INVALIDATED / EXPIRED
                                                  次数耗尽 ▶ FAILED
```

权限在三个闸门实时复评（结论不缓存）：

1. **出队闸门**：`INVALIDATE` 失权即终结；`MASK` 带失权结论继续渲染；
2. **渲染检查点**：分批渲染，每批复评。`MASK` 权限变化则丢弃半成品、整体重渲染
   （受 `max_attempts` 限制防抖动死循环）；`INVALIDATE` 立即失效并清理临时文件；
3. **下载闸门**：`INVALIDATE` 撤销文件并拒绝；`MASK` 仅在脱敏集合变化时原子替换
   为新版本，已脱敏版本被并发下载直接复用（下载锁保证只渲染一次）。

### 单一可用文件不变式

- 渲染先写任务目录下 `.tmp-*` 临时文件，`fsync` 后同目录原子 `os.replace`；
- 提交新版本时，旧 ACTIVE blob 在同一把锁内删除并标记 `SUPERSEDED`；
- 撤权/过期删除 blob 并标记 `REVOKED`；失败尝试的临时文件立即清理；
- 因此一个任务任意时刻至多一个 ACTIVE 版本、磁盘至多一个 blob。

### 超时清理（`reap_timeouts`，幂等可反复调用）

- 排队超时 → `INVALIDATED`；
- 单次生成超时 → 按失败退避重试，次数耗尽 → `FAILED`；
- READY 文件超过保留期，或绑定的临时授权全部失效且超过宽限期 → `EXPIRED` 下线；
- `RETRY_WAIT` 退避到期 → 重新入队。

## HTTP 接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /` | 任务总览、创建表单、撤权表单 |
| `POST /tasks` | 创建导出任务（`tenant_id,user_id,dataset_id,fields,policy`） |
| `GET /tasks/{id}` | 详情页：授权命中、进度条、文件版本表、下载审计表 |
| `GET /tasks/{id}/refresh` | 立即复评权限后回详情页 |
| `GET /tasks/{id}/download` | 下载（每次写审计；撤权后按策略失效或脱敏替换） |
| `POST /grants/revoke` | 撤销临时授权 |
| `GET /api/tasks` / `GET /api/tasks/{id}` / `GET /api/tasks/{id}/audit` | JSON |

## 测试覆盖（50 个）

- `test_permissions.py`：基线/字段提级/临时授权/撤销幂等/TTL 过期/租户隔离/版本号；
- `test_snapshots_masking.py`：快照深拷贝不可变、四级脱敏规则、渲染回调；
- `test_lifecycle.py`：创建拒绝、授权命中记录、进度/就绪/下载审计、退避重试、
  重试后单 blob、次数耗尽无文件、快照固定；
- `test_revocation.py`：权限在排队/渲染/下载三阶段变化时两种策略的行为；
- `test_timeouts.py`：排队超时、生成超时重试与耗尽、保留期、授权过期与宽限；
- `test_concurrency.py`：真实线程下并发撤权 vs 4 worker、8 并发下载只重渲染一次、
  撤权与下载竞速、grant 抖动下并发创建；
- `test_api.py`：页面/JSON/下载/拒绝的端到端 HTTP 验证。
