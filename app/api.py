"""HTTP 页面与 JSON 接口（标准库实现，无第三方依赖）。

页面
====
* ``GET  /``                     任务总览 + 创建表单
* ``POST /tasks``                创建导出任务
* ``GET  /tasks/{id}``           详情：授权命中、进度、文件版本、下载审计
* ``GET  /tasks/{id}/download``  下载文件（每次访问写审计）
* ``GET  /tasks/{id}/refresh``   立即复评权限后回到详情页
* ``POST /grants/revoke``        撤销临时授权（用于并发撤权演示/验证）

JSON
====
* ``GET /api/tasks``             任务列表
* ``GET /api/tasks/{id}``        任务详情（含版本、命中）
* ``GET /api/tasks/{id}/audit``  审计日志
"""

from __future__ import annotations

import html
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .models import (
    HitSource,
    PermissionDenied,
    Policy,
    TaskNotReady,
    TaskState,
    VersionStatus,
)
from .permissions import PermissionService
from .service import ExportService


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


SOURCE_LABELS = {
    HitSource.BASELINE: "基线许可",
    HitSource.GRANT: "临时授权",
    HitSource.MASKED: "已脱敏",
    HitSource.DENIED: "已拒绝",
}

VERSION_LABELS = {
    VersionStatus.ACTIVE: "可下载",
    VersionStatus.SUPERSEDED: "已被取代",
    VersionStatus.REVOKED: "已撤权下线",
    VersionStatus.FAILED: "生成失败",
}


class ExportHandler(BaseHTTPRequestHandler):
    server_version = "PermissionAwareExport/1.0"

    # ---- 工具 ---------------------------------------------------------

    @property
    def export_service(self) -> ExportService:
        return self.server.export_service  # type: ignore[attr-defined]

    @property
    def permission_service(self) -> PermissionService:
        return self.server.permission_service  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:  # 安静日志
        self.server.log.append("%s - %s" % (self.address_string(), fmt % args))  # type: ignore[attr-defined]

    def _send_html(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: object, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def _page(self, title: str, content: str) -> str:
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="refresh" content="0">
<title>{esc(title)} - 权限感知导出</title>
<style>
body {{ font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
       margin: 0; background: #f5f6f8; color: #1f2430; }}
header {{ background: #1f2430; color: #fff; padding: 14px 28px; }}
header a {{ color: #9ecbff; text-decoration: none; }}
main {{ max-width: 1080px; margin: 24px auto; padding: 0 20px; }}
.card {{ background: #fff; border: 1px solid #e3e6ea; border-radius: 10px;
         padding: 18px 22px; margin-bottom: 20px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
th, td {{ border: 1px solid #e3e6ea; padding: 8px 10px; text-align: left; }}
th {{ background: #f0f2f5; }}
.progress {{ background: #e9ecef; border-radius: 6px; height: 14px; width: 220px;
             overflow: hidden; display: inline-block; vertical-align: middle; }}
.progress > i {{ display: block; height: 100%; background: #2f81f7; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px;
          font-size: 12px; }}
.b-ready {{ background: #dafbe1; color: #1a7f37; }}
.b-queued, .b-retry_wait {{ background: #fff8c5; color: #9a6700; }}
.b-running {{ background: #ddf4ff; color: #0969da; }}
.b-invalidated, .b-failed, .b-expired {{ background: #ffebe9; color: #cf222e; }}
.b-masked {{ background: #fff1e5; color: #bc4c00; }}
.b-grant {{ background: #fbefff; color: #8250df; }}
.b-baseline {{ background: #eaeef2; color: #57606a; }}
code {{ background: #f0f2f5; padding: 1px 5px; border-radius: 4px; }}
button, .btn {{ background: #1f6feb; color: #fff; border: 0; border-radius: 6px;
                padding: 8px 14px; cursor: pointer; text-decoration: none;
                display: inline-block; font-size: 14px; }}
input, select {{ padding: 7px 9px; border: 1px solid #d0d7de; border-radius: 6px; }}
label {{ display: block; margin: 8px 0 4px; font-size: 13px; color: #57606a; }}
.muted {{ color: #6e7781; font-size: 13px; }}
</style></head><body>
<header><strong>权限感知导出服务</strong> &nbsp; <a href="/">任务总览</a></header>
<main>{content}</main></body></html>"""

    # ---- 路由 ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if path == "/":
                return self._dashboard()
            if path.startswith("/api/tasks/") and path.endswith("/audit"):
                task_id = path.split("/")[3]
                return self._json_audit(task_id)
            if path.startswith("/api/tasks/"):
                return self._json_task(path.split("/")[3])
            if path == "/api/tasks":
                return self._send_json(
                    [t.to_dict() for t in self.export_service.list_tasks()]
                )
            if path.startswith("/tasks/") and path.endswith("/download"):
                return self._download(path.split("/")[2])
            if path.startswith("/tasks/") and path.endswith("/refresh"):
                return self._refresh(path.split("/")[2])
            if path.startswith("/tasks/"):
                return self._detail(path.split("/")[2])
            self._send_html(self._page("未找到", "<p>页面不存在</p>"), 404)
        except KeyError as exc:
            self._send_html(self._page("未找到", f"<p>{esc(exc)}</p>"), 404)
        except (PermissionDenied, TaskNotReady) as exc:
            self._send_html(self._page("操作被拒绝", f"<p>{esc(exc)}</p>"), 403)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        form = self._read_form()
        try:
            if path == "/tasks":
                return self._create_task(form)
            if path == "/grants/revoke":
                return self._revoke(form)
            self._send_html(self._page("未找到", "<p>接口不存在</p>"), 404)
        except (PermissionDenied, TaskNotReady, KeyError) as exc:
            self._send_html(self._page("操作失败", f"<p>{esc(exc)}</p>"), 400)

    # ---- 页面渲染 -----------------------------------------------------

    def _dashboard(self) -> None:
        svc = self.export_service
        rows = []
        for t in svc.list_tasks():
            rows.append(
                f"<tr><td><a href='/tasks/{esc(t.id)}'><code>{esc(t.id)}</code></a></td>"
                f"<td>{esc(t.user_id)}<br><span class='muted'>{esc(t.tenant_id)}</span></td>"
                f"<td>{esc(t.dataset_id)}</td>"
                f"<td><span class='badge b-{esc(t.state.value)}'>{esc(t.state.label)}</span></td>"
                f"<td>{self._progress_bar(t.progress)}</td>"
                f"<td>{len(t.versions)}</td>"
                f"<td>{'脱敏' if t.policy == Policy.MASK else '失效'}</td>"
                f"<td>{'是' if t.stale else '否'}</td></tr>"
            )
        datasets = "".join(
            f"<option value='{esc(d.id)}'>{esc(d.id)}（{esc(d.tenant_id)}）</option>"
            for d in svc._datasets.values()
        )
        content = f"""
<div class="card"><h2 style="margin-top:0">导出任务</h2>
<table><thead><tr><th>任务</th><th>用户/租户</th><th>数据集</th><th>状态</th>
<th>进度</th><th>版本数</th><th>策略</th><th>权限已变化</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=8 class=muted>暂无任务</td></tr>'}</tbody></table></div>
<div class="card"><h2 style="margin-top:0">创建导出任务</h2>
<form method="post" action="/tasks">
<label>租户 ID</label><input name="tenant_id" value="tenant-a" required>
<label>用户 ID</label><input name="user_id" value="u1" required>
<label>数据集</label><select name="dataset_id">{datasets}</select>
<label>字段（逗号分隔，留空为全部字段）</label><input name="fields" placeholder="id,name,id_card,salary">
<label>权限变化策略</label>
<select name="policy"><option value="mask">MASK（脱敏降级）</option>
<option value="invalidate">INVALIDATE（立即失效）</option></select>
<p><button type="submit">生成导出任务</button></p></form></div>
<div class="card"><h2 style="margin-top:0">撤销临时授权</h2>
<form method="post" action="/grants/revoke">
<label>Grant ID</label><input name="grant_id" required>
<p><button type="submit">撤销</button></p></form></div>
<p class="muted">JSON 接口：<code>/api/tasks</code> · <code>/api/tasks/{{id}}</code> · <code>/api/tasks/{{id}}/audit</code></p>
"""
        self._send_html(self._page("任务总览", content))

    def _detail(self, task_id: str) -> None:
        svc = self.export_service
        t = svc.require_task(task_id)
        audit = svc.audit_log(task_id)

        def hit_rows(hits, stage_name: str) -> str:
            if not hits:
                return f"<p class='muted'>{stage_name}：暂无记录</p>"
            body = "".join(
                f"<tr><td>{esc(h.field)}</td><td>{esc(h.sensitivity.label)}</td>"
                f"<td><span class='badge b-{esc(h.source.value)}'>"
                f"{esc(SOURCE_LABELS.get(h.source, h.source.value))}</span></td>"
                f"<td>{esc(h.grant_id or '—')}</td><td>{esc(h.detail)}</td></tr>"
                for h in hits
            )
            return (
                f"<h4>{stage_name}</h4><table><thead><tr><th>字段</th><th>敏感级别</th>"
                f"<th>命中来源</th><th>授权 ID</th><th>说明</th></tr></thead>"
                f"<tbody>{body}</tbody></table>"
            )

        ver_rows = "".join(
            f"<tr><td>v{esc(v.version)}</td>"
            f"<td><span class='badge b-{esc(v.state.value)}'>"
            f"{esc(VERSION_LABELS.get(v.state, v.state.value))}</span></td>"
            f"<td>{esc(v.size)} B</td><td>{esc(v.row_count)}</td>"
            f"<td><code>{esc((v.checksum or '')[:16])}</code></td>"
            f"<td>{esc(','.join(v.masked_fields) or '—')}</td>"
            f"<td>{esc(v.download_count)}</td><td class='muted'>{esc(v.reason)}</td></tr>"
            for v in t.versions
        ) or "<tr><td colspan=8 class=muted>尚无文件版本</td></tr>"

        audit_rows = "".join(
            f"<tr><td>{e.time:.2f}</td><td>{esc(e.action)}</td>"
            f"<td>{esc(e.actor)}</td><td><code>{esc(json.dumps(e.detail, ensure_ascii=False))}</code></td></tr>"
            for e in audit
        ) or "<tr><td colspan=4 class=muted>暂无审计</td></tr>"

        download_btn = (
            f"<a class='btn' href='/tasks/{esc(t.id)}/download'>下载当前文件</a>"
            if t.state == TaskState.READY
            else "<span class='muted'>当前状态不可下载</span>"
        )
        content = f"""
<div class="card"><h2 style="margin-top:0">导出任务 <code>{esc(t.id)}</code></h2>
<p><span class='badge b-{esc(t.state.value)}'>{esc(t.state.label)}</span>
&nbsp; 策略：{esc('脱敏降级' if t.policy == Policy.MASK else '立即失效')}
&nbsp; 快照：<code>{esc(t.snapshot_id)}</code>
&nbsp; 权限版本：{esc(t.permission_version)}
&nbsp; 权限已变化：{'是' if t.stale else '否'}
{('&nbsp; 失效原因：' + esc(t.invalid_reason)) if t.invalid_reason else ''}</p>
<p>{self._progress_bar(t.progress)} &nbsp; 尝试 {esc(t.attempts)}/{esc(t.max_attempts)} 次
&nbsp; 错误：{esc(t.error or '—')}</p>
<p>{download_btn} &nbsp;
<a class="btn" style="background:#6e7781" href="/tasks/{esc(t.id)}/refresh">立即复评权限</a>
&nbsp; <a class="btn" style="background:#bc4c00"
href="/api/tasks/{esc(t.id)}">查看 JSON</a></p></div>

<div class="card"><h3 style="margin-top:0">授权命中</h3>
{hit_rows(t.gate_hits, "闸门评估（出队/最近复评）")}
{hit_rows(t.render_hits, "渲染评估（生成时实际生效）")}
<p class="muted">绑定的临时授权：{esc(', '.join(t.grant_ids) or '无')}</p></div>

<div class="card"><h3 style="margin-top:0">文件版本</h3>
<table><thead><tr><th>版本</th><th>状态</th><th>大小</th><th>行数</th>
<th>校验和</th><th>脱敏字段</th><th>下载次数</th><th>原因</th></tr></thead>
<tbody>{ver_rows}</tbody></table></div>

<div class="card"><h3 style="margin-top:0">下载与处理审计</h3>
<table><thead><tr><th>时间</th><th>动作</th><th>操作者</th><th>详情</th></tr></thead>
<tbody>{audit_rows}</tbody></table></div>
"""
        self._send_html(self._page(f"任务 {t.id}", content))

    @staticmethod
    def _progress_bar(progress: int) -> str:
        return (
            f"<span class='progress'><i style='width:{int(progress)}%'></i></span>"
            f" <span class='muted'>{int(progress)}%</span>"
        )

    # ---- 动作 ---------------------------------------------------------

    def _create_task(self, form: dict) -> None:
        fields = [f.strip() for f in form.get("fields", "").split(",") if f.strip()]
        if not fields:
            ds = self.export_service._datasets.get(form["dataset_id"])
            fields = list(ds.columns) if ds else []
        policy = Policy(form.get("policy", "mask"))
        task = self.export_service.create_export(
            tenant_id=form["tenant_id"],
            user_id=form["user_id"],
            dataset_id=form["dataset_id"],
            fields=fields,
            policy=policy,
        )
        self._redirect(f"/tasks/{task.id}")

    def _revoke(self, form: dict) -> None:
        grant_id = form["grant_id"].strip()
        changed = self.permission_service.revoke_grant(grant_id)
        if not changed:
            raise PermissionDenied(f"授权 {grant_id} 不存在或已撤销")
        self._redirect("/")

    def _refresh(self, task_id: str) -> None:
        self.export_service.refresh_task(task_id)
        self._redirect(f"/tasks/{task_id}")

    def _download(self, task_id: str) -> None:
        # 下载审计由 service.download 内部记录；这里只负责传输
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        user = query.get("as", [None])[0]
        if user is None:
            # 演示环境：未显式指定身份时以任务所有者身份下载；
            # 真实部署应替换为认证中间件提供的登录用户。
            user = self.export_service.require_task(task_id).user_id
        data = self.export_service.download(task_id, user_id=user)
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header(
            "Content-Disposition", f'attachment; filename="export-{task_id}.csv"'
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- JSON ---------------------------------------------------------

    def _json_task(self, task_id: str) -> None:
        t = self.export_service.require_task(task_id)
        payload = t.to_dict()
        payload["gate_hits"] = [h.to_dict() for h in t.gate_hits]
        payload["render_hits"] = [h.to_dict() for h in t.render_hits]
        payload["audit"] = [e.to_dict() for e in self.export_service.audit_log(task_id)]
        self._send_json(payload)

    def _json_audit(self, task_id: str) -> None:
        self.export_service.require_task(task_id)
        self._send_json(
            [e.to_dict() for e in self.export_service.audit_log(task_id)]
        )


def build_server(
    export_service: ExportService,
    permission_service: PermissionService,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), ExportHandler)
    server.export_service = export_service  # type: ignore[attr-defined]
    server.permission_service = permission_service  # type: ignore[attr-defined]
    server.log = []  # type: ignore[attr-defined]
    server.thread_name = "http-export"
    return server


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True, name="http-export")
    t.start()
    return t
