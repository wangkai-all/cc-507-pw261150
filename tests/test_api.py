"""HTTP 页面与 JSON 接口端到端测试。"""

import json
import urllib.parse
import urllib.request

import pytest

from app.api import build_server
from app.models import Policy, TaskState
from tests.conftest import ALL_FIELDS, BASE_FIELDS


@pytest.fixture
def server(svc, perms, grants):
    srv = build_server(svc, perms, host="127.0.0.1", port=0)
    thread = __import__("app.api", fromlist=["serve_in_thread"]).serve_in_thread(srv)
    yield srv
    srv.shutdown()
    thread.join(timeout=5)


def _url(server, path):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


def _get(server, path):
    req = urllib.request.Request(_url(server, path))
    try:
        resp = _NO_REDIRECT.open(req)
        return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 让 urllib 抛出 HTTPError，保留 303 与 Location


_NO_REDIRECT = urllib.request.build_opener(_NoRedirect)


def _post(server, path, form: dict):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(_url(server, path), data=data, method="POST")
    try:
        resp = _NO_REDIRECT.open(req)
        return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_dashboard_lists_tasks(server, svc):
    svc.create_export("tenant-a", "u1", "employees", BASE_FIELDS, Policy.MASK)
    status, body, _ = _get(server, "/")
    assert status == 200 and "导出任务".encode() in body


def test_full_flow_pages_and_json(server, svc, perms, grants):
    # 1. 创建任务
    status, _, headers = _post(server, "/tasks", {
        "tenant_id": "tenant-a", "user_id": "u1",
        "dataset_id": "employees", "fields": ",".join(ALL_FIELDS),
        "policy": "mask",
    })
    assert status == 303
    location = headers["Location"]
    task_id = location.rstrip("/").split("/")[-1]

    # 2. 同步生成
    svc.drain_queue()

    # 3. 详情页包含授权命中、进度、版本、审计四个板块
    _, body, _ = _get(server, location)
    text = body.decode()
    for marker in ("授权命中", "文件版本", "下载与处理审计", "临时授权", "100%"):
        assert marker in text

    # 4. JSON 详情
    _, body, _ = _get(server, f"/api/tasks/{task_id}")
    payload = json.loads(body)
    assert payload["state"] == TaskState.READY.value
    assert len(payload["gate_hits"]) == len(ALL_FIELDS)
    assert payload["versions"][0]["state"] == "active"

    # 5. 下载
    status, data, headers = _get(server, f"/tasks/{task_id}/download")
    assert status == 200
    assert headers["Content-Type"].startswith("text/csv")
    assert b"salary" in data and b"20001" in data  # 授权内明文

    # 6. 撤权后再下载 → MASK 新版本
    _post(server, "/grants/revoke", {"grant_id": grants["salary"]})
    status, data, _ = _get(server, f"/tasks/{task_id}/download")
    assert b"20001" not in data and b"MASKED" in data
    _, body, _ = _get(server, f"/api/tasks/{task_id}/audit")
    actions = [e["action"] for e in json.loads(body)]
    assert "export.downloaded" in actions
    assert "export.download_rerender" in actions


def test_invalidate_policy_via_http(server, svc, perms, grants):
    status, _, headers = _post(server, "/tasks", {
        "tenant_id": "tenant-a", "user_id": "u1",
        "dataset_id": "employees", "fields": ",".join(ALL_FIELDS),
        "policy": "invalidate",
    })
    task_id = headers["Location"].rstrip("/").split("/")[-1]
    svc.drain_queue()
    perms.revoke_grant(grants["id_card"])
    code, _, _ = _get(server, f"/tasks/{task_id}/download")
    assert code == 403
    _, body, _ = _get(server, f"/api/tasks/{task_id}")
    assert json.loads(body)["state"] == "invalidated"


def test_create_denied_returns_400(server):
    # u2 无任何基线/授权，申请敏感字段必然被拒
    code, _, _ = _post(server, "/tasks", {
        "tenant_id": "tenant-a", "user_id": "u2",
        "dataset_id": "employees", "fields": "id_card", "policy": "mask",
    })
    assert code == 400


def test_refresh_endpoint(server, svc, perms, grants):
    task = svc.create_export("tenant-a", "u1", "employees", ALL_FIELDS, Policy.MASK)
    svc.drain_queue()
    perms.revoke_grant(grants["salary"])
    status, _, headers = _get(server, f"/tasks/{task.id}/refresh")
    assert status == 303
    assert svc.require_task(task.id).stale is True
