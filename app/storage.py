"""导出文件存储。

核心不变式
==========
一个导出任务在任意时刻**至多有一个可下载文件**：

* 写入先落到任务目录下的临时文件，``fsync`` 后原子 ``rename`` 为 blob；
* 提交新版本时，旧 ACTIVE blob 在同一把任务锁内被删除并标记 SUPERSEDED；
* 撤权/过期下线时删除 blob 并标记 REVOKED；
* 失败的尝试只产生临时文件，且临时文件会被立即清理，永远不可下载。
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
from typing import Dict, Optional


class FileStore:
    def __init__(self, root: str) -> None:
        self.root = root
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.RLock()
        # task_id -> 当前 blob 文件名（与内存中 ACTIVE 版本保持一致）
        self._active: Dict[str, str] = {}

    # ---- 路径 ---------------------------------------------------------

    def _task_dir(self, task_id: str) -> str:
        # task_id 自带前缀且由服务端生成，禁止路径分隔符
        safe = task_id.replace(os.sep, "_")
        d = os.path.join(self.root, safe)
        os.makedirs(d, exist_ok=True)
        return d

    def _blob_path(self, task_id: str, blob_name: str) -> str:
        return os.path.join(self._task_dir(task_id), blob_name)

    # ---- 写入 ---------------------------------------------------------

    def write_temp(self, task_id: str, data: bytes) -> str:
        """写入临时文件，返回临时路径。调用方随后必须 commit 或 discard。"""
        d = self._task_dir(task_id)
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=d)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            self.discard_temp(tmp_path)
            raise
        return tmp_path

    @staticmethod
    def discard_temp(tmp_path: str) -> None:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

    def commit(self, task_id: str, tmp_path: str, version: int) -> str:
        """把临时文件原子提升为指定版本的 ACTIVE blob。

        同一任务的旧 ACTIVE blob 被删除后，新 blob 才可见，因此下载者
        永远只能看到一个完整文件，不会读到半成品或两个并存文件。
        """
        with self._lock:
            blob_name = f"export-v{version}.csv"
            final_path = self._blob_path(task_id, blob_name)
            old = self._active.get(task_id)
            if old is not None and old != blob_name:
                try:
                    os.unlink(self._blob_path(task_id, old))
                except FileNotFoundError:
                    pass
            os.replace(tmp_path, final_path)  # 同目录原子 rename
            self._active[task_id] = blob_name
            return blob_name

    def revoke(self, task_id: str) -> None:
        """下线任务的当前文件（撤权/过期）。删除后下载必然失败。"""
        with self._lock:
            blob_name = self._active.pop(task_id, None)
            if blob_name is None:
                return
            try:
                os.unlink(self._blob_path(task_id, blob_name))
            except FileNotFoundError:
                pass

    # ---- 读取 ---------------------------------------------------------

    def open_active(self, task_id: str) -> Optional[bytes]:
        """读取当前可用文件；不存在（未就绪/已下线）时返回 None。"""
        with self._lock:
            blob_name = self._active.get(task_id)
            if blob_name is None:
                return None
            path = self._blob_path(task_id, blob_name)
            if not os.path.exists(path):
                # 磁盘与内存不一致时以磁盘为准，避免交出悬空引用
                self._active.pop(task_id, None)
                return None
            with open(path, "rb") as f:
                return f.read()

    def active_blob_name(self, task_id: str) -> Optional[str]:
        with self._lock:
            return self._active.get(task_id)

    def active_path(self, task_id: str) -> Optional[str]:
        with self._lock:
            blob_name = self._active.get(task_id)
            if blob_name is None:
                return None
            return self._blob_path(task_id, blob_name)

    def cleanup_task(self, task_id: str) -> None:
        """彻底清理任务目录（超时清理任务时使用）。"""
        with self._lock:
            self._active.pop(task_id, None)
        d = os.path.join(self.root, task_id)
        if not os.path.isdir(d):
            return
        for name in os.listdir(d):
            try:
                os.unlink(os.path.join(d, name))
            except FileNotFoundError:
                pass
        try:
            os.rmdir(d)
        except OSError:
            pass

    @staticmethod
    def checksum(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
