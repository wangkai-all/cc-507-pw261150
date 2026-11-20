"""时间抽象。

所有服务只依赖 ``Clock`` 接口取当前时间，测试用 :class:`FakeClock`
即可确定性地推进时间、驱动超时与临时授权过期。
"""

from __future__ import annotations

import threading
import time
from typing import Callable, List, Protocol


class Clock(Protocol):
    def now(self) -> float:
        """返回单调递增的当前时间（秒，epoch 语义）。"""

    def sleep(self, seconds: float) -> None:
        """等待指定时长。"""


class RealClock:
    """生产时钟，委托给 :mod:`time`。"""

    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class FakeClock:
    """虚拟时钟：时间只能通过 :meth:`advance` 显式前进。

    同时维护一个等待线程队列，``sleep`` 的线程会被挂起，时钟前进
    跨过其唤醒点时自动唤醒，从而可以确定性地测试超时清理与授权过期。
    """

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = float(start)
        self._lock = threading.Condition()
        self._waiters: List[dict] = []

    def now(self) -> float:
        with self._lock:
            return self._now

    def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        with self._lock:
            deadline = self._now + seconds
            self._waiters.append({"deadline": deadline, "done": False})
            self._waiters.sort(key=lambda w: w["deadline"])
            while self._now < deadline:
                self._lock.wait()
                # 被唤醒后重新检查，防止伪唤醒。

    def advance(self, seconds: float) -> None:
        """将时钟向前推进 ``seconds`` 秒并唤醒到期的等待者。"""
        if seconds < 0:
            raise ValueError("时间不能倒流")
        with self._lock:
            self._now += seconds
            due = [w for w in self._waiters if w["deadline"] <= self._now]
            for w in due:
                w["done"] = True
            self._waiters = [w for w in self._waiters if not w["done"]]
            self._lock.notify_all()

    def run_with_timeouts(self, target: Callable[[], None], timeout: float) -> bool:
        """在守护线程中运行 ``target``，必要时推进时钟直到其结束或超时。

        仅用于测试：让依赖 ``FakeClock.sleep`` 的后台逻辑在虚拟时间下跑完。
        返回 target 是否在超时前结束。
        """
        box: dict = {"finished": False}

        def runner() -> None:
            target()
            box["finished"] = True

        t = threading.Thread(target=runner, daemon=True)
        t.start()
        waited = 0.0
        step = 0.01
        while t.is_alive() and waited < timeout:
            self.advance(step)
            waited += step
            t.join(timeout=0.005)
        return box["finished"]
