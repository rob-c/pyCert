"""Run workflow calls off the UI thread.

``TaskRunner.start(work, on_done, on_error, on_progress)`` runs ``work(progress,
stop_event)`` on Qt's thread pool and delivers progress lines and the result
back on the UI thread through queued signals.  Cancellation is cooperative:
the workflow functions check ``stop_event`` between network calls.

Qt widgets must only ever be destroyed on the UI thread.  When the last
reference to a widget's Python wrapper goes away on a worker thread, PySide
postpones the C++ destruction to the UI thread, and that has crashed the
application.  Two rules keep it from happening:

* A worker thread never drops the last reference to anything the UI handed
  it.  The work function, its result or error, and the callbacks stay
  referenced by the :class:`Task` until the UI thread has delivered the
  result and released them.  Tasks have no Qt objects of their own.
* :class:`MainThreadCollector` runs Python's cyclic garbage collector on the
  UI thread.  An automatic collection started by a worker thread could
  otherwise free a reference cycle holding a widget on that thread.
"""

import gc
import threading
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, Qt, QThreadPool, QTimer, Signal


class Task:
    """One piece of background work.  ``cancel()`` asks it to stop."""

    def __init__(
        self,
        runner: "TaskRunner",
        work: "Callable[[Callable[[str], None], threading.Event], Any]",
        on_done: "Callable[[Any], None] | None",
        on_error: "Callable[[BaseException], None] | None",
        on_progress: "Callable[[str], None] | None",
        name: str = "",
    ):
        self.runner: "TaskRunner | None" = runner
        self.work = work
        self.on_done = on_done
        self.on_error = on_error
        self.on_progress = on_progress
        self.name = name
        self.stop_event = threading.Event()
        self.done = False
        self.result: Any = None
        self.error: "BaseException | None" = None

    def cancel(self) -> None:
        self.stop_event.set()

    def release(self) -> None:
        """Drop everything the task refers to.  Only called on the UI thread."""
        self.runner = None
        self.work = self.on_done = self.on_error = self.on_progress = None
        self.result = self.error = None


def _execute(task: Task) -> None:  # runs on a worker thread
    relay = _RELAY
    try:
        task.result = task.work(lambda message: relay.progressed.emit(task, str(message)), task.stop_event)
    except BaseException as exc:  # noqa: BLE001 - delivered to the UI
        exc.__pycert_traceback__ = traceback.format_exc()  # type: ignore[attr-defined]
        task.error = exc
    task.done = True
    relay.delivered.emit(task)


class _Relay(QObject):
    """Carries finished tasks and progress lines from worker threads to the UI thread.

    It lives as long as the process does, so a worker can always reach it,
    even after the window that started the task has gone.
    """

    delivered = Signal(object)
    progressed = Signal(object, str)

    def __init__(self) -> None:
        super().__init__()
        self.delivered.connect(self._deliver, Qt.ConnectionType.QueuedConnection)
        self.progressed.connect(self._progress, Qt.ConnectionType.QueuedConnection)

    @staticmethod
    def _live_runner(task: Task) -> "TaskRunner | None":
        import shiboken6

        runner = task.runner
        return runner if runner is not None and shiboken6.isValid(runner) else None

    def _deliver(self, task: Task) -> None:
        runner = self._live_runner(task)
        if runner is None:
            task.release()
            return
        runner._finish(task)

    def _progress(self, task: Task, message: str) -> None:
        runner = self._live_runner(task)
        if runner is not None:
            runner._report(task, message)


_RELAY: "_Relay | None" = None


def _relay() -> _Relay:
    """The process-wide relay.  It is created on the UI thread by the first runner."""
    global _RELAY
    if _RELAY is None:
        _RELAY = _Relay()
    return _RELAY


class TaskRunner(QObject):
    """Keeps tasks alive while they run and reports when the app is busy."""

    busy_changed = Signal(bool)
    progress = Signal(str)

    def __init__(self, parent: "QObject | None" = None):
        super().__init__(parent)
        _relay()
        self.pool = QThreadPool.globalInstance()
        self._tasks: "list[Task]" = []
        self._closed = False

    def _alive(self) -> bool:
        """False once the runner or its window has gone: late results are then dropped."""
        import shiboken6

        if self._closed or not shiboken6.isValid(self):
            return False
        parent = self.parent()
        return parent is None or shiboken6.isValid(parent)

    def shutdown(self) -> None:
        """Cancel everything and stop delivering results (the window is closing)."""
        self._closed = True
        self.cancel_all()

    @property
    def busy(self) -> bool:
        # A task stays "busy" until its result has been delivered on the UI thread.
        return bool(self._tasks)

    def start(
        self,
        work: "Callable[[Callable[[str], None], threading.Event], Any]",
        on_done: "Callable[[Any], None] | None" = None,
        on_error: "Callable[[BaseException], None] | None" = None,
        on_progress: "Callable[[str], None] | None" = None,
        name: str = "",
    ) -> Task:
        task = Task(self, work, on_done, on_error, on_progress, name)
        was_busy = self.busy
        self._tasks.append(task)
        if not was_busy:
            self.busy_changed.emit(True)
        self.pool.start(lambda: _execute(task))
        return task

    def _report(self, task: Task, message: str) -> None:
        if not self._alive():
            return
        self.progress.emit(message)
        if task.on_progress is not None:
            task.on_progress(message)

    def _finish(self, task: Task) -> None:
        if task.error is not None:
            callback, value = task.on_error, task.error
        else:
            callback, value = task.on_done, task.result
        try:
            if callback is not None and self._alive():
                callback(value)
        finally:
            callback = value = None
            task.release()
            if task in self._tasks:
                self._tasks.remove(task)
            if not self._tasks and self._alive():
                self.busy_changed.emit(False)

    def cancel_all(self) -> None:
        for task in list(self._tasks):
            task.cancel()

    def wait(self, msecs: int = 5000) -> bool:
        return self.pool.waitForDone(msecs)


class MainThreadCollector(QObject):
    """Run Python's cyclic garbage collector on the UI thread only.

    Automatic collection runs on whichever thread happens to allocate when a
    threshold is reached, often a worker running a background check.  It is
    switched off while this object is active.  The same generational
    thresholds are checked from a UI-thread timer instead, so garbage is
    collected at much the same rate.
    """

    def __init__(self, parent: "QObject | None" = None, *, interval_ms: int = 1000):
        super().__init__(parent)
        self.threshold = gc.get_threshold()
        self.was_enabled = gc.isenabled()
        gc.disable()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check)
        self.timer.start(interval_ms)

    def check(self) -> int:
        """Collect the oldest generation that is over its threshold; returns objects freed."""
        if not self.threshold[0]:  # automatic collection was switched off before we started
            return 0
        counts = gc.get_count()
        for generation in (2, 1, 0):
            if counts[generation] > self.threshold[generation]:
                return gc.collect(generation)
        return 0

    def stop(self) -> None:
        self.timer.stop()
        if self.was_enabled:
            gc.enable()
