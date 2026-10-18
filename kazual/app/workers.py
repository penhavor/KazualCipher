# -*- coding: utf-8 -*-
"""Фоновые задачи GUI: QThread-воркер с прогрессом, ошибками и отменой."""

from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal


class CancelledError(Exception):
    """Задача отменена пользователем."""


class TaskWorker(QThread):
    """Выполняет fn(progress_cb, cancel_event) в отдельном потоке.

    progress_cb(stage: str, fraction: float | None) — из него же проверяется
    отмена (бросает CancelledError). cancel_event (threading.Event) dodatkowo
    передаётся потоковым конвейерам kazual.stream — они проверяют его между
    сегментами и корректно подчищают временные файлы.
    """

    finished_ok = Signal(object)
    failed = Signal(object)
    progress = Signal(str, object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn
        self.cancel_event = threading.Event()

    def run(self):  # noqa: D102 (вызывается Qt)
        def cb(stage, frac=None):
            if self.cancel_event.is_set():
                raise CancelledError('операция отменена пользователем')
            self.progress.emit(stage, frac)
        try:
            result = self._fn(cb, self.cancel_event)
        except Exception as exc:                          # noqa: BLE001
            from ..stream import OperationCancelled
            if isinstance(exc, OperationCancelled):
                exc = CancelledError(str(exc))
            self.failed.emit(exc)
        else:
            if self.cancel_event.is_set():
                self.failed.emit(
                    CancelledError('операция отменена пользователем'))
            else:
                self.finished_ok.emit(result)

    def cancel(self):
        self.cancel_event.set()
