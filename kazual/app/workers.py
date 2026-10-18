# -*- coding: utf-8 -*-
"""Фоновые задачи GUI: QThread-воркер с прогрессом, ошибками и отменой."""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal


class CancelledError(Exception):
    """Задача отменена пользователем."""


class TaskWorker(QThread):
    """Выполняет fn(progress_cb) в отдельном потоке.

    progress_cb(stage: str, fraction: float | None) — из него же проверяется
    флаг отмены: отмена срабатывает на ближайшей контрольной точке
    (между сегментами CTR/ECB; Argon2id и расписание ключей неделимы).
    """

    finished_ok = Signal(object)
    failed = Signal(object)
    progress = Signal(str, object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn
        self._cancelled = False

    def run(self):  # noqa: D102 (вызывается Qt)
        def cb(stage, frac=None):
            if self._cancelled:
                raise CancelledError('операция отменена пользователем')
            self.progress.emit(stage, frac)
        try:
            result = self._fn(cb)
        except Exception as exc:                          # noqa: BLE001
            self.failed.emit(exc)
        else:
            if self._cancelled:
                self.failed.emit(CancelledError('операция отменена пользователем'))
            else:
                self.finished_ok.emit(result)

    def cancel(self):
        self._cancelled = True
