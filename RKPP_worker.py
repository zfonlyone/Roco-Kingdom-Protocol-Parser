#!/usr/bin/env python3
"""RKPP live packet worker.

The sniffer callback only enqueues packets. This worker consumes them in order
and runs the full analyzer path for every packet.
"""
from __future__ import annotations

import queue
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rkpp_analyzer import RkppAnalyzer
    from rkpp_io import SessionLogger


RKPP_PACKET_QUEUE_MAXSIZE = 2048


class RKPP_PacketWorker:
    _STOP = object()

    def __init__(self, analyzer: RkppAnalyzer, logger: SessionLogger) -> None:
        self.analyzer = analyzer
        self.logger = logger
        self.errors = 0
        self._queue: queue.Queue[object] = queue.Queue(maxsize=RKPP_PACKET_QUEUE_MAXSIZE)
        self._thread = threading.Thread(target=self._run, name="RKPP_packet_worker", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def submit(self, packet) -> None:
        self._queue.put((packet, None))

    def close(self) -> None:
        self._queue.put(self._STOP)
        self._queue.join()
        self._thread.join(timeout=5.0)
        if self._thread.is_alive():
            self.logger.log("[worker] RKPP_packet_worker did not stop within timeout")
        if self.errors:
            self.logger.log(f"[worker] packet_worker_errors={self.errors}")

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._STOP:
                    return
                packet, frame_no = item  # type: ignore[misc]
                try:
                    self.analyzer.process_packet(packet, frame_no)
                except Exception as exc:
                    self.errors += 1
                    self.logger.log(f"[worker_error] packet processing failed: {exc}")
            finally:
                self._queue.task_done()
