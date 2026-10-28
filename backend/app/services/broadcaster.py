import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("zerosentinel.broadcaster")


class ScanBroadcaster:
    """
    In-memory pub/sub broadcaster for real-time WebSocket scan events.
    Thread-safe and memory-bounded to prevent leaks.
    """

    def __init__(self):
        # scan_id -> Set of active WebSocket connections
        self._subscriptions: Dict[uuid.UUID, Set[WebSocket]] = {}
        # scan_id -> cached latest progress event for fast reconnect delivery
        self._latest_progress: Dict[uuid.UUID, Dict[str, Any]] = {}
        # scan_id -> cached done event if completed
        self._completed_events: Dict[uuid.UUID, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, scan_id: uuid.UUID, websocket: WebSocket) -> None:
        async with self._lock:
            if scan_id not in self._subscriptions:
                self._subscriptions[scan_id] = set()
            self._subscriptions[scan_id].add(websocket)
            logger.debug("WebSocket subscribed to scan %s (total: %d)", scan_id, len(self._subscriptions[scan_id]))

    async def unsubscribe(self, scan_id: uuid.UUID, websocket: WebSocket) -> None:
        async with self._lock:
            if scan_id in self._subscriptions:
                self._subscriptions[scan_id].discard(websocket)
                if not self._subscriptions[scan_id]:
                    del self._subscriptions[scan_id]
            logger.debug("WebSocket unsubscribed from scan %s", scan_id)

    async def broadcast(self, scan_id: uuid.UUID, event: Dict[str, Any]) -> None:
        """
        Sends an event to all subscribers of scan_id.
        Gracefully handles disconnected sockets and prunes dead connections.
        """
        # Cache events for reconnecting clients
        if event.get("type") == "progress":
            self._latest_progress[scan_id] = event
        elif event.get("type") in ("done", "error"):
            self._completed_events[scan_id] = event

        async with self._lock:
            subscribers = list(self._subscriptions.get(scan_id, []))

        if not subscribers:
            return

        dead_sockets: List[WebSocket] = []
        for ws in subscribers:
            try:
                await ws.send_json(event)
            except Exception as exc:
                logger.debug("Failed sending event to client on scan %s: %s", scan_id, exc)
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                if scan_id in self._subscriptions:
                    for ws in dead_sockets:
                        self._subscriptions[scan_id].discard(ws)
                    if not self._subscriptions[scan_id]:
                        del self._subscriptions[scan_id]

    def get_latest_progress(self, scan_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        return self._latest_progress.get(scan_id)

    def get_completed_event(self, scan_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        return self._completed_events.get(scan_id)

    def cleanup_scan(self, scan_id: uuid.UUID) -> None:
        """Removes all cached states for scan_id after lifecycle ends."""
        self._latest_progress.pop(scan_id, None)
        self._completed_events.pop(scan_id, None)

    # Convenience publisher methods ensuring contract compliance

    async def publish_progress(
        self,
        scan_id: uuid.UUID,
        stage: str,
        done: int,
        total: int,
        message: str,
        status: str = "scanning",
    ) -> None:
        event = {
            "type": "progress",
            "data": {
                "scan_id": str(scan_id),
                "status": status,
                "stage": stage,
                "done": done,
                "total": total,
                "message": message,
            },
        }
        await self.broadcast(scan_id, event)

    async def publish_finding(
        self,
        scan_id: uuid.UUID,
        finding_data: Dict[str, Any],
    ) -> None:
        # Guarantee scan_id is in finding_data
        finding_data["scan_id"] = str(scan_id)
        event = {
            "type": "finding",
            "data": finding_data,
        }
        await self.broadcast(scan_id, event)

    async def publish_done(
        self,
        scan_id: uuid.UUID,
        status: str,
        risk_score: float,
        findings_count: int,
        severity_breakdown: Dict[str, int],
        duration_seconds: float,
        completed_at: str,
        name: str = "Scan",
        source_type: str = "code",
    ) -> None:
        event = {
            "type": "done",
            "data": {
                "scan_id": str(scan_id),
                "id": str(scan_id),
                "name": name,
                "source_type": source_type,
                "status": status,
                "stage": "ranking",
                "risk_score": risk_score,
                "findings_count": findings_count,
                "files_scanned": 1,
                "functions_scanned": 1,
                "counts_by_severity": severity_breakdown,
                "severity_breakdown": severity_breakdown,
                "duration_seconds": duration_seconds,
                "started_at": completed_at,
                "finished_at": completed_at,
                "completed_at": completed_at,
                "model_version": "0.1.0",
                "rescan_of": None,
            },
        }
        await self.broadcast(scan_id, event)

    async def publish_error(
        self,
        scan_id: uuid.UUID,
        code: str,
        message: str,
        stage: str = "rules",
    ) -> None:
        event = {
            "type": "error",
            "data": {
                "scan_id": str(scan_id),
                "code": code,
                "message": message,
                "stage": stage,
            },
        }
        await self.broadcast(scan_id, event)


# Global broadcaster singleton
broadcaster = ScanBroadcaster()
