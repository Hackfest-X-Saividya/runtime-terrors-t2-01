import logging
import uuid
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.broadcaster import broadcaster

logger = logging.getLogger("zerosentinel.websocket")

router = APIRouter(tags=["streaming"])


@router.websocket("/ws/scans/{id}")
async def scan_websocket_endpoint(
    websocket: WebSocket,
    id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Real-time WebSocket streaming endpoint for scan events.
    Envelope format: {"type": "progress|finding|done|error", "data": {"scan_id": "...", ...}}
    """
    # 1. Validate UUID format
    try:
        scan_id = uuid.UUID(id)
    except (ValueError, AttributeError):
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "data": {
                "scan_id": str(id),
                "code": "INVALID_SCAN_ID",
                "message": f"'{id}' is not a valid RFC 4122 UUID.",
            },
        })
        await websocket.close(code=1008)
        return

    # 2. Check scan existence in database
    scan_stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(scan_stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "data": {
                "scan_id": str(scan_id),
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan with ID '{scan_id}' was not found.",
            },
        })
        await websocket.close(code=1008)
        return

    current_status = scan.status
    completed_at = scan.completed_at
    risk_score = scan.risk_score
    findings_count = scan.findings_count

    # Pre-compute severity breakdown if completed
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if current_status == "completed":
        sev_stmt = (
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.scan_id == scan_id)
            .group_by(Finding.severity)
        )
        sev_res = await db.execute(sev_stmt)
        for sev, count in sev_res.all():
            if sev in severity_breakdown:
                severity_breakdown[sev] = count

    # 3. Accept WebSocket connection
    await websocket.accept()
    logger.debug("Client connected to /ws/scans/%s (status: %s)", scan_id, current_status)

    # 4. Handle Terminal States (completed / failed)
    if current_status == "completed":
        duration = 0.0
        if completed_at and scan.created_at:
            duration = round((completed_at - scan.created_at).total_seconds(), 2)

        done_event = broadcaster.get_completed_event(scan_id) or {
            "type": "done",
            "data": {
                "scan_id": str(scan_id),
                "status": "completed",
                "risk_score": risk_score,
                "findings_count": findings_count,
                "severity_breakdown": severity_breakdown,
                "duration_seconds": duration,
                "completed_at": completed_at.isoformat() if completed_at else "",
            },
        }
        await websocket.send_json(done_event)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        return

    if current_status == "failed":
        err_event = broadcaster.get_completed_event(scan_id) or {
            "type": "error",
            "data": {
                "scan_id": str(scan_id),
                "code": "SCAN_FAILED",
                "message": "Scan failed during pipeline processing.",
                "stage": "rules",
            },
        }
        await websocket.send_json(err_event)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        return

    # 5. Active Scan: Subscribe to broadcaster
    await broadcaster.subscribe(scan_id, websocket)

    # Send latest progress if available
    latest_progress = broadcaster.get_latest_progress(scan_id)
    if latest_progress:
        try:
            await websocket.send_json(latest_progress)
        except Exception:
            pass
    else:
        # Send initial status
        try:
            await websocket.send_json({
                "type": "progress",
                "data": {
                    "scan_id": str(scan_id),
                    "status": current_status,
                    "stage": "ingest" if current_status == "queued" else "rules",
                    "done": 1,
                    "total": 4,
                    "message": f"Scan is currently {current_status}...",
                },
            })
        except Exception:
            pass

    # 6. Event loop awaiting client messages or disconnect
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.debug("Client disconnected from /ws/scans/%s", scan_id)
    except Exception as exc:
        logger.debug("Exception in websocket loop for /ws/scans/%s: %s", scan_id, exc)
    finally:
        await broadcaster.unsubscribe(scan_id, websocket)
