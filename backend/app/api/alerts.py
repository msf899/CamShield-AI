"""Alerts API"""
from fastapi import APIRouter
from sqlalchemy import select
from app.core.database import AsyncSessionLocal, Alert

router = APIRouter()

@router.get("")
async def list_alerts():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert).order_by(Alert.created_at.desc()).limit(50)
        )
        alerts = result.scalars().all()
        return [
            {
                "id": a.id,
                "type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "device_ip": a.device_ip,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ]
