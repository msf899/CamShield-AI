"""
CamShield AI - Devices API Routes
GET /api/devices         — all discovered devices
GET /api/devices/{ip}    — single device details + vulnerabilities
DELETE /api/devices/{ip} — remove device from DB
"""
import json
from fastapi import APIRouter, HTTPException
from sqlalchemy import select
from app.core.database import AsyncSessionLocal, Device, Vulnerability

router = APIRouter()


@router.get("")
async def list_devices():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Device).order_by(Device.risk_score.desc()))
        devices = result.scalars().all()
        return [_device_to_dict(d) for d in devices]


@router.get("/{ip}")
async def get_device(ip: str):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Device).where(Device.ip == ip))
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        vuln_result = await db.execute(
            select(Vulnerability).where(Vulnerability.device_ip == ip)
            .order_by(Vulnerability.found_at.desc())
        )
        vulns = vuln_result.scalars().all()

        return {
            **_device_to_dict(device),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "description": v.description,
                    "cve_id": v.cve_id,
                    "recommendation": v.recommendation,
                    "found_at": v.found_at.isoformat() if v.found_at else None,
                }
                for v in vulns
            ],
        }


@router.delete("/{ip}")
async def delete_device(ip: str):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Device).where(Device.ip == ip))
        device = result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        await db.delete(device)
        await db.commit()
    return {"status": "deleted"}


def _device_to_dict(d: Device) -> dict:
    ports = []
    try:
        ports = json.loads(d.open_ports or "[]")
    except Exception:
        pass
    return {
        "ip": d.ip,
        "mac": d.mac or "",
        "vendor": d.vendor or "Unknown",
        "hostname": d.hostname or "",
        "device_type": d.device_type or "unknown",
        "is_camera": d.is_camera or False,
        "model": d.model or "",
        "open_ports": ports,
        "risk_score": d.risk_score or 0.0,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
    }
