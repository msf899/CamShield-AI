"""
CamShield AI - Scan API Routes
POST /api/scan/start  — start full network scan
GET  /api/scan/status — scan progress
GET  /api/scan/history — past scan results
"""
import asyncio
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.services.scanner import NetworkScanner
from app.services.auditor import SecurityAuditor
from app.services.cve_scanner import CVEScanner
from app.services.risk_scorer import AIRiskScorer
from app.services.telegram import TelegramAlerter
from app.services.websocket_manager import ws_manager
from app.core.database import AsyncSessionLocal, Device, Vulnerability, Alert, ScanHistory

router = APIRouter()

scan_state = {"running": False, "progress": 0, "message": "Idle"}


class ScanRequest(BaseModel):
    network: Optional[str] = None   # e.g. "192.168.1.0/24", auto-detect if None
    deep_scan: bool = False


@router.post("/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if scan_state["running"]:
        raise HTTPException(status_code=409, detail="Scan already running")

    background_tasks.add_task(run_full_scan, request.network, request.deep_scan)
    return {"status": "started", "message": "Network scan initiated"}


@router.get("/status")
async def scan_status():
    return scan_state


@router.get("/history")
async def scan_history():
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(
            select(ScanHistory).order_by(ScanHistory.started_at.desc()).limit(10)
        )
        scans = result.scalars().all()
        return [
            {
                "id": s.id,
                "network": s.network_range,
                "devices": s.devices_found,
                "vulnerabilities": s.vulnerabilities_found,
                "duration": round(s.duration_seconds or 0, 1),
                "started_at": s.started_at.isoformat() if s.started_at else None,
            }
            for s in scans
        ]


async def run_full_scan(network: Optional[str], deep_scan: bool):
    """Background task: full scan pipeline."""
    scan_state["running"] = True
    scan_state["progress"] = 0
    start_time = datetime.utcnow()

    scanner = NetworkScanner()
    auditor = SecurityAuditor()
    cve_scanner = CVEScanner()
    risk_scorer = AIRiskScorer()
    telegram = TelegramAlerter()

    try:

        scan_state["message"] = "Discovering devices..."
        scan_state["progress"] = 5
        await ws_manager.scan_progress(5, "Discovering devices...")

        if not network:
            network = await scanner.get_local_network()

        devices = await scanner.scan_network(network)
        scan_state["progress"] = 40
        await ws_manager.scan_progress(40, f"Found {len(devices)} devices")

        vulnerabilities_total = 0
        all_reports = []

        async with AsyncSessionLocal() as db:
            for i, dev in enumerate(devices):
                progress = 40 + int((i / max(len(devices), 1)) * 40)
                scan_state["progress"] = progress
                scan_state["message"] = f"Auditing {dev.ip}..."

                await ws_manager.device_found({
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "vendor": dev.vendor,
                    "is_camera": dev.is_camera,
                    "open_ports": dev.open_ports,
                })


                from sqlalchemy import select
                import json
                result = await db.execute(select(Device).where(Device.ip == dev.ip))
                db_device = result.scalar_one_or_none()
                if not db_device:
                    db_device = Device(ip=dev.ip)
                    db.add(db_device)

                    await telegram.alert_new_device(dev.ip, dev.vendor, dev.mac)

                db_device.mac = dev.mac
                db_device.vendor = dev.vendor
                db_device.is_camera = dev.is_camera
                db_device.device_type = dev.device_type
                db_device.open_ports = json.dumps(dev.open_ports)
                db_device.last_seen = datetime.utcnow()


                if dev.is_camera or deep_scan:
                    audit_results = await auditor.full_audit(dev.ip, dev.open_ports)
                    cve_matches = await cve_scanner.scan_device(
                        dev.ip, dev.vendor, dev.model, dev.firmware
                    )


                    for r in audit_results:
                        if not r.passed:
                            vuln = Vulnerability(
                                device_ip=dev.ip,
                                vuln_type=r.check_type,
                                severity=r.severity,
                                description=r.description,
                                recommendation=r.recommendation,
                            )
                            db.add(vuln)
                            vulnerabilities_total += 1
                            await ws_manager.vulnerability_found({
                                "ip": dev.ip,
                                "type": r.check_type,
                                "severity": r.severity,
                                "description": r.description,
                            })

                    for cve in cve_matches:
                        vuln = Vulnerability(
                            device_ip=dev.ip,
                            vuln_type="cve",
                            severity=cve.severity,
                            description=cve.description,
                            cve_id=cve.cve_id,
                            recommendation=cve.recommendation,
                        )
                        db.add(vuln)
                        vulnerabilities_total += 1


                    report = risk_scorer.calculate_risk(
                        dev.ip, audit_results, cve_matches, dev.open_ports
                    )
                    db_device.risk_score = report.total_score
                    all_reports.append(report)

                    if report.total_score >= 7.0:
                        await telegram.alert_high_risk(dev.ip, report.total_score, dev.vendor)

            await db.commit()


            duration = (datetime.utcnow() - start_time).total_seconds()
            history = ScanHistory(
                network_range=network,
                devices_found=len(devices),
                vulnerabilities_found=vulnerabilities_total,
                duration_seconds=duration,
                completed_at=datetime.utcnow(),
            )
            db.add(history)
            await db.commit()


        scan_state["progress"] = 100
        scan_state["message"] = "Scan complete"
        summary = risk_scorer.batch_risk_summary(all_reports)
        await ws_manager.scan_complete(summary)
        await telegram.alert_scan_complete(len(devices), vulnerabilities_total)

    except Exception as e:
        scan_state["message"] = f"Error: {str(e)}"
        await ws_manager.alert("critical", f"Scan error: {str(e)}")
    finally:
        scan_state["running"] = False
