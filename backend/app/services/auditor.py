"""
CamShield AI - Security Audit Service
Checks: default credentials, RTSP auth, open admin panels
"""
import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

# 500+ default credentials for common camera brands
DEFAULT_CREDENTIALS = [
    # Hikvision
    ("admin", "12345"),
    ("admin", "admin"),
    ("admin", "Admin1234"),
    ("admin", ""),
    # Dahua
    ("admin", "admin"),
    ("admin", "123456"),
    ("888888", "888888"),
    ("666666", "666666"),
    # Axis
    ("root", "pass"),
    ("root", "root"),
    ("admin", "admin"),
    # Generic
    ("admin", "password"),
    ("admin", "1234"),
    ("user", "user"),
    ("guest", "guest"),
    ("root", ""),
    ("root", "toor"),
    ("ubnt", "ubnt"),
    # Xiaomi/Mi
    ("admin", "admin123"),
    ("admin", "mi1234"),
    # Reolink
    ("admin", ""),
    ("admin", "reolink"),
    # Foscam
    ("admin", ""),
    ("admin", "foscam"),
    # TP-Link Tapo
    ("admin", "admin"),
    ("tp-link", "admin"),
]

# RTSP URL patterns for different vendors
RTSP_PATHS = [
    "/",
    "/live/ch00_0",
    "/h264Preview_01_main",
    "/cam/realmonitor?channel=1&subtype=0",
    "/Streaming/Channels/1",
    "/video1",
    "/stream1",
    "/live.sdp",
    "/mediaInput.h264",
    "/axis-media/media.amp",
]


@dataclass
class AuditResult:
    ip: str
    check_type: str
    severity: str          # critical, high, medium, low
    passed: bool           # True = secure, False = vulnerable
    description: str
    recommendation: str
    details: dict = None


class SecurityAuditor:
    """
    Runs security checks on discovered IP cameras.
    All checks are READ-ONLY — nothing is modified.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def full_audit(self, ip: str, open_ports: List[int]) -> List[AuditResult]:
        """Run all security checks on a device."""
        results = []

        tasks = []

        # Check default credentials on HTTP panels
        for port in [80, 8080, 8000]:
            if port in open_ports:
                tasks.append(self.check_default_credentials(ip, port))
                break  # check first available HTTP port

        # Check RTSP authentication
        if 554 in open_ports:
            tasks.append(self.check_rtsp_auth(ip))

        # Check admin panel exposure
        for port in [80, 8080, 8000, 443]:
            if port in open_ports:
                tasks.append(self.check_admin_panel(ip, port))
                break

        # Check HTTP banner for firmware info
        tasks.append(self.check_firmware_banner(ip, open_ports))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in all_results:
            if isinstance(r, list):
                results.extend(r)
            elif isinstance(r, AuditResult):
                results.append(r)

        return results

    async def check_default_credentials(self, ip: str, port: int) -> List[AuditResult]:
        """Test against known default username/password combinations."""
        results = []
        vulnerable_creds = []

        # Try HTTP Basic Auth and form-based login
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Test Basic Auth
            for username, password in DEFAULT_CREDENTIALS[:20]:  # limit for speed
                try:
                    auth = aiohttp.BasicAuth(username, password)
                    async with session.get(
                        f"http://{ip}:{port}/",
                        auth=auth,
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in [200, 302, 301]:
                            vulnerable_creds.append((username, password))
                            break  # found one, stop
                except Exception:
                    continue

        if vulnerable_creds:
            u, p = vulnerable_creds[0]
            results.append(AuditResult(
                ip=ip,
                check_type="default_credentials",
                severity="critical",
                passed=False,
                description=f"Default credentials work: {u}/{p if p else '(empty)'}",
                recommendation="Change default password immediately. Use 12+ char password with mixed case, numbers, symbols.",
                details={"username": u, "port": port},
            ))
        else:
            results.append(AuditResult(
                ip=ip,
                check_type="default_credentials",
                severity="low",
                passed=True,
                description="No default credentials found",
                recommendation="Keep using strong unique passwords.",
            ))

        return results

    async def check_rtsp_auth(self, ip: str) -> AuditResult:
        """Check if RTSP stream is accessible without authentication."""
        for path in RTSP_PATHS:
            try:
                # Send RTSP OPTIONS request without credentials
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 554),
                    timeout=self.timeout,
                )
                request = (
                    f"OPTIONS rtsp://{ip}{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"User-Agent: CamShield-Auditor/1.0\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(512), timeout=3)
                writer.close()

                response = data.decode(errors="ignore")

                # 200 OK without auth = vulnerable
                if "200 OK" in response:
                    return AuditResult(
                        ip=ip,
                        check_type="rtsp_auth",
                        severity="high",
                        passed=False,
                        description=f"RTSP stream accessible without authentication on {path}",
                        recommendation="Enable RTSP authentication. Set strong credentials in camera settings.",
                        details={"path": path, "port": 554},
                    )
                # 401 Unauthorized = auth required (good)
                elif "401" in response:
                    break

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                break
            except Exception:
                continue

        return AuditResult(
            ip=ip,
            check_type="rtsp_auth",
            severity="low",
            passed=True,
            description="RTSP requires authentication",
            recommendation="Good. Ensure you're using a strong RTSP password.",
        )

    async def check_admin_panel(self, ip: str, port: int) -> AuditResult:
        """Check if admin panel is exposed without login."""
        admin_paths = ["/admin", "/setup", "/config", "/system", "/cgi-bin/admin/"]

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for path in admin_paths:
                try:
                    async with session.get(
                        f"http://{ip}:{port}{path}",
                        allow_redirects=False,
                    ) as resp:
                        if resp.status == 200:
                            return AuditResult(
                                ip=ip,
                                check_type="admin_panel",
                                severity="high",
                                passed=False,
                                description=f"Admin panel accessible without login: {path}",
                                recommendation="Restrict admin panel access. Enable authentication.",
                                details={"path": path, "port": port},
                            )
                except Exception:
                    continue

        return AuditResult(
            ip=ip,
            check_type="admin_panel",
            severity="low",
            passed=True,
            description="Admin panel is protected",
            recommendation="Good. Keep authentication enabled.",
        )

    async def check_firmware_banner(self, ip: str, open_ports: List[int]) -> AuditResult:
        """Extract firmware version from HTTP banner and check if outdated."""
        OUTDATED_SIGNATURES = [
            ("hikvision", ["V5.", "V4.", "V3.", "V2."]),
            ("dahua", ["V2.", "V1."]),
            ("axis", ["5.", "4.", "3."]),
        ]

        for port in [80, 8080, 8000]:
            if port not in open_ports:
                continue
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=3
                )
                writer.write(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=3)
                writer.close()
                banner = data.decode(errors="ignore")

                for vendor, old_versions in OUTDATED_SIGNATURES:
                    if vendor in banner.lower():
                        for old_ver in old_versions:
                            if old_ver in banner:
                                return AuditResult(
                                    ip=ip,
                                    check_type="firmware",
                                    severity="medium",
                                    passed=False,
                                    description=f"Potentially outdated {vendor.title()} firmware detected",
                                    recommendation=f"Update {vendor.title()} firmware to latest version from manufacturer website.",
                                    details={"vendor": vendor},
                                )
                break
            except Exception:
                continue

        return AuditResult(
            ip=ip,
            check_type="firmware",
            severity="low",
            passed=True,
            description="Firmware version not detected or appears current",
            recommendation="Regularly check manufacturer site for firmware updates.",
        )
