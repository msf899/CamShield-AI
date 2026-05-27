"""
CamShield AI - CVE Scanner Service
Checks devices against known CVE database for IP cameras
"""
import asyncio
import aiohttp
from typing import List, Dict, Optional
from dataclasses import dataclass

# Built-in CVE database for common camera vulnerabilities
# In production, this syncs with NVD API (https://nvd.nist.gov/developers/vulnerabilities)
CAMERA_CVE_DB = [
    {
        "cve_id": "CVE-2021-36260",
        "vendor": "hikvision",
        "severity": "critical",
        "cvss": 9.8,
        "description": "Command injection in Hikvision IP cameras via web server — unauthenticated RCE",
        "affected_firmware": ["V5.5.800", "V5.5.700", "V5.5.600"],
        "recommendation": "Update firmware to V5.5.800 build 210628 or later immediately",
    },
    {
        "cve_id": "CVE-2021-33044",
        "vendor": "dahua",
        "severity": "critical",
        "cvss": 9.8,
        "description": "Authentication bypass in Dahua cameras — attacker can bypass login",
        "affected_firmware": ["2.820", "2.800", "2.622"],
        "recommendation": "Update to latest Dahua firmware and change all passwords",
    },
    {
        "cve_id": "CVE-2021-33045",
        "vendor": "dahua",
        "severity": "critical",
        "cvss": 9.8,
        "description": "Identity authentication bypass using a temporary credential",
        "affected_firmware": ["2.820", "2.800"],
        "recommendation": "Apply Dahua security patch and enable 2FA if available",
    },
    {
        "cve_id": "CVE-2018-10088",
        "vendor": "xiongmai",
        "severity": "critical",
        "cvss": 9.8,
        "description": "Buffer overflow in XiongMai-based cameras allows RCE",
        "affected_firmware": ["all"],
        "recommendation": "Replace device — no patch available for old XiongMai chipsets",
    },
    {
        "cve_id": "CVE-2017-7921",
        "vendor": "hikvision",
        "severity": "critical",
        "cvss": 10.0,
        "description": "Authentication bypass — attacker can access camera without credentials",
        "affected_firmware": ["V5.2.0", "V5.3.0", "V5.4.0", "V5.4.1"],
        "recommendation": "Upgrade firmware immediately. Disable UPnP and P2P.",
    },
    {
        "cve_id": "CVE-2023-28812",
        "vendor": "dahua",
        "severity": "high",
        "cvss": 7.5,
        "description": "Stored XSS vulnerability in Dahua web interface",
        "affected_firmware": ["V2.850"],
        "recommendation": "Update Dahua firmware to V2.860 or later",
    },
    {
        "cve_id": "CVE-2022-30563",
        "vendor": "axis",
        "severity": "high",
        "cvss": 8.1,
        "description": "VAPIX API vulnerability in Axis cameras — session hijacking",
        "affected_firmware": ["10.x", "9.x"],
        "recommendation": "Update AXIS OS to 10.12 LTS or 11.x",
    },
    {
        "cve_id": "CVE-2020-25078",
        "vendor": "dlink",
        "severity": "high",
        "cvss": 7.5,
        "description": "D-Link DCS cameras expose credentials via /config/getuser",
        "affected_firmware": ["all"],
        "recommendation": "Disable remote access. No patch — consider replacing device.",
    },
]


@dataclass
class CVEMatch:
    cve_id: str
    vendor: str
    severity: str
    cvss_score: float
    description: str
    recommendation: str
    matched_by: str   # "vendor", "firmware", "banner"


class CVEScanner:
    """
    Matches discovered devices against known CVE database.
    Optionally syncs with live NVD API.
    """

    def __init__(self):
        self.local_db = CAMERA_CVE_DB
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def scan_device(
        self,
        ip: str,
        vendor: str = "",
        model: str = "",
        firmware: str = "",
        banner: str = "",
    ) -> List[CVEMatch]:
        """Check a device against known CVEs."""
        matches = []
        search_text = f"{vendor} {model} {firmware} {banner}".lower()

        for cve in self.local_db:
            # Match by vendor name
            if cve["vendor"] in search_text:
                # Check if firmware version matches
                matched = False
                if firmware:
                    for affected in cve["affected_firmware"]:
                        if affected.lower() in firmware.lower() or affected == "all":
                            matched = True
                            break
                else:
                    # No firmware info — report as potential match
                    matched = True

                if matched:
                    matches.append(CVEMatch(
                        cve_id=cve["cve_id"],
                        vendor=cve["vendor"],
                        severity=cve["severity"],
                        cvss_score=cve["cvss"],
                        description=cve["description"],
                        recommendation=cve["recommendation"],
                        matched_by="vendor" if not firmware else "firmware",
                    ))

        return matches

    async def fetch_live_cves(self, keyword: str) -> List[Dict]:
        """
        Fetch latest CVEs from NVD API.
        Optional — enriches local database with live data.
        """
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 10,
                }
                async with session.get(self.nvd_api_url, params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("vulnerabilities", [])
        except Exception:
            pass
        return []

    def get_severity_color(self, severity: str) -> str:
        colors = {
            "critical": "#ff4060",
            "high": "#ff8800",
            "medium": "#ffaa00",
            "low": "#00ff99",
        }
        return colors.get(severity.lower(), "#ffffff")
