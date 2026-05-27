"""
CamShield AI - AI Risk Scoring Engine
Calculates a 0-10 risk score and generates recommendations
"""
from typing import List, Dict
from dataclasses import dataclass
from app.core.config import settings


@dataclass
class RiskReport:
    ip: str
    total_score: float           # 0.0 - 10.0
    risk_level: str              # CRITICAL / HIGH / MEDIUM / LOW / SAFE
    breakdown: Dict[str, float]  # per-category scores
    recommendations: List[str]
    summary: str


# Severity weights for score calculation
SEVERITY_SCORES = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 1.0,
}

RISK_LABELS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (2.0, "LOW"),
    (0.0, "SAFE"),
]


class AIRiskScorer:
    """
    Aggregates all audit results into a single AI risk score.
    Uses weighted scoring across vulnerability categories.
    """

    def calculate_risk(
        self,
        ip: str,
        audit_results: list,     # from SecurityAuditor
        cve_matches: list,       # from CVEScanner
        open_ports: List[int],
    ) -> RiskReport:

        breakdown = {
            "auth":     0.0,
            "firmware": 0.0,
            "network":  0.0,
            "rtsp":     0.0,
            "cve":      0.0,
        }
        recommendations = []

        # --- Auth score ---
        for r in audit_results:
            if r.check_type == "default_credentials" and not r.passed:
                breakdown["auth"] = SEVERITY_SCORES[r.severity]
                recommendations.append("🔑 Change default credentials immediately")
            if r.check_type == "admin_panel" and not r.passed:
                breakdown["auth"] = max(breakdown["auth"], SEVERITY_SCORES["high"])
                recommendations.append("🔒 Restrict admin panel access — require strong password")

        # --- Firmware score ---
        for r in audit_results:
            if r.check_type == "firmware" and not r.passed:
                breakdown["firmware"] = SEVERITY_SCORES[r.severity]
                recommendations.append("⬆️  Update camera firmware to latest version")

        # --- Network exposure score ---
        dangerous_ports = {
            554:   ("RTSP exposed to network", "medium"),
            23:    ("Telnet open — very dangerous", "critical"),
            21:    ("FTP open — file access risk", "high"),
            8000:  ("Hikvision SDK port exposed", "medium"),
            37777: ("Dahua control port exposed", "medium"),
        }
        for port, (msg, sev) in dangerous_ports.items():
            if port in open_ports and port != 554:  # 554 handled separately
                score = SEVERITY_SCORES[sev]
                breakdown["network"] = max(breakdown["network"], score)
                recommendations.append(f"🌐 Close port {port}: {msg}")

        if len(open_ports) > 5:
            breakdown["network"] = max(breakdown["network"], SEVERITY_SCORES["medium"])
            recommendations.append(f"🌐 Too many open ports ({len(open_ports)}) — disable unused services")

        # --- RTSP score ---
        for r in audit_results:
            if r.check_type == "rtsp_auth" and not r.passed:
                breakdown["rtsp"] = SEVERITY_SCORES[r.severity]
                recommendations.append("📹 Enable RTSP authentication — stream is publicly accessible")

        # --- CVE score ---
        if cve_matches:
            max_cvss = max(c.cvss_score for c in cve_matches)
            breakdown["cve"] = min(max_cvss, 10.0)
            for cve in cve_matches[:3]:  # top 3 CVEs
                recommendations.append(f"🐛 {cve.cve_id} ({cve.severity.upper()}): {cve.recommendation}")

        # --- Weighted total score ---
        weights = {
            "auth":     settings.RISK_WEIGHT_AUTH,
            "firmware": settings.RISK_WEIGHT_FIRMWARE,
            "network":  settings.RISK_WEIGHT_NETWORK,
            "rtsp":     settings.RISK_WEIGHT_RTSP,
            "cve":      settings.RISK_WEIGHT_CVE,
        }

        total = sum(breakdown[k] * weights[k] for k in breakdown)
        total = round(min(total, 10.0), 1)

        # Determine risk label
        risk_level = "SAFE"
        for threshold, label in RISK_LABELS:
            if total >= threshold:
                risk_level = label
                break

        # Generate summary
        if not recommendations:
            recommendations.append("✅ No major issues found. Keep firmware updated.")
            summary = f"Device appears secure. Risk score: {total}/10."
        else:
            summary = (
                f"Found {len(recommendations)} security issue(s). "
                f"Highest concern: {recommendations[0].split('—')[0].strip()}"
            )

        # Add general recommendations if score is high
        if total >= 7.0:
            recommendations.append("🔌 Consider placing camera on isolated VLAN")
            recommendations.append("🚫 Disable UPnP on your router")

        return RiskReport(
            ip=ip,
            total_score=total,
            risk_level=risk_level,
            breakdown=breakdown,
            recommendations=list(dict.fromkeys(recommendations)),  # deduplicate
            summary=summary,
        )

    def batch_risk_summary(self, reports: List[RiskReport]) -> Dict:
        """Summarize risk across all devices on the network."""
        if not reports:
            return {"average": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for r in reports:
            counts[r.risk_level] = counts.get(r.risk_level, 0) + 1

        avg = round(sum(r.total_score for r in reports) / len(reports), 1)

        return {
            "average_score": avg,
            "total_devices": len(reports),
            "critical_count": counts["CRITICAL"],
            "high_count": counts["HIGH"],
            "medium_count": counts["MEDIUM"],
            "low_count": counts["LOW"],
            "safe_count": counts["SAFE"],
        }
