"""
CamShield AI - Telegram Alert Service
Sends real-time security alerts via Telegram Bot
"""
import aiohttp
from typing import Optional
from app.core.config import settings


class TelegramAlerter:
    """
    Sends formatted security alerts to Telegram.
    Setup: Create bot via @BotFather, get token and chat_id.
    """

    def __init__(self):
        self.token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = settings.TELEGRAM_CHAT_ID
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.enabled = bool(self.token and self.chat_id)

    async def send_alert(self, message: str, parse_mode: str = "HTML") -> bool:
        if not self.enabled:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": message,
                        "parse_mode": parse_mode,
                    },
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def alert_new_device(self, ip: str, vendor: str, mac: str = "") -> bool:
        msg = (
            "🔔 <b>NEW IoT DEVICE DETECTED</b>\n\n"
            f"📡 IP: <code>{ip}</code>\n"
            f"🏭 Vendor: <code>{vendor}</code>\n"
            f"🔌 MAC: <code>{mac or 'N/A'}</code>\n\n"
            "⚠️ Run a full audit to check for vulnerabilities."
        )
        return await self.send_alert(msg)

    async def alert_vulnerability(
        self, ip: str, vuln_type: str, severity: str, description: str
    ) -> bool:
        icons = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}
        icon = icons.get(severity.lower(), "⚠️")
        msg = (
            f"{icon} <b>VULNERABILITY FOUND — {severity.upper()}</b>\n\n"
            f"📍 Device: <code>{ip}</code>\n"
            f"🔍 Type: <code>{vuln_type}</code>\n"
            f"📝 {description}"
        )
        return await self.send_alert(msg)

    async def alert_high_risk(self, ip: str, score: float, vendor: str) -> bool:
        msg = (
            "🚨 <b>HIGH RISK DEVICE DETECTED</b>\n\n"
            f"📍 IP: <code>{ip}</code>\n"
            f"🏭 Vendor: <code>{vendor}</code>\n"
            f"⚡ Risk Score: <b>{score}/10</b>\n\n"
            "👉 Open CamShield dashboard for full report."
        )
        return await self.send_alert(msg)

    async def alert_scan_complete(self, devices: int, vulnerable: int) -> bool:
        msg = (
            "✅ <b>NETWORK SCAN COMPLETE</b>\n\n"
            f"📊 Devices found: <b>{devices}</b>\n"
            f"⚠️ Vulnerable: <b>{vulnerable}</b>\n"
            f"✅ Secure: <b>{devices - vulnerable}</b>"
        )
        return await self.send_alert(msg)
