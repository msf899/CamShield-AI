"""
CamShield AI - Configuration
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "CamShield AI"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./camshield.db"

    # Telegram
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # Scan defaults
    SCAN_TIMEOUT: int = 10
    RTSP_TIMEOUT: int = 5
    MAX_CONCURRENT_SCANS: int = 50

    # AI Risk Scoring
    RISK_WEIGHT_AUTH: float = 0.35
    RISK_WEIGHT_FIRMWARE: float = 0.20
    RISK_WEIGHT_NETWORK: float = 0.15
    RISK_WEIGHT_RTSP: float = 0.20
    RISK_WEIGHT_CVE: float = 0.10

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
