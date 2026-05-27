
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from datetime import datetime
from app.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    ip = Column(String(15), unique=True, nullable=False)
    mac = Column(String(17))
    vendor = Column(String(100))
    hostname = Column(String(100))
    device_type = Column(String(50))  # camera, router, phone, unknown
    os_fingerprint = Column(String(200))
    open_ports = Column(Text)           # JSON
    firmware_version = Column(String(50))
    model = Column(String(100))
    risk_score = Column(Float, default=0.0)
    is_camera = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    first_seen = Column(DateTime, default=datetime.utcnow)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    device_ip = Column(String(15))
    vuln_type = Column(String(50))
    severity = Column(String(10))     # critical
    description = Column(Text)
    cve_id = Column(String(20))
    recommendation = Column(Text)
    found_at = Column(DateTime, default=datetime.utcnow)
    is_fixed = Column(Boolean, default=False)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    alert_type = Column(String(50))
    severity = Column(String(10))
    message = Column(Text)
    device_ip = Column(String(15))
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_telegram = Column(Boolean, default=False)


class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True)
    scan_type = Column(String(50))
    network_range = Column(String(50))
    devices_found = Column(Integer)
    vulnerabilities_found = Column(Integer)
    duration_seconds = Column(Float)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
