"""
CamShield AI - Network Scanner Service
Discovers devices, identifies cameras, checks open ports
"""
import asyncio
import json
import socket
import subprocess
import platform
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Ports commonly used by IP cameras
CAMERA_PORTS = {
    554:  "RTSP",
    80:   "HTTP",
    8080: "HTTP-ALT",
    443:  "HTTPS",
    8000: "Hikvision",
    8888: "HTTP-ALT2",
    37777: "Dahua",
    34567: "DVR",
    9000:  "Axis",
}

# Known camera vendors (from MAC OUI)
CAMERA_VENDORS = [
    "hikvision", "dahua", "axis", "bosch", "hanwha",
    "reolink", "amcrest", "foscam", "uniview", "mobotix",
    "pelco", "vivotek", "xiaomi", "ezviz", "annke",
    "tp-link", "tapo"
]


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str = ""
    vendor: str = "Unknown"
    hostname: str = ""
    device_type: str = "unknown"
    open_ports: List[int] = field(default_factory=list)
    os_fingerprint: str = ""
    is_camera: bool = False
    model: str = ""
    firmware: str = ""


class NetworkScanner:
    """
    Main network discovery and device fingerprinting engine.
    Works on Linux, Windows, and macOS.
    """

    def __init__(self):
        self.os = platform.system().lower()

    async def get_local_network(self) -> str:
        """Auto-detect the local network range."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Convert to CIDR notation (assume /24)
            parts = local_ip.rsplit(".", 1)
            return f"{parts[0]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    async def scan_network(self, network: str) -> List[DiscoveredDevice]:
        """
        Scan a network range and return discovered devices.
        Uses Scapy (preferred) or falls back to nmap/ping.
        """
        if SCAPY_AVAILABLE and self.os == "linux":
            return await self._scan_with_scapy(network)
        elif NMAP_AVAILABLE:
            return await self._scan_with_nmap(network)
        else:
            return await self._scan_with_ping(network)

    async def _scan_with_scapy(self, network: str) -> List[DiscoveredDevice]:
        """ARP scan using Scapy — fastest, requires root on Linux."""
        loop = asyncio.get_event_loop()

        def _arp_scan():
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            devices = []
            for sent, received in result:
                devices.append(DiscoveredDevice(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    vendor=self._lookup_vendor(received.hwsrc),
                ))
            return devices

        devices = await loop.run_in_executor(None, _arp_scan)
        # Enrich with port scan
        tasks = [self._scan_ports(device) for device in devices]
        await asyncio.gather(*tasks)
        return devices

    async def _scan_with_nmap(self, network: str) -> List[DiscoveredDevice]:
        """Nmap-based scan — works on all platforms."""
        loop = asyncio.get_event_loop()

        def _nmap_scan():
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments="-sn -T4")
            devices = []
            for host in nm.all_hosts():
                dev = DiscoveredDevice(ip=host)
                if "mac" in nm[host].get("addresses", {}):
                    dev.mac = nm[host]["addresses"]["mac"]
                    dev.vendor = nm[host].get("vendor", {}).get(dev.mac, "Unknown")
                if "hostnames" in nm[host]:
                    names = nm[host]["hostnames"]
                    if names:
                        dev.hostname = names[0].get("name", "")
                devices.append(dev)
            return devices

        devices = await loop.run_in_executor(None, _nmap_scan)
        tasks = [self._scan_ports(device) for device in devices]
        await asyncio.gather(*tasks)
        return devices

    async def _scan_with_ping(self, network: str) -> List[DiscoveredDevice]:
        """Fallback ping sweep — no root required."""
        base = ".".join(network.split(".")[:3])
        tasks = [self._ping_host(f"{base}.{i}") for i in range(1, 255)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        devices = [r for r in results if isinstance(r, DiscoveredDevice)]
        port_tasks = [self._scan_ports(dev) for dev in devices]
        await asyncio.gather(*port_tasks)
        return devices

    async def _ping_host(self, ip: str) -> Optional[DiscoveredDevice]:
        """Ping a single host."""
        cmd = ["ping", "-n" if self.os == "windows" else "-c", "1",
               "-w" if self.os == "windows" else "-W", "1", ip]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=2)
            if proc.returncode == 0:
                return DiscoveredDevice(ip=ip)
        except (asyncio.TimeoutError, Exception):
            pass
        return None

    async def _scan_ports(self, device: DiscoveredDevice) -> None:
        """Scan camera-relevant ports on a device."""
        open_ports = []
        tasks = [self._check_port(device.ip, port) for port in CAMERA_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for port, result in zip(CAMERA_PORTS.keys(), results):
            if result is True:
                open_ports.append(port)

        device.open_ports = open_ports
        device.is_camera = self._classify_camera(device)
        if device.is_camera:
            device.device_type = "camera"
            await self._fingerprint_camera(device)

    async def _check_port(self, ip: str, port: int) -> bool:
        """Check if a port is open."""
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    def _classify_camera(self, device: DiscoveredDevice) -> bool:
        """Determine if a device is an IP camera."""
        # Check vendor name
        vendor_lower = device.vendor.lower()
        if any(v in vendor_lower for v in CAMERA_VENDORS):
            return True
        # Check port combination (554 + 80 is classic camera)
        if 554 in device.open_ports:
            return True
        if 8000 in device.open_ports or 37777 in device.open_ports:
            return True
        return False

    async def _fingerprint_camera(self, device: DiscoveredDevice) -> None:
        """Try to get camera model/firmware from HTTP banner."""
        for port in [80, 8080, 8000]:
            if port not in device.open_ports:
                continue
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(device.ip, port), timeout=3
                )
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner = data.decode(errors="ignore").lower()
                writer.close()

                # Detect from HTTP banner
                if "hikvision" in banner:
                    device.model = "Hikvision IP Camera"
                elif "dahua" in banner:
                    device.model = "Dahua IP Camera"
                elif "axis" in banner:
                    device.model = "Axis IP Camera"
                elif "xiaomi" in banner or "mi home" in banner:
                    device.model = "Xiaomi IP Camera"
                break
            except Exception:
                continue

    def _lookup_vendor(self, mac: str) -> str:
        """Simple OUI vendor lookup."""
        oui_map = {
            "c0:56:e3": "Hikvision",
            "8c:e7:48": "Hikvision",
            "d4:e0:8e": "Xiaomi",
            "28:6c:07": "Dahua",
            "00:40:8c": "Axis",
            "b0:a7:37": "Apple",
            "dc:a6:32": "Raspberry Pi",
        }
        prefix = mac[:8].lower()
        return oui_map.get(prefix, "Unknown Vendor")
