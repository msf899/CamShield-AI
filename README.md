# 🛡️ CamShield AI

<div align="center">

![CamShield AI Banner](docs/banner.png)

**Professional IoT Camera Security Audit Tool**

[![Python](https://img.shields.io/badge/Python-3.11+-00c8ff?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-00ff99?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61dafb?style=flat-square&logo=react)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ed?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/yourusername/camshield-ai?style=flat-square&color=ff4060)](https://github.com/yourusername/camshield-ai/stargazers)

*Scan → Detect → Audit → Protect*

</div>

---

## ✨ What is CamShield AI?

CamShield AI is an **ethical cybersecurity tool** for auditing IoT cameras and network devices. It does NOT break anything — it finds vulnerabilities so you can fix them before attackers do.

Think of it as a **doctor checkup for your network cameras**.

```
┌─────────────────────────────────────────────────────┐
│  YOUR NETWORK                                       │
│                                                     │
│  Router ──┬── 192.168.1.15 Hikvision ⚠ VULNERABLE  │
│           ├── 192.168.1.22 Xiaomi    ⚠ WEAK RTSP   │
│           ├── 192.168.1.30 Samsung TV ✓ OK          │
│           └── 192.168.1.44 Unknown   ⚠ HIGH RISK   │
└─────────────────────────────────────────────────────┘
```

## 🚀 Features

| Feature | Description |
|---|---|
| 📡 **Wi-Fi Scanner** | Discover all devices on your network with vendor info |
| 📷 **Camera Detector** | Identify IP cameras by port fingerprinting |
| 🔑 **Default Password Check** | Test against 500+ known default credentials |
| 🎥 **Weak RTSP Checker** | Find unauthenticated RTSP streams |
| 🐛 **CVE Scanner** | Match firmware against CVE database |
| 🗺️ **Network Map** | Live visual topology of your network |
| 🤖 **AI Risk Scoring** | AI-powered risk analysis & recommendations |
| 📲 **Telegram Alerts** | Real-time notifications for new threats |
| 🖥️ **SOC Dashboard** | Professional cyberpunk-style web UI |

## 🖥️ Platform Support

| Platform | Status | Notes |
|---|---|---|
| 🐧 Linux | ✅ Full | Native, best performance |
| 🪟 Windows | ✅ Full | WSL2 recommended, or native |
| 🍎 macOS | ✅ Full | Homebrew dependencies |
| 🐳 Docker | ✅ Full | Any platform |

## ⚡ Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/msf899/CamShield-AI
cd camshield-ai
docker compose up
```

Open `http://localhost:3000` — Dashboard ready! 🎉

### Option 2: Manual Install

**Linux/macOS:**
```bash
# Clone
git clone https://github.com/msf899/CamShield-AI
cd camshield-ai

# Backend
cd backend
pip install -r requirements.txt
python -m app.main

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

**Windows:**
```powershell
# Install nmap from https://nmap.org/download.html first!
# Then same steps as above, or use Docker
```

## 📸 Screenshots

<!-- Add your GIFs here for GitHub stars! -->
> 🎯 Add a demo GIF at `docs/demo.gif` — this gets 10x more GitHub stars!

## 🛠️ Tech Stack

```
Backend:  Python 3.11 · FastAPI · Scapy · Nmap · SQLite/PostgreSQL
Frontend: React 18 · Tailwind CSS · Framer Motion · Recharts
Infra:    Docker · WebSocket · Telegram Bot API
```

## ⚖️ Ethical Use

This tool is for **authorized security auditing only**.

- ✅ Scan your own network
- ✅ Authorized penetration testing
- ❌ Never scan networks without permission

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
  <b>If this helped you, please ⭐ star the repo!</b>
</div>
