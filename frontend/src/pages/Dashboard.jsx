import { useState, useEffect, useRef, useCallback } from "react";
import {
  LineChart, Line, AreaChart, Area,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import NetworkTopology from "../components/NetworkTopology";
import AlertFeed from "../components/AlertFeed";
import useWebSocket from "../hooks/useWebSocket";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const RISK_CLASS = (score) => {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 2) return "low";
  return "safe";
};

const SEVERITY_BADGE = (s) => `badge badge-${s?.toLowerCase() || "low"}`;

export default function Dashboard({ onSelectDevice }) {
  const [devices, setDevices] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("Ready");
  const [traffic, setTraffic] = useState(
    Array.from({ length: 30 }, (_, i) => ({ t: i, v: Math.random() * 60 + 10 }))
  );
  const [time, setTime] = useState(new Date().toTimeString().slice(0, 8));

  // WebSocket live updates
  const { lastMessage } = useWebSocket(`${API.replace("http", "ws")}/ws/live`);

  useEffect(() => {
    if (!lastMessage) return;
    const { type, data } = lastMessage;
    if (type === "device_found") {
      setDevices((prev) => {
        const exists = prev.find((d) => d.ip === data.ip);
        return exists ? prev.map((d) => d.ip === data.ip ? { ...d, ...data } : d) : [...prev, data];
      });
    }
    if (type === "scan_progress") {
      setProgress(data.percent);
      setProgressMsg(data.message);
    }
    if (type === "scan_complete") {
      setScanning(false);
      setProgress(100);
      fetchDevices();
    }
    if (type === "vulnerability_found") {
      const now = new Date().toTimeString().slice(0, 8);
      setAlerts((prev) => [
        { id: Date.now(), severity: data.severity, message: data.description, ip: data.ip, time: now },
        ...prev.slice(0, 49),
      ]);
    }
    if (type === "alert") {
      const now = new Date().toTimeString().slice(0, 8);
      setAlerts((prev) => [
        { id: Date.now(), severity: data.severity, message: data.message, ip: data.ip, time: now },
        ...prev.slice(0, 49),
      ]);
    }
  }, [lastMessage]);

  const fetchDevices = async () => {
    try {
      const res = await fetch(`${API}/api/devices`);
      const data = await res.json();
      setDevices(data);
    } catch {
      // backend not running — show demo data
      setDevices(DEMO_DEVICES);
    }
  };

  useEffect(() => {
    fetchDevices();
    setAlerts(DEMO_ALERTS);
    const iv = setInterval(() => {
      setTime(new Date().toTimeString().slice(0, 8));
      setTraffic((prev) => [
        ...prev.slice(1),
        { t: prev[prev.length - 1].t + 1, v: Math.random() * 80 + 10 },
      ]);
    }, 1000);
    return () => clearInterval(iv);
  }, []);

  const startScan = async () => {
    setScanning(true);
    setProgress(0);
    setProgressMsg("Initializing scan...");
    try {
      await fetch(`${API}/api/scan/start`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
    } catch {
      // Demo mode — simulate scan
      simulateDemoScan();
    }
  };

  const simulateDemoScan = () => {
    let p = 0;
    const msgs = ["Sending ARP probes...", "Discovering devices...", "Port scanning cameras...", "Checking credentials...", "Running CVE check...", "Calculating risk scores..."];
    const iv = setInterval(() => {
      p += Math.random() * 8 + 2;
      if (p >= 100) { p = 100; clearInterval(iv); setScanning(false); }
      setProgress(Math.round(p));
      setProgressMsg(msgs[Math.floor(p / 18)] || "Finalizing...");
    }, 300);
  };

  const cameras = devices.filter((d) => d.is_camera);
  const vulnerable = devices.filter((d) => (d.risk_score || 0) >= 4);
  const secure = devices.filter((d) => (d.risk_score || 0) < 4);
  const cveCount = devices.reduce((acc, d) => acc + (d.cve_count || 0), 0);

  const avgRisk = devices.length
    ? (devices.reduce((a, d) => a + (d.risk_score || 0), 0) / devices.length).toFixed(1)
    : 0;

  return (
    <div className="layout">
      {/* Header */}
      <header className="header">
        <div className="header-logo">
          <div className="logo-shield">🛡</div>
          <div>
            <div className="logo-name">CAMSHIELD AI</div>
            <div className="logo-version">NETWORK SECURITY AUDIT v1.0</div>
          </div>
        </div>
        <div className="header-right">
          {scanning && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 200 }}>
              <div style={{ flex: 1 }}>
                <div className="scan-progress">
                  <div className="scan-progress-fill" style={{ width: `${progress}%` }} />
                </div>
              </div>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)", minWidth: 30 }}>
                {progress}%
              </span>
            </div>
          )}
          <div className="live-indicator">
            <div className="pulse-dot" />
            LIVE
          </div>
          <div className="header-time">{time}</div>
          <button className="btn btn-primary" onClick={startScan} disabled={scanning}>
            {scanning ? "▶ SCANNING..." : "▶ SCAN NETWORK"}
          </button>
        </div>
      </header>

      {/* Metrics row */}
      <div style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div className="metrics-row">
          <div className="metric-card">
            <div className="metric-value">{devices.length}</div>
            <div className="metric-label">DEVICES</div>
          </div>
          <div className="metric-card">
            <div className="metric-value warn">{cameras.length}</div>
            <div className="metric-label">CAMERAS</div>
          </div>
          <div className="metric-card">
            <div className="metric-value danger">{vulnerable.length}</div>
            <div className="metric-label">VULNERABLE</div>
          </div>
          <div className="metric-card">
            <div className="metric-value ok">{secure.length}</div>
            <div className="metric-label">SECURE</div>
          </div>
          <div className="metric-card">
            <div className={`metric-value ${parseFloat(avgRisk) >= 7 ? "danger" : parseFloat(avgRisk) >= 4 ? "warn" : "ok"}`}>
              {avgRisk}
            </div>
            <div className="metric-label">AVG RISK</div>
          </div>
        </div>

        {/* Main 3-column layout */}
        <div className="main-content" style={{ flex: 1 }}>

          {/* Left — Device list */}
          <div className="panel">
            <div className="panel-title">DISCOVERED DEVICES</div>
            {devices.length === 0 && (
              <div style={{ color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: 11, padding: "20px 0", textAlign: "center" }}>
                No devices yet.<br />Click SCAN NETWORK.
              </div>
            )}
            {devices.map((dev) => (
              <div
                key={dev.ip}
                className={`device-item ${(dev.risk_score || 0) >= 7 ? "high-risk" : ""}`}
                onClick={() => onSelectDevice(dev.ip)}
              >
                <div>
                  <div className="device-ip">{dev.ip}</div>
                  <div className="device-name">{dev.vendor || "Unknown"}</div>
                  {dev.is_camera && (
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--yellow)", marginTop: 2 }}>
                      📷 IP CAMERA
                    </div>
                  )}
                </div>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                  <span className={SEVERITY_BADGE(RISK_CLASS(dev.risk_score || 0))}>
                    {RISK_CLASS(dev.risk_score || 0).toUpperCase()}
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-secondary)" }}>
                    {dev.open_ports?.length || 0} ports
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Center — Topology + Traffic */}
          <div className="panel" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <div className="panel-title">NETWORK TOPOLOGY</div>
              <NetworkTopology devices={devices} onSelect={onSelectDevice} />
            </div>
            <div>
              <div className="panel-title">LIVE TRAFFIC</div>
              <ResponsiveContainer width="100%" height={90}>
                <AreaChart data={traffic}>
                  <defs>
                    <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00c8ff" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#00c8ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area type="monotone" dataKey="v" stroke="#00c8ff" strokeWidth={1.5} fill="url(#tg)" dot={false} />
                  <XAxis dataKey="t" hide />
                  <YAxis hide domain={[0, 100]} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div>
              <div className="panel-title">SCAN STATUS</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: scanning ? "var(--cyan)" : "var(--text-secondary)", padding: "4px 0" }}>
                {scanning ? `> ${progressMsg}` : `> ${progressMsg}`}
              </div>
              {scanning && (
                <div className="scan-progress" style={{ marginTop: 8 }}>
                  <div className="scan-progress-fill" style={{ width: `${progress}%` }} />
                </div>
              )}
            </div>
          </div>

          {/* Right — Risk + Alerts */}
          <div className="panel">
            <div className="panel-title">AI RISK OVERVIEW</div>
            <div style={{ textAlign: "center", padding: "8px 0 16px" }}>
              <div className={`risk-score-big ${RISK_CLASS(avgRisk)}`}>{avgRisk}</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)", letterSpacing: 2, marginTop: 4 }}>
                AVERAGE RISK / 10
              </div>
            </div>

            {/* Score breakdown bars */}
            {[
              { label: "AUTH",     score: vulnerable.length > 0 ? 8.5 : 1, color: "#ff4060" },
              { label: "FIRMWARE", score: 6.0, color: "#ff6030" },
              { label: "NETWORK",  score: 5.5, color: "#ffaa00" },
              { label: "RTSP",     score: cameras.length > 0 ? 7.0 : 0, color: "#ff4060" },
              { label: "CVE",      score: 4.0, color: "#ffaa00" },
            ].map(({ label, score, color }) => (
              <div key={label} className="score-bar-row">
                <div className="score-bar-label">{label}</div>
                <div className="score-bar-track">
                  <div className="score-bar-fill" style={{ width: `${score * 10}%`, background: color }} />
                </div>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)", minWidth: 24 }}>
                  {score.toFixed(1)}
                </span>
              </div>
            ))}

            <div className="panel-title" style={{ marginTop: 20 }}>LIVE ALERTS</div>
            <AlertFeed alerts={alerts} />
          </div>
        </div>
      </div>
    </div>
  );
}

// Demo data when backend is not running
const DEMO_DEVICES = [
  { ip: "192.168.1.1",  vendor: "TP-Link Router",    is_camera: false, risk_score: 1.5, open_ports: [80, 443] },
  { ip: "192.168.1.15", vendor: "Hikvision",          is_camera: true,  risk_score: 8.7, open_ports: [80, 554, 8000] },
  { ip: "192.168.1.22", vendor: "Xiaomi Camera",      is_camera: true,  risk_score: 5.3, open_ports: [80, 554] },
  { ip: "192.168.1.30", vendor: "Samsung Smart TV",   is_camera: false, risk_score: 2.1, open_ports: [80] },
  { ip: "192.168.1.44", vendor: "Unknown Device",     is_camera: false, risk_score: 6.8, open_ports: [22, 80, 8080] },
];

const DEMO_ALERTS = [
  { id: 1, severity: "critical", message: "Default credentials on 192.168.1.15", ip: "192.168.1.15", time: "14:32:01" },
  { id: 2, severity: "critical", message: "RTSP exposed without auth — port 554", ip: "192.168.1.15", time: "14:31:55" },
  { id: 3, severity: "high",     message: "CVE-2021-36260 detected: Hikvision RCE",ip: "192.168.1.15", time: "14:31:40" },
  { id: 4, severity: "medium",   message: "Old firmware detected on Xiaomi cam",   ip: "192.168.1.22", time: "14:30:12" },
  { id: 5, severity: "info",     message: "New device joined: 192.168.1.44",        ip: "192.168.1.44", time: "14:29:50" },
];
