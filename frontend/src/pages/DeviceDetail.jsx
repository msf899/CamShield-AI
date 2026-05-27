import { useState, useEffect } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const RISK_CLASS = (s) => {
  if (s >= 9) return "critical";
  if (s >= 7) return "high";
  if (s >= 4) return "medium";
  if (s >= 2) return "low";
  return "safe";
};

const CAMERA_PORTS = { 554: "RTSP", 80: "HTTP", 8080: "HTTP-ALT", 8000: "Hikvision SDK", 443: "HTTPS", 37777: "Dahua" };

export default function DeviceDetail({ ip, onBack }) {
  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/devices/${ip}`)
      .then((r) => r.json())
      .then((d) => { setDevice(d); setLoading(false); })
      .catch(() => { setDevice(DEMO_DEVICE); setLoading(false); });
  }, [ip]);

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", fontFamily: "var(--font-mono)", color: "var(--cyan)" }}>
        LOADING DEVICE DATA...
      </div>
    );
  }

  if (!device) return null;

  const riskClass = RISK_CLASS(device.risk_score || 0);

  return (
    <div className="layout">
      <header className="header">
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button className="btn btn-primary" onClick={onBack}>← BACK</button>
          <div className="logo-name" style={{ fontSize: 14 }}>{device.ip}</div>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
            {device.vendor}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {device.is_camera && (
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--yellow)", border: "1px solid rgba(255,170,0,0.4)", padding: "2px 10px", borderRadius: 3 }}>
              📷 IP CAMERA
            </span>
          )}
          <div className="header-time">{new Date().toTimeString().slice(0, 8)}</div>
        </div>
      </header>

      <div style={{ overflow: "auto", padding: 24, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

        {/* Risk score card */}
        <div style={{ gridColumn: "1 / -1", background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 6, padding: 20, display: "flex", alignItems: "center", gap: 32 }}>
          <div>
            <div className={`risk-score-big ${riskClass}`}>{(device.risk_score || 0).toFixed(1)}</div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-secondary)", letterSpacing: 2, marginTop: 4 }}>RISK SCORE / 10</div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)", marginBottom: 8 }}>DEVICE INFO</div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              {[
                ["IP Address",   device.ip],
                ["MAC Address",  device.mac || "N/A"],
                ["Vendor",       device.vendor || "Unknown"],
                ["Model",        device.model || "Unknown"],
                ["Device Type",  device.device_type || "unknown"],
                ["Last Seen",    device.last_seen ? new Date(device.last_seen).toLocaleString() : "N/A"],
              ].map(([label, value]) => (
                <tr key={label}>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)", padding: "3px 0", width: 120 }}>{label}</td>
                  <td style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--cyan)", padding: "3px 0" }}>{value}</td>
                </tr>
              ))}
            </table>
          </div>
        </div>

        {/* Open ports */}
        <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 6, padding: 16 }}>
          <div className="panel-title">OPEN PORTS</div>
          {(device.open_ports || []).length === 0 ? (
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)" }}>None detected</div>
          ) : (
            (device.open_ports || []).map((port) => (
              <div key={port} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: [554, 23, 21].includes(port) ? "var(--red)" : "var(--cyan)" }}>
                  {port}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
                  {CAMERA_PORTS[port] || "Unknown"}
                </span>
                {[554, 23].includes(port) && (
                  <span className="badge badge-high">RISK</span>
                )}
              </div>
            ))
          )}
        </div>

        {/* Vulnerabilities */}
        <div style={{ background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 6, padding: 16 }}>
          <div className="panel-title">VULNERABILITIES ({(device.vulnerabilities || []).length})</div>
          <div style={{ maxHeight: 300, overflowY: "auto" }}>
            {(device.vulnerabilities || []).length === 0 ? (
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--green)" }}>✓ No vulnerabilities found</div>
            ) : (
              device.vulnerabilities.map((v) => (
                <div key={v.id} style={{ padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-primary)" }}>
                      {v.type?.replace(/_/g, " ").toUpperCase()}
                    </span>
                    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                      {v.cve_id && (
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--purple)" }}>{v.cve_id}</span>
                      )}
                      <span className={`badge badge-${v.severity || "low"}`}>{v.severity?.toUpperCase()}</span>
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>{v.description}</div>
                  <div style={{ fontSize: 11, color: "var(--green)", fontFamily: "var(--font-mono)" }}>
                    → {v.recommendation}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

const DEMO_DEVICE = {
  ip: "192.168.1.15",
  mac: "C0:56:E3:11:22:33",
  vendor: "Hikvision",
  model: "DS-2CD2143G2-I",
  device_type: "camera",
  is_camera: true,
  risk_score: 8.7,
  open_ports: [80, 554, 8000],
  last_seen: new Date().toISOString(),
  vulnerabilities: [
    { id: 1, type: "default_credentials", severity: "critical", description: "Default credentials work: admin/12345", recommendation: "Change password immediately. Use 12+ characters.", cve_id: null },
    { id: 2, type: "rtsp_auth", severity: "high", description: "RTSP stream accessible without authentication", recommendation: "Enable RTSP authentication in camera settings", cve_id: null },
    { id: 3, type: "cve", severity: "critical", description: "Command injection in Hikvision web server — unauthenticated RCE", recommendation: "Update firmware to V5.5.800 build 210628 or later", cve_id: "CVE-2021-36260" },
  ],
};
