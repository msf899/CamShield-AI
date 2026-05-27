import { useRef, useEffect } from "react";

const NODE_COLORS = {
  router:  { fill: "#0a2040", stroke: "#00c8ff", text: "#00c8ff",  label: "ROUTER" },
  camera:  { fill: "#1a0810", stroke: "#ff4060", text: "#ff7088",  label: "CAMERA" },
  phone:   { fill: "#0a2040", stroke: "#00ff99", text: "#00ff99",  label: "PHONE"  },
  tv:      { fill: "#0a2040", stroke: "#4488aa", text: "#4488aa",  label: "TV"     },
  laptop:  { fill: "#0a2040", stroke: "#00ff99", text: "#00ff99",  label: "PC"     },
  unknown: { fill: "#100d00", stroke: "#ffaa00", text: "#ffcc44",  label: "?"      },
};

function guessType(dev) {
  const v = (dev.vendor || "").toLowerCase();
  const t = (dev.device_type || "").toLowerCase();
  if (dev.is_camera || t === "camera") return "camera";
  if (v.includes("router") || v.includes("tp-link") || v.includes("asus") || v.includes("netgear")) return "router";
  if (v.includes("samsung") && v.includes("tv")) return "tv";
  if (v.includes("apple") || v.includes("samsung") || v.includes("xiaomi")) return "phone";
  if (v.includes("laptop") || v.includes("dell") || v.includes("lenovo") || v.includes("hp")) return "laptop";
  return "unknown";
}

export default function NetworkTopology({ devices, onSelect }) {
  const W = 500, H = 200;
  const cx = W / 2, cy = 36;

  // Router is center-top, others spread below
  const router = devices.find((d) => guessType(d) === "router") || { ip: "192.168.1.1", vendor: "Router", is_camera: false };
  const others = devices.filter((d) => d.ip !== router.ip);

  const nodePositions = others.map((dev, i) => {
    const total = others.length;
    const spread = Math.min(total * 70, W - 60);
    const startX = (W - spread) / 2 + 35;
    const x = total <= 1 ? cx : startX + (i / Math.max(total - 1, 1)) * spread;

    // Two rows if many devices
    const row = total > 5 ? (i % 2) : 0;
    const y = 100 + row * 55;
    return { ...dev, x, y };
  });

  return (
    <div style={{ position: "relative", background: "rgba(0,0,0,0.2)", borderRadius: 4, overflow: "hidden" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ display: "block" }}>

        {/* Grid dots */}
        {Array.from({ length: 12 }, (_, i) =>
          Array.from({ length: 5 }, (_, j) => (
            <circle key={`${i}-${j}`} cx={i * 46 + 10} cy={j * 46 + 8} r={1} fill="rgba(0,200,255,0.08)" />
          ))
        )}

        {/* Connection lines */}
        {nodePositions.map((dev) => (
          <line
            key={`line-${dev.ip}`}
            x1={cx} y1={cy + 14}
            x2={dev.x} y2={dev.y - 14}
            stroke={dev.is_camera ? "rgba(255,64,96,0.3)" : "rgba(0,200,255,0.2)"}
            strokeWidth={1}
            strokeDasharray={dev.is_camera ? "4,3" : "none"}
          />
        ))}

        {/* Sub-connections for cameras showing vuln ports */}
        {nodePositions.filter(d => d.is_camera && (d.open_ports || []).includes(554)).map((dev) => (
          <g key={`sub-${dev.ip}`}>
            <line
              x1={dev.x} y1={dev.y + 14}
              x2={dev.x - 20} y2={dev.y + 45}
              stroke="rgba(255,64,96,0.25)" strokeWidth={1}
            />
            <rect x={dev.x - 46} y={dev.y + 45} width={52} height={16} rx={2}
              fill="#1a0810" stroke="rgba(255,64,96,0.5)" strokeWidth={0.5} />
            <text x={dev.x - 20} y={dev.y + 57} textAnchor="middle"
              fill="#ff7088" fontSize={7} fontFamily="Share Tech Mono, monospace">RTSP:554</text>
          </g>
        ))}

        {/* Router node */}
        <g style={{ cursor: "pointer" }} onClick={() => onSelect && onSelect(router.ip)}>
          <rect x={cx - 28} y={cy - 14} width={56} height={22} rx={3}
            fill={NODE_COLORS.router.fill} stroke={NODE_COLORS.router.stroke} strokeWidth={1} />
          <text x={cx} y={cy + 3} textAnchor="middle"
            fill={NODE_COLORS.router.text} fontSize={9} fontFamily="Share Tech Mono, monospace">
            {router.ip}
          </text>
        </g>

        {/* Device nodes */}
        {nodePositions.map((dev) => {
          const type = guessType(dev);
          const colors = NODE_COLORS[type];
          return (
            <g key={dev.ip} style={{ cursor: "pointer" }} onClick={() => onSelect && onSelect(dev.ip)}>
              <rect x={dev.x - 30} y={dev.y - 14} width={60} height={28} rx={3}
                fill={colors.fill} stroke={colors.stroke} strokeWidth={dev.is_camera ? 1.5 : 0.8} />
              <text x={dev.x} y={dev.y - 1} textAnchor="middle"
                fill={colors.text} fontSize={8} fontFamily="Share Tech Mono, monospace">
                {dev.ip.split(".").slice(-1)[0]
                  ? `...${dev.ip.split(".").slice(-1)[0]}`
                  : dev.ip}
              </text>
              <text x={dev.x} y={dev.y + 10} textAnchor="middle"
                fill={colors.stroke} fontSize={7} fontFamily="Share Tech Mono, monospace" opacity={0.7}>
                {(dev.vendor || "UNKNOWN").slice(0, 10).toUpperCase()}
              </text>
            </g>
          );
        })}

        {/* Scan line animation */}
        <line x1={0} y1={0} x2={W} y2={0} stroke="rgba(0,200,255,0.4)" strokeWidth={1}>
          <animateTransform
            attributeName="transform"
            type="translate"
            from={`0 0`}
            to={`0 ${H}`}
            dur="3s"
            repeatCount="indefinite"
          />
          <animate attributeName="opacity" values="0;0.6;0.6;0" dur="3s" repeatCount="indefinite" />
        </line>
      </svg>
    </div>
  );
}
