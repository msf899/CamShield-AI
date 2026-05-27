export default function AlertFeed({ alerts }) {
  if (!alerts.length) {
    return (
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", padding: "12px 0" }}>
        No alerts yet.
      </div>
    );
  }

  return (
    <div style={{ maxHeight: 200, overflowY: "auto" }}>
      {alerts.map((a) => (
        <div key={a.id} className={`alert-item alert-${a.severity || "info"}`}>
          <span className="alert-time">{a.time}</span>
          <span>{a.message}</span>
        </div>
      ))}
    </div>
  );
}
