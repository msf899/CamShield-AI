import { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import "./App.css";

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [selectedIp, setSelectedIp] = useState(null);

  const navigate = (p, ip = null) => {
    setPage(p);
    setSelectedIp(ip);
  };

  return (
    <div className="app">
      {page === "dashboard" && <Dashboard onSelectDevice={(ip) => navigate("device", ip)} />}
      {page === "device" && <DeviceDetail ip={selectedIp} onBack={() => navigate("dashboard")} />}
    </div>
  );
}
