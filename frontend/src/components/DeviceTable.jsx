import React from "react";

function DeviceTable({ devices }) {
  // Helper to color PQC algorithms dynamically
  const getPqcBadgeClass = (algo) => {
    switch (algo) {
      case "Kyber512":
        return "badge border border-info border-opacity-50 text-info bg-info bg-opacity-10";
      case "Kyber768":
        return "badge border border-success border-opacity-50 text-success bg-success bg-opacity-10";
      case "Dilithium2":
        return "badge border border-magenta border-opacity-50 text-magenta bg-magenta bg-opacity-10";
      case "Falcon512":
        return "badge border border-danger border-opacity-50 text-danger bg-danger bg-opacity-10";
      default:
        return "badge border border-warning border-opacity-50 text-warning bg-warning bg-opacity-10";
    }
  };

  // Helper to color battery text/bars dynamically
  const getBatteryColor = (level) => {
    if (level > 60) return "#00e676"; // green
    if (level > 20) return "#ff9100"; // orange
    return "#ff1744"; // red
  };

  return (
    <div className="table-responsive">
      <table className="table">
        <thead>
          <tr>
            <th>Device ID</th>
            <th>Name</th>
            <th>Status</th>
            <th>CPU Usage</th>
            <th>Memory Used</th>
            <th>Battery</th>
            <th>Active PQC</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => (
            <tr key={device.id}>
              <td className="font-monospace fw-bold text-white">{device.device_id}</td>
              <td className="text-secondary">{device.device_name}</td>
              <td>
                <div className="d-flex align-items-center gap-2">
                  <span className={device.status === "ONLINE" ? "status-glow-online" : "status-glow-offline"} />
                  <span style={{ fontSize: "0.85rem", fontWeight: "600", color: device.status === "ONLINE" ? "#00e676" : "#94a3b8" }}>
                    {device.status}
                  </span>
                </div>
              </td>
              <td>
                <div className="d-flex align-items-center gap-2">
                  <div className="progress flex-grow-1 bg-dark bg-opacity-50" style={{ height: "6px", minWidth: "60px" }}>
                    <div 
                      className="progress-bar bg-info" 
                      style={{ width: `${device.cpu_usage}%` }} 
                    />
                  </div>
                  <span className="font-monospace text-info" style={{ fontSize: "0.85rem" }}>
                    {device.cpu_usage}%
                  </span>
                </div>
              </td>
              <td className="font-monospace text-light">{device.memory_usage} MB</td>
              <td>
                <div className="d-flex align-items-center gap-2">
                  <i 
                    className={`bi ${device.battery_level > 80 ? "bi-battery-full" : device.battery_level > 50 ? "bi-battery-half" : "bi-battery"}`}
                    style={{ color: getBatteryColor(device.battery_level) }}
                  />
                  <span className="font-monospace" style={{ color: getBatteryColor(device.battery_level) }}>
                    {device.battery_level}%
                  </span>
                </div>
              </td>
              <td>
                <span className={getPqcBadgeClass(device.selected_algorithm)}>
                  {device.selected_algorithm}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default DeviceTable;