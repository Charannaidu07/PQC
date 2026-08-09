import React, { useEffect, useState, useRef } from "react";
import api from "../services/api";

function TerminalLog() {
  const [logs, setLogs] = useState([]);
  const containerRef = useRef(null);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 3000);
    return () => clearInterval(interval);
  }, []);

  async function fetchLogs() {
    try {
      const res = await api.get("/logs");
      setLogs(res.data);
    } catch (err) {
      console.error("Error fetching logs:", err);
    }
  }

  // Scroll to bottom when logs update
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="card terminal-window overflow-hidden border-0">
      <div className="terminal-header">
        <div className="terminal-dot terminal-dot-red"></div>
        <div className="terminal-dot terminal-dot-yellow"></div>
        <div className="terminal-dot terminal-dot-green"></div>
        <span className="ms-2 font-monospace text-secondary" style={{ fontSize: "0.75rem", fontWeight: "600" }}>
          quantumshield_soc_telemetry.log
        </span>
      </div>
      <div className="terminal-body font-monospace" ref={containerRef}>
        {logs.map((log, index) => {
          let typeColorClass = "terminal-log-inf";
          if (log.type === "WRN") typeColorClass = "terminal-log-wrn";
          if (log.type === "ERR") typeColorClass = "terminal-log-err";

          return (
            <div key={index} className="mb-1 d-flex align-items-start">
              <span className="terminal-log-time">[{log.time}]</span>
              <span className={`${typeColorClass} me-2 fw-bold`}>[{log.type}]</span>
              <span className="terminal-log-pqc me-2">[{log.service}]</span>
              <span className="text-light-gray">{log.text}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default TerminalLog;
