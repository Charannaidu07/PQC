import { useEffect, useState } from "react";
import api from "../services/api";
import DeviceTable from "../components/DeviceTable";
import ThreatChart from "../components/ThreatChart";
import BenchmarkChart from "../components/BenchmarkChart";
import ThreatTimeline from "../components/ThreatTimeline";
import TopAttackedDevices from "../components/TopAttackedDevices";
import PQCDistribution from "../components/PQCDistribution";
import TerminalLog from "../components/TerminalLog";
import SimulatorControl from "../components/SimulatorControl";

function Dashboard() {
  const [stats, setStats] = useState({});
  const [devices, setDevices] = useState([]);
  const [threats, setThreats] = useState([]);
  const [benchmarks, setBenchmarks] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [topDevices, setTopDevices] = useState([]);
  const [pqcData, setPqcData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadData() {
    try {
      const statsRes = await api.get("/stats");
      const devicesRes = await api.get("/devices");
      const threatsRes = await api.get("/threats");
      const benchmarksRes = await api.get("/benchmarks");
      const timelineRes = await api.get("/threat-timeline");
      const topRes = await api.get("/top-attacked-devices");
      const pqcRes = await api.get("/pqc-distribution");

      setStats(statsRes.data);
      setDevices(devicesRes.data);
      setThreats(threatsRes.data);
      setBenchmarks(benchmarksRes.data);
      setTimeline(timelineRes.data);
      setTopDevices(topRes.data);
      setPqcData(pqcRes.data);
      setLoading(false);
    } catch (error) {
      console.error(error);
    }
  }

  return (
    <div className="container-fluid py-2 fade-in">
      {/* HEADER SECTION */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 className="mb-1 text-gradient-cyan" style={{ fontSize: "2rem", fontWeight: "800" }}>
            Security Operations Center (SOC)
          </h2>
          <p className="text-secondary mb-0">
            Real-time Post-Quantum Cryptographic telemetry and anomaly mitigation.
          </p>
        </div>
        <div className="d-flex gap-2">
          <button 
            className="btn btn-dark border border-secondary border-opacity-25 text-white d-flex align-items-center gap-2"
            onClick={loadData}
          >
            <i className="bi bi-arrow-clockwise"></i> Refresh Data
          </button>
        </div>
      </div>

      {/* CORE PERFORMANCE STATS */}
      <div className="row g-3 mb-4">
        {/* Fleet Size Card */}
        <div className="col-md-3">
          <div className="card h-100 shadow" style={{ borderLeft: "4px solid #00e5ff" }}>
            <div className="card-body d-flex flex-column justify-content-between">
              <div className="d-flex justify-content-between align-items-start mb-3">
                <div>
                  <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                    Total IoT Fleet
                  </span>
                  <h3 className="stats-number mt-2 mb-0">{stats.total_devices || 0}</h3>
                </div>
                <div className="badge bg-cyan bg-opacity-10 text-cyan p-2">
                  <i className="bi bi-cpu" style={{ fontSize: "1.2rem" }}></i>
                </div>
              </div>
              <div className="d-flex align-items-center text-secondary" style={{ fontSize: "0.85rem" }}>
                <span className="status-glow-online me-2"></span>
                <span className="text-success fw-bold me-1">{stats.active_devices || 0}</span> Online
                <span className="status-glow-offline ms-3 me-2"></span>
                <span className="text-light fw-bold me-1">{(stats.total_devices - stats.active_devices) || 0}</span> Offline
              </div>
            </div>
          </div>
        </div>

        {/* Battery Health Card */}
        <div className="col-md-3">
          <div className="card h-100 shadow" style={{ borderLeft: "4px solid #00e676" }}>
            <div className="card-body d-flex flex-column justify-content-between">
              <div className="d-flex justify-content-between align-items-start mb-3">
                <div>
                  <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                    Fleet Battery Avg
                  </span>
                  <h3 className="stats-number mt-2 mb-0">{stats.avg_battery || 0}%</h3>
                </div>
                <div className="badge bg-success bg-opacity-10 text-success p-2">
                  <i className="bi bi-battery-half" style={{ fontSize: "1.2rem" }}></i>
                </div>
              </div>
              <div className="w-100 bg-secondary bg-opacity-25 rounded" style={{ height: "6px" }}>
                <div 
                  className="bg-success rounded" 
                  style={{ height: "6px", width: `${stats.avg_battery || 0}%`, transition: "width 0.5s ease-in-out" }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Attack Block Rate */}
        <div className="col-md-3">
          <div className="card h-100 shadow" style={{ borderLeft: "4px solid #ff1744" }}>
            <div className="card-body d-flex flex-column justify-content-between">
              <div className="d-flex justify-content-between align-items-start mb-3">
                <div>
                  <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                    Mitigation Rate
                  </span>
                  <h3 className="stats-number mt-2 mb-0">{stats.block_rate || 0}%</h3>
                </div>
                <div className="badge bg-danger bg-opacity-10 text-danger p-2">
                  <i className="bi bi-shield-check" style={{ fontSize: "1.2rem" }}></i>
                </div>
              </div>
              <div className="d-flex justify-content-between align-items-center" style={{ fontSize: "0.85rem" }}>
                <span className="text-secondary">Blocked:</span>
                <span className="text-gradient-magenta fw-bold">{stats.blocked_threats || 0} / {stats.total_threats || 0}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Algorithm Variety */}
        <div className="col-md-3">
          <div className="card h-100 shadow" style={{ borderLeft: "4px solid #d500f9" }}>
            <div className="card-body d-flex flex-column justify-content-between">
              <div className="d-flex justify-content-between align-items-start mb-3">
                <div>
                  <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                    Active PQC Enclaves
                  </span>
                  <h3 className="stats-number mt-2 mb-0">{stats.pqc_algorithms || 0}</h3>
                </div>
                <div className="badge bg-magenta bg-opacity-10 text-magenta p-2">
                  <i className="bi bi-safe2" style={{ fontSize: "1.2rem" }}></i>
                </div>
              </div>
              <div className="d-flex justify-content-between align-items-center text-secondary" style={{ fontSize: "0.85rem" }}>
                <span>Selected Cryptography:</span>
                <span className="text-light fw-bold">Hybrid Post-Quantum</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* DETAILED PQC LATENCY & COMPUTE STATS */}
      <div className="row g-3 mb-4">
        {/* Latency Breakdown */}
        <div className="col-md-4">
          <div className="card h-100 shadow">
            <div className="card-body">
              <h6 className="text-secondary text-uppercase font-monospace fw-bold mb-3" style={{ fontSize: "0.75rem" }}>
                Avg KEM / Sig Latency
              </h6>
              <div className="d-flex flex-column gap-3">
                <div>
                  <div className="d-flex justify-content-between align-items-center mb-1" style={{ fontSize: "0.85rem" }}>
                    <span>Keypair Generation (KEM)</span>
                    <strong className="text-info">{stats.avg_keygen_ms || 0} ms</strong>
                  </div>
                  <div className="progress bg-dark bg-opacity-50" style={{ height: "4px" }}>
                    <div className="progress-bar bg-info" style={{ width: `${Math.min(100, (stats.avg_keygen_ms || 0) * 100)}%` }} />
                  </div>
                </div>
                <div>
                  <div className="d-flex justify-content-between align-items-center mb-1" style={{ fontSize: "0.85rem" }}>
                    <span>Encapsulation</span>
                    <strong className="text-success">{stats.avg_encapsulation_ms || 0} ms</strong>
                  </div>
                  <div className="progress bg-dark bg-opacity-50" style={{ height: "4px" }}>
                    <div className="progress-bar bg-success" style={{ width: `${Math.min(100, (stats.avg_encapsulation_ms || 0) * 100)}%` }} />
                  </div>
                </div>
                <div>
                  <div className="d-flex justify-content-between align-items-center mb-1" style={{ fontSize: "0.85rem" }}>
                    <span>Decapsulation</span>
                    <strong className="text-warning">{stats.avg_decapsulation_ms || 0} ms</strong>
                  </div>
                  <div className="progress bg-dark bg-opacity-50" style={{ height: "4px" }}>
                    <div className="progress-bar bg-warning" style={{ width: `${Math.min(100, (stats.avg_decapsulation_ms || 0) * 100)}%` }} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Simulator Control Panel */}
        <div className="col-md-4">
          <SimulatorControl />
        </div>

        {/* Compute & Memory Overhead Stack */}
        <div className="col-md-4 d-flex flex-column gap-3">
          {/* Memory Footprint */}
          <div className="card flex-grow-1 shadow">
            <div className="card-body p-3 d-flex flex-column justify-content-between">
              <div>
                <h6 className="text-secondary text-uppercase font-monospace fw-bold mb-2" style={{ fontSize: "0.7rem" }}>
                  Avg PQC RAM Footprint
                </h6>
                <h3 className="stats-number mb-1" style={{ fontSize: "1.4rem" }}>
                  {stats.avg_pqc_mem_mb || 0} <span style={{ fontSize: "0.9rem" }}>MB</span>
                </h3>
                <p className="text-secondary mb-0" style={{ fontSize: "0.75rem" }}>
                  Static heap overhead of PQC enclaves.
                </p>
              </div>
              <div className="badge bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-25 text-start py-1 px-2 mt-2" style={{ fontSize: "0.7rem" }}>
                <i className="bi bi-shield-exclamation text-warning me-1"></i>
                Dilithium2 requires larger keys
              </div>
            </div>
          </div>

          {/* CPU/Memory Overhead */}
          <div className="card flex-grow-1 shadow">
            <div className="card-body p-3">
              <h6 className="text-secondary text-uppercase font-monospace fw-bold mb-2" style={{ fontSize: "0.7rem" }}>
                Fleet Telemetry Overhead
              </h6>
              <div className="d-flex justify-content-around align-items-center py-1">
                <div className="text-center">
                  <div className="border border-info border-2 rounded-circle d-flex align-items-center justify-content-center mb-1" style={{ width: "45px", height: "45px" }}>
                    <span className="fw-bold text-info" style={{ fontSize: "0.85rem" }}>{stats.avg_cpu || 0}%</span>
                  </div>
                  <small className="text-secondary d-block" style={{ fontSize: "0.7rem" }}>Avg CPU</small>
                </div>
                <div className="text-center">
                  <div className="border border-success border-2 rounded-circle d-flex align-items-center justify-content-center mb-1" style={{ width: "45px", height: "45px" }}>
                    <span className="fw-bold text-success" style={{ fontSize: "0.75rem" }}>{Math.round(stats.avg_memory) || 0}M</span>
                  </div>
                  <small className="text-secondary d-block" style={{ fontSize: "0.7rem" }}>Avg RAM</small>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CHARTS */}
      <div className="row g-4 mb-4">
        {/* Threat chart */}
        <div className="col-md-6">
          <div className="card shadow h-100">
            <div className="card-body">
              <h5 className="mb-3">Threat Severity Breakdown</h5>
              <div style={{ minHeight: "300px", position: "relative" }}>
                <ThreatChart threats={threats} />
              </div>
            </div>
          </div>
        </div>

        {/* PQC Benchmark */}
        <div className="col-md-6">
          <div className="card shadow h-100">
            <div className="card-body">
              <h5 className="mb-3">KEM Keypair Gen Benchmark (ms)</h5>
              <div style={{ minHeight: "360px", position: "relative" }}>
                <BenchmarkChart benchmarks={benchmarks} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* TIMELINE + TOP ATTACKED */}
      <div className="row g-4 mb-4">
        <div className="col-md-8">
          <div className="card shadow h-100">
            <div className="card-body">
              <h5 className="mb-3">Threat Frequency Timeline</h5>
              <div style={{ minHeight: "300px", position: "relative" }}>
                <ThreatTimeline data={timeline} />
              </div>
            </div>
          </div>
        </div>

        <div className="col-md-4">
          <div className="card shadow h-100">
            <div className="card-body">
              <h5 className="mb-3">Top Attacked Devices</h5>
              <TopAttackedDevices devices={topDevices} />
            </div>
          </div>
        </div>
      </div>

      {/* PQC DISTRIBUTION & TERMINAL LOG */}
      <div className="row g-4 mb-4">
        <div className="col-md-5">
          <div className="card shadow h-100">
            <div className="card-body">
              <h5 className="mb-3 text-gradient-magenta">PQC Algorithm Distribution</h5>
              <div style={{ minHeight: "250px", position: "relative" }}>
                <PQCDistribution data={pqcData} />
              </div>
            </div>
          </div>
        </div>

        <div className="col-md-7">
          <TerminalLog />
        </div>
      </div>

      {/* DEVICE TABLE */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <h5 className="mb-3">Live Device Fleet (Recent Active)</h5>
          <DeviceTable devices={devices.slice(0, 10)} />
        </div>
      </div>
    </div>
  );
}

export default Dashboard;