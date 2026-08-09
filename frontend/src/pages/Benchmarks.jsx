import { useEffect, useState } from "react";
import api from "../services/api";
import BenchmarkChart from "../components/BenchmarkChart";
import KeySizeChart from "../components/KeySizeChart";

function Benchmarks() {
  const [benchmarks, setBenchmarks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadBenchmarks();
  }, []);

  async function loadBenchmarks() {
    setLoading(true);
    try {
      const res = await api.get("/benchmarks");
      setBenchmarks(res.data);
    } catch (error) {
      console.error(error);
    }
    setLoading(false);
  }

  return (
    <div className="container-fluid py-2 fade-in">
      {/* HEADER SECTION */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 className="mb-1 text-gradient-cyan" style={{ fontSize: "2rem", fontWeight: "800" }}>
            Post-Quantum Cryptographic Benchmarks
          </h2>
          <p className="text-secondary mb-0">
            Performance comparison metrics for key generation, encapsulation, decapsulation, signing, and verification.
          </p>
        </div>
        <button 
          className="btn btn-dark border border-secondary border-opacity-25 text-white d-flex align-items-center gap-2"
          onClick={loadBenchmarks}
        >
          <i className="bi bi-arrow-clockwise"></i> Recalculate Benchmarks
        </button>
      </div>

      <div className="row g-4 mb-4">
        {/* Benchmark Chart Card */}
        <div className="col-lg-6">
          <div className="card shadow h-100 border-0">
            <div className="card-body p-4">
              <h5 className="mb-3 text-gradient-cyan">Latency Benchmark Comparison</h5>
              {loading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-info" role="status">
                    <span className="visually-hidden">Loading Chart...</span>
                  </div>
                </div>
              ) : (
                <BenchmarkChart benchmarks={benchmarks} />
              )}
            </div>
          </div>
        </div>

        {/* Key Size Chart Card */}
        <div className="col-lg-6">
          <div className="card shadow h-100 border-0">
            <div className="card-body p-4">
              <h5 className="mb-3 text-gradient-green">Cryptographic Key & Payload Sizes</h5>
              <KeySizeChart />
            </div>
          </div>
        </div>
      </div>

      <div className="row g-4 mb-4">
        {/* Algorithm Type Info Card */}
        <div className="col-12">
          <div className="card shadow border-0">
            <div className="card-body p-4">
              <h5 className="mb-3">PQC Category Standards</h5>
              <div className="row g-3">
                <div className="col-md-6">
                  <div className="p-3 bg-dark bg-opacity-20 border border-secondary border-opacity-10 rounded h-100">
                    <span className="badge bg-info bg-opacity-10 text-info border border-info border-opacity-25 mb-2">Key Encapsulation (KEM)</span>
                    <p className="small text-secondary mb-0">
                      Standard algorithms like <strong>Kyber512</strong> and <strong>Kyber768</strong> are used for secure key exchanges, establishing shared secret channels over unsecured pathways.
                    </p>
                  </div>
                </div>
                <div className="col-md-6">
                  <div className="p-3 bg-dark bg-opacity-20 border border-secondary border-opacity-10 rounded h-100">
                    <span className="badge bg-magenta bg-opacity-10 text-magenta border border-magenta border-opacity-25 mb-2">Digital Signatures (Sig)</span>
                    <p className="small text-secondary mb-0">
                      Signature algorithms like <strong>Dilithium2</strong> and <strong>Falcon512</strong> verify endpoint device identity and message origin authentication, vital to prevent firmware tampering.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Complete Benchmark Table Card */}
        <div className="col-12">
          <div className="card shadow border-0">
            <div className="card-body p-4">
              <h5 className="mb-3">Cryptographic Telemetry Table</h5>
              {loading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-info" role="status">
                    <span className="visually-hidden">Loading telemetry data...</span>
                  </div>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Algorithm Standard</th>
                        <th>KeyGen Latency</th>
                        <th>Encap / Sign</th>
                        <th>Decap / Verify</th>
                        <th>Max RAM Overhead</th>
                        <th>CPU Load</th>
                        <th>Performance Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {benchmarks.map((b) => {
                        const isKem = b.algorithm.startsWith("Kyber");
                        const latencyScore = isKem 
                          ? (b.keygen_time_ms + b.encapsulation_time_ms + b.decapsulation_time_ms)
                          : (b.signature_time_ms + b.verify_time_ms);
                        
                        return (
                          <tr key={b.id}>
                            <td className="fw-bold text-white font-monospace">
                              <span className={`me-2 status-glow-${isKem ? 'online' : 'offline'}`} />
                              {b.algorithm}
                            </td>
                            <td className="font-monospace text-light">{b.keygen_time_ms > 0 ? `${b.keygen_time_ms} ms` : "N/A (Signature)"}</td>
                            <td className="font-monospace text-light">
                              {isKem ? `${b.encapsulation_time_ms} ms (Encap)` : `${b.signature_time_ms.toFixed(2)} ms (Sign)`}
                            </td>
                            <td className="font-monospace text-light">
                              {isKem ? `${b.decapsulation_time_ms} ms (Decap)` : `${b.verify_time_ms.toFixed(2)} ms (Verify)`}
                            </td>
                            <td className="font-monospace text-info">{b.memory_usage_mb.toFixed(1)} MB</td>
                            <td>
                              <span className={`badge bg-${b.cpu_usage_percent > 50 ? 'danger' : 'success'} bg-opacity-10 text-${b.cpu_usage_percent > 50 ? 'danger' : 'success'} border border-${b.cpu_usage_percent > 50 ? 'danger' : 'success'} border-opacity-25`}>
                                {b.cpu_usage_percent.toFixed(1)}%
                              </span>
                            </td>
                            <td>
                              <span className="badge bg-dark border border-secondary border-opacity-50 text-white font-monospace">
                                {Math.round(1000 / (latencyScore || 1))} OPS/s
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Benchmarks;