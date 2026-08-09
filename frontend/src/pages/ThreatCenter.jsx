import { useEffect, useState } from "react";
import api from "../services/api";
import ThreatChart from "../components/ThreatChart";

function ThreatCenter() {
  const [threats, setThreats] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState(null);

  useEffect(() => {
    loadThreats();
    loadMetrics();
  }, []);

  async function loadMetrics() {
    try {
      const res = await api.get("/ai/metrics");
      setMetrics(res.data);
    } catch (error) {
      console.error("Failed to load AI model metrics", error);
    }
  }

  async function loadThreats() {
    setLoading(true);
    try {
      const res = await api.get("/threats");
      setThreats(res.data);
    } catch (error) {
      console.error(error);
    }
    setLoading(false);
  }

  // Filtered threats based on search and dropdown filters
  const filteredThreats = threats.filter(t => {
    const matchesSearch = t.device_id.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          t.threat_type.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === "ALL" || t.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadgeClass = (severity) => {
    switch (severity) {
      case "HIGH":
        return "badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25";
      case "MEDIUM":
        return "badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25";
      default:
        return "badge bg-info bg-opacity-10 text-info border border-info border-opacity-25";
    }
  };

  const getConfidenceColor = (conf) => {
    if (conf > 0.9) return "#ff1744"; // red
    if (conf > 0.7) return "#ff9100"; // orange
    return "#00e5ff"; // cyan
  };

  // Calculate statistics
  const highCount = threats.filter(t => t.severity === "HIGH").length;
  const mediumCount = threats.filter(t => t.severity === "MEDIUM").length;
  const lowCount = threats.filter(t => t.severity === "LOW").length;
  const blockedCount = threats.filter(t => t.blocked).length;

  return (
    <div className="container-fluid py-2 fade-in">
      {/* HEADER SECTION */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 className="mb-1 text-gradient-magenta" style={{ fontSize: "2rem", fontWeight: "800" }}>
            Threat Mitigation Center
          </h2>
          <p className="text-secondary mb-0">
            Intrusion detection log, machine learning threat classifications, and enclaved firewall rules.
          </p>
        </div>
        <button 
          className="btn btn-dark border border-secondary border-opacity-25 text-white d-flex align-items-center gap-2"
          onClick={loadThreats}
        >
          <i className="bi bi-arrow-clockwise"></i> Refresh Alerts
        </button>
      </div>

      {/* THREAT METRIC CARDS */}
      <div className="row g-3 mb-4">
        <div className="col-md-3">
          <div className="card shadow" style={{ borderLeft: "4px solid #ff1744" }}>
            <div className="card-body">
              <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                Total Alerts
              </span>
              <h3 className="stats-number mt-2 mb-0">{threats.length}</h3>
              <small className="text-secondary d-block mt-2">Active security incidents</small>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card shadow" style={{ borderLeft: "4px solid #ff9100" }}>
            <div className="card-body">
              <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                High Severity
              </span>
              <h3 className="stats-number mt-2 mb-0 text-gradient-magenta">{highCount}</h3>
              <small className="text-secondary d-block mt-2">Immediate response required</small>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card shadow" style={{ borderLeft: "4px solid #00e676" }}>
            <div className="card-body">
              <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                Mitigated (Blocked)
              </span>
              <h3 className="stats-number mt-2 mb-0 text-gradient-green">{blockedCount}</h3>
              <small className="text-secondary d-block mt-2">Auto-mitigated by enclaved PQC rules</small>
            </div>
          </div>
        </div>

        <div className="col-md-3">
          <div className="card shadow" style={{ borderLeft: "4px solid #00e5ff" }}>
            <div className="card-body">
              <span className="text-secondary text-uppercase font-monospace fw-bold" style={{ fontSize: "0.75rem" }}>
                Low & Medium
              </span>
              <h3 className="stats-number mt-2 mb-0">{mediumCount + lowCount}</h3>
              <small className="text-secondary d-block mt-2">Monitoring anomalies</small>
            </div>
          </div>
        </div>
      </div>

      <div className="row g-4">
        {/* Threat Distribution Chart Card */}
        <div className="col-md-5">
          <div className="card shadow h-100 border-0">
            <div className="card-body p-4 d-flex flex-column justify-content-between">
              <h5 className="mb-3">Threat Severity Proportions</h5>
              {loading ? (
                <div className="text-center py-5">
                  <div className="spinner-border text-info" role="status">
                    <span className="visually-hidden">Loading Chart...</span>
                  </div>
                </div>
              ) : (
                <ThreatChart threats={threats} />
              )}
              <div className="badge bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-25 py-2 px-3 mt-3 text-start">
                <i className="bi bi-info-circle text-info me-2"></i>
                Mitigation parameters automatically scale based on threat severities.
              </div>
            </div>
          </div>
        </div>

        {/* Live Logs Table Card */}
        <div className="col-md-7">
          <div className="card shadow h-100 border-0">
            <div className="card-body p-4 d-flex flex-column">
              <h5 className="mb-3">Incident Management Log</h5>

              {/* SEARCH & FILTERS */}
              <div className="d-flex gap-2 mb-3">
                <div className="input-group">
                  <span className="input-group-text bg-dark border-secondary border-opacity-25 text-secondary">
                    <i className="bi bi-search"></i>
                  </span>
                  <input
                    type="text"
                    className="form-control bg-dark text-white border-secondary border-opacity-25"
                    placeholder="Search by Device or Threat..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    style={{ fontSize: "0.9rem" }}
                  />
                </div>
                <select
                  className="form-select bg-dark text-white border-secondary border-opacity-25 w-auto"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={{ fontSize: "0.9rem" }}
                >
                  <option value="ALL">All Severities</option>
                  <option value="HIGH">High Only</option>
                  <option value="MEDIUM">Medium Only</option>
                  <option value="LOW">Low Only</option>
                </select>
              </div>

              {loading ? (
                <div className="text-center py-5 flex-grow-1 d-flex align-items-center justify-content-center">
                  <div className="spinner-border text-info" role="status">
                    <span className="visually-hidden">Loading Log...</span>
                  </div>
                </div>
              ) : (
                <div className="table-responsive flex-grow-1" style={{ maxHeight: "400px", overflowY: "auto" }}>
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Device ID</th>
                        <th>Classification</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Action Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredThreats.length === 0 ? (
                        <tr>
                          <td colSpan="5" className="text-center py-4 text-secondary">
                            No threat records match selection.
                          </td>
                        </tr>
                      ) : (
                        filteredThreats.map((threat) => (
                          <tr key={threat.id}>
                            <td className="font-monospace text-white">{threat.device_id}</td>
                            <td>
                              <span className="text-light">{threat.threat_type}</span>
                            </td>
                            <td>
                              <span className={getSeverityBadgeClass(threat.severity)}>
                                {threat.severity}
                              </span>
                            </td>
                            <td className="font-monospace fw-bold" style={{ color: getConfidenceColor(threat.confidence) }}>
                              {Math.round(threat.confidence * 100)}%
                            </td>
                            <td>
                              {threat.blocked ? (
                                <span className="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25 px-2 py-1">
                                  <i className="bi bi-shield-lock me-1"></i> Blocked
                                </span>
                              ) : (
                                <span className="badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25 px-2 py-1">
                                  <i className="bi bi-eye me-1"></i> Monitored
                                </span>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* AI MODEL EVALUATION METRICS CARD ROW */}
      {metrics && (
        <div className="row g-4 mt-2">
          {/* Performance Overview Card */}
          <div className="col-md-6">
            <div className="card shadow border-0 h-100">
              <div className="card-body p-4 d-flex flex-column justify-content-between">
                <div>
                  <h5 className="mb-4 text-white font-monospace text-gradient-magenta" style={{ fontSize: "1.1rem", fontWeight: "700" }}>
                    AI Threat Classifier Performance (OOD Generalization)
                  </h5>
                  <div className="row text-center g-3 mb-4">
                    <div className="col-6 col-md-3">
                      <span className="text-secondary font-monospace" style={{ fontSize: "0.75rem" }}>Accuracy</span>
                      <h4 className="mt-1 mb-0 text-white font-monospace" style={{ fontWeight: "700" }}>
                        {(metrics.accuracy * 100).toFixed(1)}%
                      </h4>
                    </div>
                    <div className="col-6 col-md-3">
                      <span className="text-secondary font-monospace" style={{ fontSize: "0.75rem" }}>Precision</span>
                      <h4 className="mt-1 mb-0 text-white font-monospace" style={{ fontWeight: "700" }}>
                        {(metrics.precision * 100).toFixed(1)}%
                      </h4>
                    </div>
                    <div className="col-6 col-md-3">
                      <span className="text-secondary font-monospace" style={{ fontSize: "0.75rem" }}>Recall</span>
                      <h4 className="mt-1 mb-0 text-white font-monospace" style={{ fontWeight: "700" }}>
                        {(metrics.recall * 100).toFixed(1)}%
                      </h4>
                    </div>
                    <div className="col-6 col-md-3">
                      <span className="text-secondary font-monospace" style={{ fontSize: "0.75rem" }}>F1-Score</span>
                      <h4 className="mt-1 mb-0 text-white font-monospace" style={{ fontWeight: "700" }}>
                        {(metrics.f1_score * 100).toFixed(1)}%
                      </h4>
                    </div>
                  </div>
                  <hr className="my-3 border-secondary border-opacity-25" />
                  <div className="d-flex justify-content-between align-items-center mb-2" style={{ fontSize: "0.9rem" }}>
                    <span className="text-secondary">Weighted ROC-AUC score:</span>
                    <span className="text-gradient-green fw-bold font-monospace">
                      {(metrics.roc_auc * 100).toFixed(4)}%
                    </span>
                  </div>
                  <div className="d-flex justify-content-between align-items-center" style={{ fontSize: "0.9rem" }}>
                    <span className="text-secondary">Optimal Hyperparameters (GridSearchCV):</span>
                    <span className="text-warning font-monospace">
                      depth={metrics.best_params?.max_depth || 4}, lr={metrics.best_params?.learning_rate || 0.05}, trees={metrics.best_params?.n_estimators || 100}
                    </span>
                  </div>
                </div>
                <div className="badge bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-25 py-2 px-3 mt-3 text-start">
                  <i className="bi bi-shield-check text-success me-2"></i>
                  Evaluated on completely independent out-of-distribution shifted environment.
                </div>
              </div>
            </div>
          </div>
          
          {/* Confusion Matrix Card */}
          <div className="col-md-6">
            <div className="card shadow border-0 h-100">
              <div className="card-body p-4">
                <h5 className="mb-3 text-white font-monospace" style={{ fontSize: "1.1rem", fontWeight: "700" }}>
                  OOD Evaluation Confusion Matrix
                </h5>
                <div className="table-responsive">
                  <table className="table table-bordered border-secondary border-opacity-25 text-center text-light align-middle mb-0" style={{ fontSize: "0.78rem" }}>
                    <thead>
                      <tr className="table-dark">
                        <th>True \ Pred</th>
                        <th>Normal</th>
                        <th>DDoS</th>
                        <th>Crypto</th>
                        <th>Thermal</th>
                        <th>Recon</th>
                      </tr>
                    </thead>
                    <tbody>
                      {["Normal", "DDoS", "Crypto", "Thermal", "Recon"].map((rowLabel, rIdx) => (
                        <tr key={rowLabel}>
                          <td className="fw-bold bg-dark text-start" style={{ fontSize: "0.75rem" }}>{rowLabel}</td>
                          {["Normal", "DDoS", "Crypto", "Thermal", "Recon"].map((colLabel, cIdx) => {
                            const val = metrics.confusion_matrix?.[rIdx]?.[cIdx] || 0;
                            const isDiagonal = rIdx === cIdx;
                            return (
                              <td 
                                key={colLabel} 
                                className="font-monospace"
                                style={{ 
                                  backgroundColor: isDiagonal && val > 0 ? "rgba(0, 230, 118, 0.12)" : val > 0 ? "rgba(255, 23, 68, 0.12)" : "transparent",
                                  color: isDiagonal && val > 0 ? "#00e676" : val > 0 ? "#ff1744" : "#6c757d"
                                }}
                              >
                                {val}
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ThreatCenter;