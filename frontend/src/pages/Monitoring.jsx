import React from "react";

function Monitoring() {
  return (
    <div className="container-fluid py-2 fade-in">
      <div className="mb-4">
        <h2 className="mb-1 text-gradient-cyan" style={{ fontSize: "2rem", fontWeight: "800" }}>
          Observability Portal
        </h2>
        <p className="text-secondary mb-0">
          Access deep system metrics, process logs, and dashboard metrics via Grafana and Prometheus gateways.
        </p>
      </div>

      <div className="row g-4">
        {/* Core observability card */}
        <div className="col-md-8">
          <div className="card shadow p-4 h-100 border-0 d-flex flex-column justify-content-between">
            <div>
              <h4 className="mb-3">Grafana Integrations</h4>
              <p className="text-secondary">
                The post-quantum security framework publishes unified logs to Prometheus metrics endpoints. You can query custom metrics, set threshold alerts, and visualize active network socket queues.
              </p>
              
              {/* Features list */}
              <div className="row g-3 my-2">
                <div className="col-sm-6">
                  <div className="d-flex align-items-center gap-2 text-light font-monospace" style={{ fontSize: "0.9rem" }}>
                    <i className="bi bi-check2-circle text-info"></i>
                    <span>MQTT Queue Size Telemetry</span>
                  </div>
                </div>
                <div className="col-sm-6">
                  <div className="d-flex align-items-center gap-2 text-light font-monospace" style={{ fontSize: "0.9rem" }}>
                    <i className="bi bi-check2-circle text-info"></i>
                    <span>AI Model Inference Latency</span>
                  </div>
                </div>
                <div className="col-sm-6">
                  <div className="d-flex align-items-center gap-2 text-light font-monospace" style={{ fontSize: "0.9rem" }}>
                    <i className="bi bi-check2-circle text-info"></i>
                    <span>PQC Signature Byte Overhead</span>
                  </div>
                </div>
                <div className="col-sm-6">
                  <div className="d-flex align-items-center gap-2 text-light font-monospace" style={{ fontSize: "0.9rem" }}>
                    <i className="bi bi-check2-circle text-info"></i>
                    <span>Device Battery depletion predictions</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-top border-secondary border-opacity-10 d-flex justify-content-between align-items-center">
              <span className="text-secondary small">Grafana Port: <code className="text-info">3001</code></span>
              <a
                href="http://localhost:3001"
                target="_blank"
                rel="noreferrer"
                className="btn btn-info d-flex align-items-center gap-2"
                style={{ fontWeight: "600", color: "#080d19" }}
              >
                <i className="bi bi-box-arrow-up-right"></i> Open Grafana Dashboard
              </a>
            </div>
          </div>
        </div>

        {/* Integration Status Card */}
        <div className="col-md-4">
          <div className="card shadow p-4 h-100 border-0 d-flex flex-column justify-content-between">
            <div>
              <h5 className="mb-3">Gateway Statuses</h5>
              <div className="d-flex flex-column gap-3">
                <div className="d-flex justify-content-between align-items-center p-2 rounded bg-dark bg-opacity-25 border border-secondary border-opacity-10">
                  <span style={{ fontSize: "0.9rem" }}>Prometheus Server</span>
                  <span className="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25 px-2 py-1">ONLINE</span>
                </div>
                <div className="d-flex justify-content-between align-items-center p-2 rounded bg-dark bg-opacity-25 border border-secondary border-opacity-10">
                  <span style={{ fontSize: "0.9rem" }}>Grafana Instance</span>
                  <span className="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25 px-2 py-1">ONLINE</span>
                </div>
                <div className="d-flex justify-content-between align-items-center p-2 rounded bg-dark bg-opacity-25 border border-secondary border-opacity-10">
                  <span style={{ fontSize: "0.9rem" }}>MQTT Broker</span>
                  <span className="badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25 px-2 py-1">STANDBY</span>
                </div>
              </div>
            </div>

            <div className="badge bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-25 text-start py-2 px-3 mt-3">
              <i className="bi bi-shield-lock text-success me-2"></i>
              Data feeds are encrypted via TLS
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Monitoring;