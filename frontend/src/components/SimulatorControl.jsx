import { useEffect, useState } from "react";
import api from "../services/api";

function SimulatorControl() {
  const [config, setConfig] = useState({
    publish_interval: 10,
    attack_probability: 0.005,
    active_devices: 0
  });
  const [attackType, setAttackType] = useState("DDoS");
  const [targetDevice, setTargetDevice] = useState("");
  const [actionStatus, setActionStatus] = useState("");
  const [actionType, setActionType] = useState("info"); // "info", "success", "danger"
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchConfig();
    const interval = setInterval(fetchConfig, 10000);
    return () => clearInterval(interval);
  }, []);

  async function fetchConfig() {
    try {
      const res = await api.get("/simulator/config");
      setConfig(res.data);
    } catch (err) {
      console.error("Error fetching simulator config:", err);
    }
  }

  async function handleConfigChange(field, val) {
    const updated = { ...config, [field]: val };
    setConfig(updated);

    try {
      await api.post("/simulator/config", null, {
        params: {
          publish_interval: field === "publish_interval" ? parseInt(val) : config.publish_interval,
          attack_probability: field === "attack_probability" ? parseFloat(val) : config.attack_probability
        }
      });
      showStatus(`Config updated: ${field} set to ${val}`, "success");
    } catch (err) {
      showStatus("Failed to update simulator config", "danger");
    }
  }

  async function handleTriggerAttack() {
    setLoading(true);
    try {
      const res = await api.post("/simulator/trigger-attack", null, {
        params: {
          attack_type: attackType,
          device_id: targetDevice.trim() || undefined
        }
      });
      if (res.data.status === "success") {
        showStatus(`Injected ${res.data.attack_type} attack on device ${res.data.device_id}!`, "success");
        setTargetDevice("");
      } else {
        showStatus(res.data.message || "Failed to trigger attack", "danger");
      }
    } catch (err) {
      showStatus("Error communicating with simulator API", "danger");
    }
    setLoading(false);
  }

  async function handleResetSimulator() {
    setLoading(true);
    try {
      const res = await api.post("/simulator/reset");
      showStatus("Fleet state reset successfully. Threat logs cleared.", "success");
      fetchConfig();
    } catch (err) {
      showStatus("Failed to reset simulator", "danger");
    }
    setLoading(false);
  }

  function showStatus(msg, type = "info") {
    setActionStatus(msg);
    setActionType(type);
    setTimeout(() => {
      setActionStatus("");
    }, 6000);
  }

  return (
    <div className="card shadow h-100 border-0 bg-dark-card text-white">
      <div className="card-body p-4 d-flex flex-column justify-content-between">
        <div>
          {/* Header */}
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h5 className="mb-0 text-gradient-cyan d-flex align-items-center gap-2">
              <i className="bi bi-sliders2"></i> QuantumShield Simulator
            </h5>
            <span className="badge bg-info bg-opacity-10 text-info border border-info border-opacity-25 font-monospace">
              {config.active_devices} Devices Active
            </span>
          </div>

          <p className="text-secondary small mb-4">
            Dynamic control over the physical IoT simulation. Set timing parameters, adjust attack probabilities, or manually inject specific cyber-threat vectors.
          </p>

          {/* Config Controls */}
          <div className="mb-4">
            <div className="mb-3">
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="small text-light">Telemetry Period</span>
                <strong className="text-cyan font-monospace">{config.publish_interval}s</strong>
              </div>
              <input
                type="range"
                className="form-range custom-slider"
                min="2"
                max="30"
                step="1"
                value={config.publish_interval}
                onChange={(e) => handleConfigChange("publish_interval", e.target.value)}
              />
            </div>

            <div className="mb-3">
              <div className="d-flex justify-content-between align-items-center mb-1">
                <span className="small text-light">Spontaneous Attack Rate</span>
                <strong className="text-magenta font-monospace">{(config.attack_probability * 100).toFixed(2)}%</strong>
              </div>
              <input
                type="range"
                className="form-range custom-slider-magenta"
                min="0"
                max="0.05"
                step="0.001"
                value={config.attack_probability}
                onChange={(e) => handleConfigChange("attack_probability", e.target.value)}
              />
            </div>
          </div>

          <hr className="border-secondary border-opacity-25 mb-4" />

          {/* Trigger Attack Form */}
          <div className="mb-4">
            <h6 className="small text-secondary text-uppercase font-monospace fw-bold mb-3">
              Threat Injection Panel
            </h6>
            
            <div className="row g-2">
              <div className="col-7">
                <select
                  className="form-select bg-dark border-secondary border-opacity-25 text-white"
                  value={attackType}
                  onChange={(e) => setAttackType(e.target.value)}
                  style={{ fontSize: "0.9rem" }}
                >
                  <option value="DDoS">DDoS (Network Flood)</option>
                  <option value="Cryptojacking">Cryptojacking (CPU/RAM Spikes)</option>
                  <option value="Thermal Tampering">Thermal Override (Cooling Fail)</option>
                </select>
              </div>
              <div className="col-5">
                <input
                  type="text"
                  className="form-control bg-dark border-secondary border-opacity-25 text-white font-monospace"
                  placeholder="iot_00123 (Opt)"
                  value={targetDevice}
                  onChange={(e) => setTargetDevice(e.target.value)}
                  style={{ fontSize: "0.9rem" }}
                />
              </div>
            </div>

            <button
              className="btn btn-outline-danger w-100 mt-2 d-flex align-items-center justify-content-center gap-2"
              onClick={handleTriggerAttack}
              disabled={loading}
              style={{ fontWeight: "600", fontSize: "0.9rem" }}
            >
              {loading ? (
                <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
              ) : (
                <i className="bi bi-shield-slash"></i>
              )}
              Inject Target Threat Payload
            </button>
          </div>
        </div>

        {/* Global Reset Action */}
        <div>
          <button
            className="btn btn-dark border border-secondary border-opacity-25 w-100 d-flex align-items-center justify-content-center gap-2 mb-2"
            onClick={handleResetSimulator}
            disabled={loading}
            style={{ fontWeight: "600", fontSize: "0.9rem", color: "#b0bec5" }}
          >
            <i className="bi bi-arrow-counterclockwise"></i> Global Emergency Reset
          </button>

          {/* Action Status Notification */}
          {actionStatus && (
            <div 
              className={`alert alert-${actionType === "success" ? "success" : actionType === "danger" ? "danger" : "info"} bg-opacity-10 text-start p-2 mb-0 mt-2 border border-${actionType} border-opacity-25`} 
              style={{ fontSize: "0.8rem", transition: "opacity 0.3s" }}
            >
              <i className={`bi ${actionType === "success" ? "bi-check-circle" : actionType === "danger" ? "bi-exclamation-triangle" : "bi-info-circle"} me-2`}></i>
              {actionStatus}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default SimulatorControl;
