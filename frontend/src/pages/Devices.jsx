import { useEffect, useState } from "react";
import api from "../services/api";
import DeviceTable from "../components/DeviceTable";

function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDevices();
  }, []);

  async function loadDevices() {
    setLoading(true);
    try {
      const res = await api.get("/devices");
      setDevices(res.data);
    } catch (error) {
      console.error(error);
    }
    setLoading(false);
  }

  return (
    <div className="container-fluid py-2 fade-in">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 className="mb-1 text-gradient-cyan" style={{ fontSize: "2rem", fontWeight: "800" }}>
            Enrolled IoT Devices
          </h2>
          <p className="text-secondary mb-0">
            Total active devices registered with the post-quantum telemetry engine.
          </p>
        </div>
        <button 
          className="btn btn-dark border border-secondary border-opacity-25 text-white d-flex align-items-center gap-2"
          onClick={loadDevices}
        >
          <i className="bi bi-arrow-clockwise"></i> Refresh Fleet
        </button>
      </div>

      <div className="card shadow border-0">
        <div className="card-body p-4">
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h5 className="mb-0">Device Registry</h5>
            <span className="badge bg-info bg-opacity-10 text-info border border-info border-opacity-25 px-3 py-2">
              {devices.length} Devices Registered
            </span>
          </div>
          
          {loading ? (
            <div className="text-center py-5">
              <div className="spinner-border text-info" role="status">
                <span className="visually-hidden">Loading...</span>
              </div>
            </div>
          ) : (
            <DeviceTable devices={devices} />
          )}
        </div>
      </div>
    </div>
  );
}

export default Devices;