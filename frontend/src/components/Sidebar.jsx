import { NavLink } from "react-router-dom";

function Sidebar() {
  return (
    <div
      className="sidebar text-white p-4"
      style={{
        width: "260px",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column"
      }}
    >
      <div className="d-flex align-items-center mb-4 pb-2 border-bottom border-secondary border-opacity-25">
        <span 
          style={{
            fontSize: "1.5rem", 
            fontWeight: "800",
            letterSpacing: "-0.05em",
            background: "linear-gradient(135deg, #00e5ff 0%, #00e676 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent"
          }}
        >
          QuantumShield
        </span>
        <span className="badge bg-dark text-cyan border border-info border-opacity-50 ms-2" style={{ fontSize: "0.65rem", padding: "3px 6px" }}>v1.2</span>
      </div>

      <ul className="nav flex-column mb-auto">
        <li className="nav-item mb-2">
          <NavLink
            className={({ isActive }) => `nav-link text-white ${isActive ? 'active' : ''}`}
            to="/"
            end
          >
            <i className="bi bi-cpu me-2 text-info"></i> Dashboard
          </NavLink>
        </li>

        <li className="nav-item mb-2">
          <NavLink
            className={({ isActive }) => `nav-link text-white ${isActive ? 'active' : ''}`}
            to="/devices"
          >
            <i className="bi bi-router me-2 text-success"></i> Devices
          </NavLink>
        </li>

        <li className="nav-item mb-2">
          <NavLink
            className={({ isActive }) => `nav-link text-white ${isActive ? 'active' : ''}`}
            to="/threats"
          >
            <i className="bi bi-shield-slash me-2 text-danger"></i> Threat Center
          </NavLink>
        </li>

        <li className="nav-item mb-2">
          <NavLink
            className={({ isActive }) => `nav-link text-white ${isActive ? 'active' : ''}`}
            to="/benchmarks"
          >
            <i className="bi bi-speedometer2 me-2 text-warning"></i> Benchmarks
          </NavLink>
        </li>

        <li className="nav-item mb-2">
          <NavLink
            className={({ isActive }) => `nav-link text-white ${isActive ? 'active' : ''}`}
            to="/monitoring"
          >
            <i className="bi bi-graph-up me-2 text-magenta"></i> Monitoring
          </NavLink>
        </li>
      </ul>

      <div className="mt-auto pt-3 border-top border-secondary border-opacity-10 text-secondary" style={{ fontSize: "0.8rem" }}>
        <div>SOC Security Mode: <strong className="text-success">Active</strong></div>
        <div>System Health: <strong className="text-info">Optimal</strong></div>
      </div>
    </div>
  );
}

export default Sidebar;