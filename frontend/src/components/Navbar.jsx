import React from "react";

function Navbar() {
  return (
    <nav className="navbar navbar-expand-lg navbar-dark py-3 px-4">
      <div className="container-fluid p-0">
        <span className="navbar-brand d-flex align-items-center" style={{ fontWeight: "700" }}>
          <span 
            className="me-2" 
            style={{ 
              width: "12px", 
              height: "12px", 
              borderRadius: "50%", 
              backgroundColor: "#00e5ff", 
              boxShadow: "0 0 10px #00e5ff",
              display: "inline-block"
            }}
          />
          QuantumShield-IoT SOC Dashboard
        </span>
        
        <div className="d-flex align-items-center">
          <div className="text-secondary me-3" style={{ fontSize: "0.85rem" }}>
            Last Backup: <span className="text-light">Just Now</span>
          </div>
          <span className="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25 px-3 py-2">
            Secure Mode
          </span>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;