import React, { useState } from "react";
import { Bar } from "react-chartjs-2";
import {
  Chart,
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  BarElement,
  Tooltip,
  Legend
} from "chart.js";

// Register LogarithmicScale to support log scales
Chart.register(
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  BarElement,
  Tooltip,
  Legend
);

function BenchmarkChart({ benchmarks }) {
  const [filter, setFilter] = useState("ALL"); // 'ALL', 'KEM', 'SIG'
  const [scaleType, setScaleType] = useState("logarithmic"); // 'linear', 'logarithmic'

  // Filter benchmarks dynamically
  const filteredBenchmarks = benchmarks.filter(b => {
    if (filter === "KEM") return b.algorithm.startsWith("Kyber");
    if (filter === "SIG") return !b.algorithm.startsWith("Kyber");
    return true;
  });

  // Safe logarithmic mapping (0 values must be represented as null/very small numbers in log scales)
  const mapValue = (val) => {
    if (val === 0) return scaleType === "logarithmic" ? null : 0;
    return val;
  };

  const data = {
    labels: filteredBenchmarks.map(b => b.algorithm),
    datasets: [
      {
        label: "Keypair Generation (ms)",
        data: filteredBenchmarks.map(b => mapValue(b.keygen_time_ms)),
        backgroundColor: "rgba(0, 229, 255, 0.4)",
        borderColor: "#00e5ff",
        borderWidth: 1.5,
        borderRadius: 6,
        hoverBackgroundColor: "rgba(0, 229, 255, 0.7)"
      },
      {
        label: filter === "SIG" ? "Signing Time (ms)" : filter === "KEM" ? "Encapsulation (ms)" : "Encapsulate / Sign (ms)",
        data: filteredBenchmarks.map(b => {
          const isKem = b.algorithm.startsWith("Kyber");
          return mapValue(isKem ? b.encrypt_time_ms : b.signature_time_ms);
        }),
        backgroundColor: "rgba(0, 230, 118, 0.4)",
        borderColor: "#00e676",
        borderWidth: 1.5,
        borderRadius: 6,
        hoverBackgroundColor: "rgba(0, 230, 118, 0.7)"
      },
      {
        label: filter === "SIG" ? "Verification Time (ms)" : filter === "KEM" ? "Decapsulation (ms)" : "Decapsulate / Verify (ms)",
        data: filteredBenchmarks.map(b => {
          const isKem = b.algorithm.startsWith("Kyber");
          return mapValue(isKem ? b.decrypt_time_ms : b.verify_time_ms);
        }),
        backgroundColor: "rgba(213, 0, 249, 0.4)",
        borderColor: "#d500f9",
        borderWidth: 1.5,
        borderRadius: 6,
        hoverBackgroundColor: "rgba(213, 0, 249, 0.7)"
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: "#cbd5e1",
          font: { family: "Outfit", size: 11 }
        }
      },
      tooltip: {
        backgroundColor: "#0f172a",
        titleFont: { family: "Outfit" },
        bodyFont: { family: "Outfit" },
        borderColor: "rgba(255, 255, 255, 0.1)",
        borderWidth: 1,
        callbacks: {
          label: function(context) {
            let label = context.dataset.label || '';
            if (label) {
              label += ': ';
            }
            if (context.parsed.y !== null) {
              label += context.parsed.y.toFixed(4) + ' ms';
            }
            return label;
          }
        }
      }
    },
    scales: {
      x: {
        grid: {
          color: "rgba(255, 255, 255, 0.04)"
        },
        ticks: {
          color: "#94a3b8",
          font: { family: "Outfit", size: 12, weight: "bold" }
        }
      },
      y: {
        type: scaleType,
        min: scaleType === "logarithmic" ? 0.005 : undefined, // set safe min for log scale so tiny elements show
        grid: {
          color: "rgba(255, 255, 255, 0.04)"
        },
        ticks: {
          color: "#94a3b8",
          font: { family: "Outfit" },
          callback: function(value) {
            return value + " ms";
          }
        }
      }
    }
  };

  const handleFilterChange = (newFilter) => {
    setFilter(newFilter);
    // Auto toggle scale type for cleaner views
    if (newFilter === "ALL") {
      setScaleType("logarithmic");
    } else {
      setScaleType("linear");
    }
  };

  return (
    <div>
      {/* Chart Control Toolbar */}
      <div className="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
        {/* Filter Tabs */}
        <div className="btn-group btn-group-sm">
          <button
            className={`btn ${filter === "ALL" ? "btn-info text-dark" : "btn-dark border border-secondary border-opacity-25 text-secondary"}`}
            onClick={() => handleFilterChange("ALL")}
          >
            All Algorithms
          </button>
          <button
            className={`btn ${filter === "KEM" ? "btn-info text-dark" : "btn-dark border border-secondary border-opacity-25 text-secondary"}`}
            onClick={() => handleFilterChange("KEM")}
          >
            KEM (Exchange)
          </button>
          <button
            className={`btn ${filter === "SIG" ? "btn-info text-dark" : "btn-dark border border-secondary border-opacity-25 text-secondary"}`}
            onClick={() => handleFilterChange("SIG")}
          >
            Signature (Auth)
          </button>
        </div>

        {/* Scale Toggle */}
        <div className="btn-group btn-group-sm">
          <button
            className={`btn ${scaleType === "linear" ? "btn-secondary text-white" : "btn-dark border border-secondary border-opacity-25 text-secondary"}`}
            onClick={() => setScaleType("linear")}
          >
            Linear Scale
          </button>
          <button
            className={`btn ${scaleType === "logarithmic" ? "btn-secondary text-white" : "btn-dark border border-secondary border-opacity-25 text-secondary"}`}
            onClick={() => setScaleType("logarithmic")}
          >
            Logarithmic Scale
          </button>
        </div>
      </div>

      <div style={{ height: "280px" }}>
        <Bar data={data} options={options} />
      </div>
    </div>
  );
}

export default BenchmarkChart;