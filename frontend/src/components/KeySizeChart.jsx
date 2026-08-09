import React from "react";
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

Chart.register(
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  BarElement,
  Tooltip,
  Legend
);

function KeySizeChart() {
  const algorithms = ["ML-KEM-512 (Kyber512)", "ML-KEM-768 (Kyber768)", "ML-DSA-44 (Dilithium2)", "FN-DSA-512 (Falcon512)", "SPHINCS+"];
  
  const data = {
    labels: algorithms,
    datasets: [
      {
        label: "Public Key Size (Bytes)",
        data: [800, 1184, 1312, 897, 32],
        backgroundColor: "rgba(0, 229, 255, 0.4)",
        borderColor: "#00e5ff",
        borderWidth: 1.5,
        borderRadius: 4
      },
      {
        label: "Ciphertext / Signature Payload (Bytes)",
        data: [768, 1088, 2420, 666, 17088],
        backgroundColor: "rgba(213, 0, 249, 0.4)",
        borderColor: "#d500f9",
        borderWidth: 1.5,
        borderRadius: 4
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
          font: { family: "Outfit" }
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
            return context.dataset.label + ": " + context.parsed.y.toLocaleString() + " Bytes";
          }
        }
      }
    },
    scales: {
      x: {
        stacked: true, /* Stacked bar chart to show total overhead */
        grid: {
          color: "rgba(255, 255, 255, 0.04)"
        },
        ticks: {
          color: "#94a3b8",
          font: { family: "Outfit", size: 12, weight: "bold" }
        }
      },
      y: {
        type: "logarithmic", /* Log scale because SPHINCS+ signature size is 17KB vs Kyber's 700B */
        min: 10,
        stacked: true,
        grid: {
          color: "rgba(255, 255, 255, 0.04)"
        },
        ticks: {
          color: "#94a3b8",
          font: { family: "Outfit" },
          callback: function(value) {
            return value + " B";
          }
        }
      }
    }
  };

  return (
    <div style={{ height: "260px" }}>
      <Bar data={data} options={options} />
    </div>
  );
}

export default KeySizeChart;
