import React from "react";
import { Pie } from "react-chartjs-2";
import {
  Chart,
  ArcElement,
  Tooltip,
  Legend
} from "chart.js";

Chart.register(
  ArcElement,
  Tooltip,
  Legend
);

function ThreatChart({ threats }) {
  const high = threats.filter(t => t.severity === "HIGH").length;
  const medium = threats.filter(t => t.severity === "MEDIUM").length;
  const low = threats.filter(t => t.severity === "LOW").length;

  const data = {
    labels: ["Critical / High", "Warning / Medium", "Informational / Low"],
    datasets: [
      {
        data: [high, medium, low],
        backgroundColor: [
          "rgba(255, 23, 68, 0.8)",  /* Neon pink/red */
          "rgba(255, 145, 0, 0.8)",  /* Neon warning orange */
          "rgba(0, 229, 255, 0.8)"   /* Neon cyan */
        ],
        borderColor: [
          "#ff1744",
          "#ff9100",
          "#00e5ff"
        ],
        borderWidth: 1.5,
        hoverOffset: 15
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: "#cbd5e1",
          font: {
            family: "Outfit",
            size: 12
          },
          padding: 15
        }
      },
      tooltip: {
        backgroundColor: "#0f172a",
        titleFont: { family: "Outfit" },
        bodyFont: { family: "Outfit" },
        borderColor: "rgba(255, 255, 255, 0.1)",
        borderWidth: 1
      }
    }
  };

  return (
    <div style={{ height: "250px" }}>
      <Pie data={data} options={options} />
    </div>
  );
}

export default ThreatChart;