import React from "react";
import { Doughnut } from "react-chartjs-2";
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

function PQCDistribution({ data = [] }) {
  const chartData = {
    labels: data.map(d => d.algorithm),
    datasets: [
      {
        data: data.map(d => d.count),
        backgroundColor: [
          "rgba(0, 229, 255, 0.85)",  /* Kyber512 - Neon Cyan */
          "rgba(0, 230, 118, 0.85)",  /* Kyber768 - Neon Green */
          "rgba(213, 0, 249, 0.85)",   /* Dilithium2 - Neon Magenta */
          "rgba(255, 23, 68, 0.85)",   /* Falcon512 - Neon Red */
          "rgba(255, 234, 0, 0.85)"    /* SPHINCS+ - Neon Yellow */
        ],
        borderColor: "#080d19",
        borderWidth: 2.5,
        hoverOffset: 12
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "70%", /* Sleek donut look */
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: "#cbd5e1",
          font: {
            family: "Outfit",
            size: 12
          },
          padding: 12
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
    <div style={{ height: "220px" }}>
      <Doughnut data={chartData} options={options} />
    </div>
  );
}

export default PQCDistribution;
