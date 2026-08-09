import React from "react";
import { Line } from "react-chartjs-2";
import {
  Chart,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
} from "chart.js";

Chart.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

function ThreatTimeline({ data }) {
  // Format dates/times nicely for display
  const formatTime = (timeStr) => {
    try {
      const dt = new Date(timeStr);
      return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timeStr;
    }
  };

  const chartData = {
    labels: data.map(item => formatTime(item.time)),
    datasets: [
      {
        label: "Security Threats / Min",
        data: data.map(item => item.count),
        fill: true,
        backgroundColor: "rgba(255, 23, 68, 0.15)", /* Translucent neon red fill */
        borderColor: "#ff1744",
        borderWidth: 2,
        tension: 0.4, /* Smooth cubic interpolation curves */
        pointBackgroundColor: "#ff1744",
        pointBorderColor: "#080d19",
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false /* Hide legend to keep it clean */
      },
      tooltip: {
        backgroundColor: "#0f172a",
        titleFont: { family: "Outfit" },
        bodyFont: { family: "Outfit" },
        borderColor: "rgba(255, 255, 255, 0.1)",
        borderWidth: 1
      }
    },
    scales: {
      x: {
        grid: {
          color: "rgba(255, 255, 255, 0.05)"
        },
        ticks: {
          color: "#94a3b8",
          font: { family: "Outfit", size: 10 }
        }
      },
      y: {
        grid: {
          color: "rgba(255, 255, 255, 0.05)"
        },
        ticks: {
          color: "#94a3b8",
          font: { family: "Outfit" }
        }
      }
    }
  };

  return (
    <div style={{ height: "250px" }}>
      <Line data={chartData} options={options} />
    </div>
  );
}

export default ThreatTimeline;