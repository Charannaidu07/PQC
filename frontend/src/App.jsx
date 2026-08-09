import {
  BrowserRouter,
  Routes,
  Route
} from "react-router-dom";

import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";

import Dashboard from "./pages/Dashboard";
import Devices from "./pages/Devices";
import ThreatCenter from "./pages/ThreatCenter";
import Benchmarks from "./pages/Benchmarks";
import Monitoring from "./pages/Monitoring";

function App() {

  return (

    <BrowserRouter>

      <div className="d-flex">

        <Sidebar />

        <div
          className="flex-grow-1"
        >

          <Navbar />

          <div className="p-4">

            <Routes>

              <Route
                path="/"
                element={
                  <Dashboard />
                }
              />

              <Route
                path="/devices"
                element={
                  <Devices />
                }
              />

              <Route
                path="/threats"
                element={
                  <ThreatCenter />
                }
              />

              <Route
                path="/benchmarks"
                element={
                  <Benchmarks />
                }
              />

              <Route
                path="/monitoring"
                element={
                  <Monitoring />
                }
              />

            </Routes>

          </div>

        </div>

      </div>

    </BrowserRouter>
  );
}

export default App;