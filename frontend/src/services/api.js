import axios from "axios";

const api = axios.create({
  baseURL: "http://127.0.0.1:8000"
});

api.interceptors.request.use((config) => {
  config.headers["X-API-Key"] = "quantumshield-secret-api-key";
  return config;
});

export default api;