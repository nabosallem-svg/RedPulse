import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL;
const api = axios.create({
  // Empty baseURL => same-origin requests (works on Vercel where the API
  // function is served from /api on the same domain). Set NEXT_PUBLIC_API_URL
  // (e.g. http://localhost:8000 in dev) to override.
  baseURL: API_BASE && API_BASE.trim().length > 0 ? API_BASE : "",
  headers: { "Content-Type": "application/json" },
  withCredentials: false,
});

// Attach JWT from localStorage on each request
api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("RedPulse_token");
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Global 401 handling: clear token and redirect to /login
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error?.response?.status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("RedPulse_token");
        localStorage.removeItem("RedPulse_user");
        const isAuthPage = window.location.pathname === "/login" || window.location.pathname === "/signup";
        if (!isAuthPage) {
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;

// Helpers
export function setAuthToken(token: string, user?: unknown) {
  if (typeof window !== "undefined") {
    localStorage.setItem("RedPulse_token", token);
    if (user) localStorage.setItem("RedPulse_user", JSON.stringify(user));
  }
}

export function clearAuth() {
  if (typeof window !== "undefined") {
    localStorage.removeItem("RedPulse_token");
    localStorage.removeItem("RedPulse_user");
  }
}

export function getAuthToken(): string | null {
  if (typeof window !== "undefined") return localStorage.getItem("RedPulse_token");
  return null;
}
