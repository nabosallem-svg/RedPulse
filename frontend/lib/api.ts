import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL;
const api = axios.create({
  baseURL: API_BASE && API_BASE.trim().length > 0 ? API_BASE : "",
  headers: { "Content-Type": "application/json" },
  withCredentials: false,
});

let isRefreshing = false;
let failedQueue: Array<{ resolve: (token: string) => void; reject: (err: unknown) => void }> = [];

function processQueue(error: unknown, token: string | null = null) {
  failedQueue.forEach((prom) => {
    if (error || !token) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
}

// Attach JWT from localStorage on each request
api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("rp_token");
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Global response handling: token refresh on 401, then redirect
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;

    // If 401 and not already retrying and not on auth page
    if (
      error?.response?.status === 401 &&
      !originalRequest._retry &&
      typeof window !== "undefined"
    ) {
      const isAuthPage =
        window.location.pathname === "/login" ||
        window.location.pathname === "/signup";

      if (isAuthPage) {
        return Promise.reject(error);
      }

      // Try refresh token
      const refreshToken = localStorage.getItem("rp_refresh");
      if (!refreshToken) {
        localStorage.removeItem("rp_token");
        localStorage.removeItem("rp_refresh");
        localStorage.removeItem("rp_user");
        window.location.href = "/login";
        return Promise.reject(error);
      }

      if (isRefreshing) {
        return new Promise<string>((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const res = await axios.post(
          `${API_BASE || ""}/api/v1/auth/refresh`,
          { refresh_token: refreshToken }
        );
        const { access_token } = res.data;
        localStorage.setItem("rp_token", access_token);
        processQueue(null, access_token);
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        localStorage.removeItem("rp_token");
        localStorage.removeItem("rp_refresh");
        localStorage.removeItem("rp_user");
        window.location.href = "/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;

// Auth helpers
export function setAuthToken(accessToken: string, refreshToken?: string, user?: unknown) {
  if (typeof window !== "undefined") {
    localStorage.setItem("rp_token", accessToken);
    if (refreshToken) localStorage.setItem("rp_refresh", refreshToken);
    if (user) localStorage.setItem("rp_user", JSON.stringify(user));
  }
}

export function clearAuth() {
  if (typeof window !== "undefined") {
    localStorage.removeItem("rp_token");
    localStorage.removeItem("rp_refresh");
    localStorage.removeItem("rp_user");
  }
}

export function getAuthToken(): string | null {
  if (typeof window !== "undefined") return localStorage.getItem("rp_token");
  return null;
}

export function getUser(): { email?: string; id?: string } | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem("rp_user");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
