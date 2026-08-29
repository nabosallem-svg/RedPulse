import axios from "axios";

const API_BASE = process.env.NEXT_PUBLIC_API_URL;
const api = axios.create({
  baseURL: API_BASE && API_BASE.trim().length > 0 ? API_BASE : "",
  headers: { "Content-Type": "application/json" },
  withCredentials: true, // critical: sends httpOnly Secure cookies (access_token/refresh_token) on every request
});

let isRefreshing = false;
let failedQueue: Array<{ resolve: () => void; reject: (err: unknown) => void }> = [];

function processQueue(error: unknown) {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve();
    }
  });
  failedQueue = [];
}

// No localStorage read — auth is entirely httpOnly cookies (defense-in-depth against XSS)
// The browser automatically sends cookies due to withCredentials:true; we never read tokens in JS.
api.interceptors.request.use((config) => {
  // No Authorization header from localStorage — rely solely on cookies
  return config;
});

// Global response handling: token refresh via httpOnly cookie, then retry
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;

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

      if (isRefreshing) {
        return new Promise<void>((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => {
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Refresh via httpOnly cookie — no body needed, cookie is sent automatically
        await axios.post(
          `${API_BASE || ""}/api/v1/auth/refresh`,
          {},
          { withCredentials: true }
        );
        processQueue(null);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
        // On refresh failure, redirect to login (cookies will be cleared by backend logout)
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

// Auth helpers — no localStorage for tokens (httpOnly cookies only)
// These are kept for UI state (e.g., post-login redirect) but never store tokens.
export function setAuthToken(_accessToken?: string, _refreshToken?: string, _user?: unknown) {
  // Intentionally no localStorage write for tokens — cookies are set by backend via Set-Cookie
  // Keep user in memory only if needed; not persisted to localStorage to avoid XSS replay
  if (typeof window !== "undefined" && _user) {
    try {
      sessionStorage.setItem("rp_user", JSON.stringify(_user));
    } catch {}
  }
}

export function clearAuth() {
  if (typeof window !== "undefined") {
    try {
      sessionStorage.removeItem("rp_user");
    } catch {}
  }
  // Also call backend logout to clear httpOnly cookies
  if (typeof window !== "undefined") {
    axios.post(`${API_BASE || ""}/api/v1/auth/logout`, {}, { withCredentials: true }).catch(() => {});
  }
}

export function getAuthToken(): string | null {
  // Tokens are httpOnly — not readable via JS by design
  return null;
}

export function getUser(): { email?: string; id?: string } | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem("rp_user");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
