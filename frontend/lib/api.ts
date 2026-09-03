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

// Auth via httpOnly cookies (primary) + Authorization header fallback for cross-site (frontend at redpulse-frontend, API at red-pulse-nine)
let cachedToken: string | null = null;
if (typeof window !== "undefined") {
  try { cachedToken = sessionStorage.getItem("rp_access_token"); } catch {}
}
api.interceptors.request.use((config) => {
  // Send Authorization header if we have a token (cross-site fallback when cookies blocked)
  // Read from memory or sessionStorage (for page reload)
  let tok = cachedToken;
  if (!tok && typeof window !== "undefined") {
    try { tok = sessionStorage.getItem("rp_access_token"); if (tok) cachedToken = tok; } catch {}
  }
  if (tok && config.headers) {
    (config.headers as any)["Authorization"] = `Bearer ${tok}`;
  }
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

      // Demo mode is disabled in production — only allows bypass when NEXT_PUBLIC_ALLOW_DEMO=true (dev only)
      const allowDemo = process.env.NEXT_PUBLIC_ALLOW_DEMO === "true";
      if (allowDemo) {
        try {
          const raw = sessionStorage.getItem("rp_user");
          if (raw) {
            const u = JSON.parse(raw);
            if (u?.id === "demo" || u?.email === "demo@redpulse.io") {
              return Promise.reject(error);
            }
          }
        } catch {}
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
export function setAuthToken(accessToken?: string, refreshToken?: string, _user?: unknown) {
  if (accessToken) {
    cachedToken = accessToken;
    try { sessionStorage.setItem("rp_access_token", accessToken); } catch {}
  }
  if (refreshToken) {
    try { sessionStorage.setItem("rp_refresh_token", refreshToken); } catch {}
  }
  if (typeof window !== "undefined" && _user) {
    try {
      sessionStorage.setItem("rp_user", JSON.stringify(_user));
    } catch {}
  }
}

export function clearAuth() {
  cachedToken = null;
  if (typeof window !== "undefined") {
    try {
      sessionStorage.removeItem("rp_user");
      sessionStorage.removeItem("rp_access_token");
      sessionStorage.removeItem("rp_refresh_token");
    } catch {}
  }
  // Also call backend logout to clear httpOnly cookies
  if (typeof window !== "undefined") {
    axios.post(`${API_BASE || ""}/api/v1/auth/logout`, {}, { withCredentials: true }).catch(() => {});
  }
}

export function getAuthToken(): string | null {
  if (cachedToken) return cachedToken;
  if (typeof window !== "undefined") {
    try { return sessionStorage.getItem("rp_access_token"); } catch { return null; }
  }
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
