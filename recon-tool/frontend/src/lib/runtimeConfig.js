function trimTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function browserApiBase() {
  if (typeof window === "undefined") return "http://localhost:8000";
  return trimTrailingSlash(window.location.origin);
}

function browserWsBase() {
  if (typeof window === "undefined") return "ws://localhost:8000";
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return trimTrailingSlash(`${protocol}//${window.location.host}`);
}

export const API_BASE = trimTrailingSlash(process.env.REACT_APP_API_URL) || browserApiBase();
export const WS_BASE = trimTrailingSlash(process.env.REACT_APP_WS_URL) || browserWsBase();
export const ADMIN_TOKEN = String(process.env.REACT_APP_ADMIN_PASSWORD || "").trim();
