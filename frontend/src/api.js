const API_ROOT = import.meta.env.VITE_API_ROOT || "";
const TOKEN_KEY = "homeradar_token";

let inMemoryToken = null;
try {
  inMemoryToken = localStorage.getItem(TOKEN_KEY) || null;
} catch {
  inMemoryToken = null;
}

export function getStoredToken() {
  return inMemoryToken;
}

export function setStoredToken(token) {
  inMemoryToken = token || null;
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // ignore storage failures (private browsing, etc.)
  }
}

// Self-provision a token for this already-LAN-trusted dashboard, once, on module load.
const selfProvision = inMemoryToken
  ? Promise.resolve(inMemoryToken)
  : fetch(`${API_ROOT}/pair/local-token`)
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        if (payload?.token) setStoredToken(payload.token);
        return getStoredToken();
      })
      .catch(() => null);

export async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (inMemoryToken) headers["X-HomeRadar-Token"] = inMemoryToken;
  const response = await fetch(`${API_ROOT}${path}`, { headers, ...options });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

// Awaits the self-provisioned token (if one was still in flight) before resolving.
// Useful for callers that want to avoid racing a mutating call against provisioning.
export async function tokenReady() {
  return selfProvision;
}

export function dashboardSocket(onSnapshot) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const root = import.meta.env.VITE_WS_ROOT || `${protocol}//${window.location.host}`;
  const token = getStoredToken();
  const url = `${root}/ws${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  const socket = new WebSocket(url);
  socket.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === "snapshot") onSnapshot(payload);
  };
  return socket;
}
