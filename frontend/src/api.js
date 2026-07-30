import { handleDemoApi, demoDashboardSocket } from "./demo.js";

const API_ROOT = import.meta.env.VITE_API_ROOT || "";
const TOKEN_KEY = "homeradar_token";

let inMemoryToken = null;
let authPromise = null;
let pairingOverlay = null;

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
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
      document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; Path=/; SameSite=Strict`;
    } else {
      localStorage.removeItem(TOKEN_KEY);
      document.cookie = `${TOKEN_KEY}=; Path=/; Max-Age=0; SameSite=Strict`;
    }
  } catch {
    // Storage can be unavailable in private browsing or restricted webviews.
  }
}

function pairingScreen() {
  if (pairingOverlay) return pairingOverlay.promise;

  let resolvePairing;
  const promise = new Promise((resolve) => {
    resolvePairing = resolve;
  });

  const style = document.createElement("style");
  style.dataset.homeradarPairing = "true";
  style.textContent = `
    .hr-pairing-gate{position:fixed;inset:0;z-index:99999;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 15%,rgba(57,230,162,.12),transparent 34%),#020806;color:#edf9f4;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}
    .hr-pairing-card{width:min(440px,100%);padding:34px;border:1px solid rgba(95,255,190,.2);border-radius:24px;background:linear-gradient(180deg,rgba(12,31,25,.97),rgba(5,17,13,.99));box-shadow:0 32px 90px rgba(0,0,0,.55)}
    .hr-pairing-radar{width:64px;height:64px;margin-bottom:22px;border:1px solid rgba(57,230,162,.45);border-radius:50%;background:radial-gradient(circle,#39e6a2 0 3px,transparent 4px),repeating-radial-gradient(circle,transparent 0 12px,rgba(57,230,162,.16) 13px 14px);box-shadow:0 0 35px rgba(57,230,162,.18)}
    .hr-pairing-card small{display:block;margin-bottom:8px;color:#39e6a2;font-size:11px;font-weight:800;letter-spacing:.18em}
    .hr-pairing-card h1{margin:0 0 10px;font-size:30px;letter-spacing:-.04em}
    .hr-pairing-card p{margin:0 0 24px;color:#92a99f;line-height:1.6}
    .hr-pairing-card form{display:grid;gap:12px}
    .hr-pairing-card input{width:100%;box-sizing:border-box;padding:17px;border:1px solid rgba(255,255,255,.12);border-radius:14px;background:#06110d;color:#fff;font:700 24px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.28em;text-align:center;outline:none}
    .hr-pairing-card input:focus{border-color:#39e6a2;box-shadow:0 0 0 4px rgba(57,230,162,.1)}
    .hr-pairing-card button{padding:15px;border:0;border-radius:14px;background:#39e6a2;color:#042116;font-weight:900;cursor:pointer}
    .hr-pairing-card button:disabled{opacity:.6;cursor:wait}
    .hr-pairing-error{min-height:20px;margin:2px 0 0!important;color:#ff8c8c!important;font-size:13px}
    .hr-pairing-help{margin-top:20px!important;padding-top:18px;border-top:1px solid rgba(255,255,255,.08);font-size:12px}
  `;

  const gate = document.createElement("div");
  gate.className = "hr-pairing-gate";
  gate.innerHTML = `
    <section class="hr-pairing-card" role="dialog" aria-modal="true" aria-labelledby="hr-pairing-title">
      <div class="hr-pairing-radar" aria-hidden="true"></div>
      <small>SECURE DEVICE PAIRING</small>
      <h1 id="hr-pairing-title">Connect to Home Radar</h1>
      <p>Enter the six-digit code shown on the Home Radar appliance or generated from Settings on an already paired device.</p>
      <form>
        <input inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" aria-label="Six-digit pairing code" placeholder="000000" required />
        <button type="submit">Pair this device</button>
        <p class="hr-pairing-error" role="alert"></p>
      </form>
      <p class="hr-pairing-help">The code expires after ten minutes and can be used only once. Home Radar never sends your network history to a cloud account.</p>
    </section>`;

  document.head.appendChild(style);
  document.body.appendChild(gate);
  const form = gate.querySelector("form");
  const input = gate.querySelector("input");
  const button = gate.querySelector("button");
  const error = gate.querySelector(".hr-pairing-error");

  const cleanup = () => {
    gate.remove();
    style.remove();
    pairingOverlay = null;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = input.value.replace(/\D/g, "").slice(0, 6);
    if (code.length !== 6) {
      error.textContent = "Enter all six digits.";
      return;
    }
    button.disabled = true;
    error.textContent = "";
    try {
      const response = await fetch(`${API_ROOT}/pair/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
        cache: "no-store",
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.token) {
        throw new Error(payload.detail || "That code is invalid or expired.");
      }
      setStoredToken(payload.token);
      cleanup();
      resolvePairing(payload.token);
    } catch (err) {
      error.textContent = err.message || "Pairing failed. Try again.";
      button.disabled = false;
      input.select();
    }
  });

  input.addEventListener("input", () => {
    input.value = input.value.replace(/\D/g, "").slice(0, 6);
  });
  queueMicrotask(() => input.focus());

  pairingOverlay = { promise, cleanup };
  return promise;
}

async function bootstrapToken() {
  if (inMemoryToken) return inMemoryToken;
  try {
    const response = await fetch(`${API_ROOT}/pair/local-token`, { cache: "no-store" });
    if (response.ok) {
      const payload = await response.json();
      if (payload?.token) {
        setStoredToken(payload.token);
        return payload.token;
      }
    }
  } catch {
    // A remote browser cannot use the local bootstrap endpoint. Show pairing UI.
  }
  return pairingScreen();
}

function ensureToken() {
  if (import.meta.env.VITE_DEMO_MODE === "true") return Promise.resolve("demo");
  if (!authPromise) authPromise = bootstrapToken();
  return authPromise;
}

export async function tokenReady() {
  return ensureToken();
}

export async function api(path, options = {}) {
  if (import.meta.env.VITE_DEMO_MODE === "true") {
    return handleDemoApi(path, options);
  }

  await ensureToken();
  const request = async () => {
    const headers = { "Content-Type": "application/json", ...options.headers };
    if (inMemoryToken) headers["X-HomeRadar-Token"] = inMemoryToken;
    return fetch(`${API_ROOT}${path}`, { ...options, headers, cache: "no-store" });
  };

  let response = await request();
  if (response.status === 401) {
    setStoredToken(null);
    authPromise = pairingScreen();
    await authPromise;
    response = await request();
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const error = new Error(payload.detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

export function dashboardSocket(onSnapshot) {
  if (import.meta.env.VITE_DEMO_MODE === "true") {
    return demoDashboardSocket(onSnapshot);
  }

  const wrapper = {
    socket: null,
    closed: false,
    onclose: null,
    onerror: null,
    close() {
      this.closed = true;
      this.socket?.close();
    },
  };

  ensureToken().then(() => {
    if (wrapper.closed) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const root = import.meta.env.VITE_WS_ROOT || `${protocol}//${window.location.host}`;
    // Browser WebSocket APIs cannot set custom headers. Authentication is sent
    // through the strict same-site cookie, keeping the token out of URLs/logs.
    const socket = new WebSocket(`${root}/ws`);
    wrapper.socket = socket;
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === "snapshot") onSnapshot(payload);
    };
    socket.onclose = (event) => wrapper.onclose?.(event);
    socket.onerror = (event) => wrapper.onerror?.(event);
  }).catch((error) => wrapper.onerror?.(error));

  return wrapper;
}
