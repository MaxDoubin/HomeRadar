const API_ROOT = import.meta.env.VITE_API_ROOT || "";

export async function api(path, options = {}) {
  const response = await fetch(`${API_ROOT}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

export function dashboardSocket(onSnapshot) {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const root = import.meta.env.VITE_WS_ROOT || `${protocol}//${window.location.host}`;
  const socket = new WebSocket(`${root}/ws`);
  socket.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === "snapshot") onSnapshot(payload);
  };
  return socket;
}
