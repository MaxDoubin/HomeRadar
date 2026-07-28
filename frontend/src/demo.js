export const mockDevices = [
  { id: "d1", device_type: "phone", is_authorized: 1, trust_score: 98, hostname: "Max's iPhone", vendor: "Apple", ip: "192.168.1.12", mac: "00:11:22:33:44:55", last_seen: new Date().toISOString(), fingerprint_confidence: 0.99 },
  { id: "d2", device_type: "computer", is_authorized: 1, trust_score: 95, hostname: "MacBook Pro", vendor: "Apple", ip: "192.168.1.15", mac: "aa:bb:cc:dd:ee:ff", last_seen: new Date().toISOString(), fingerprint_confidence: 0.95 },
  { id: "d3", device_type: "smart_tv", is_authorized: 1, trust_score: 75, hostname: "Living Room TV", vendor: "Samsung", ip: "192.168.1.20", mac: "11:22:33:44:55:66", last_seen: new Date(Date.now() - 3600000).toISOString(), fingerprint_confidence: 0.85 },
  { id: "d4", device_type: "iot_camera", is_authorized: 0, trust_score: 45, hostname: "Unknown Camera", vendor: "Generic", ip: "192.168.1.35", mac: "66:77:88:99:aa:bb", last_seen: new Date().toISOString(), fingerprint_confidence: 0.60 },
];

export const mockAlerts = [
  { id: "a1", severity: "danger", title: "Suspicious Traffic Blocked", description: "Camera attempted to contact a known malware domain.", created_at: new Date(Date.now() - 7200000).toISOString() },
  { id: "a2", severity: "warn", title: "New Device Discovered", description: "An unknown IoT Camera joined the network.", created_at: new Date(Date.now() - 86400000).toISOString() },
];

export const mockTraffic = {
  queries: 12453,
  blocked: 142,
  bytes_sent: 10485760,
  bytes_received: 52428800,
  timeline: [
    { queries: 400, blocked: 5 },
    { queries: 500, blocked: 10 },
    { queries: 450, blocked: 2 },
    { queries: 600, blocked: 15 },
    { queries: 550, blocked: 8 },
    { queries: 700, blocked: 12 },
    { queries: 800, blocked: 20 },
    { queries: 650, blocked: 5 },
    { queries: 900, blocked: 25 },
    { queries: 850, blocked: 18 },
    { queries: 750, blocked: 10 },
    { queries: 950, blocked: 12 },
  ],
  top_domains: [
    { domain: "google.com", count: 4500 },
    { domain: "apple.com", count: 3200 },
    { domain: "netflix.com", count: 2100 },
    { domain: "telemetry.samsung.com", count: 850 },
    { domain: "malware-c2.bad", count: 142 },
  ]
};

export const mockStatus = {
  security_score: 82,
  open_alert_count: mockAlerts.length,
  device_count: mockDevices.length,
  blocklist_domains: 154231
};

export async function handleDemoApi(path, options = {}) {
  const method = options.method || "GET";

  await new Promise(r => setTimeout(r, 400)); // simulate network delay

  if (path === "/dashboard") {
    return { status: mockStatus, devices: mockDevices, alerts: mockAlerts, traffic: mockTraffic };
  }

  if (path === "/setup") {
    if (method === "GET") return { complete: true };
    if (method === "POST") return {};
  }

  if (path.startsWith("/devices/")) {
    const id = path.split("/")[2];
    const device = mockDevices.find(d => d.id === id) || mockDevices[0];

    if (path.endsWith("/trust")) {
      return { reasons: ["Valid DHCP request", "Known manufacturer", "No suspicious traffic patterns"] };
    }
    if (path.endsWith("/traffic?limit=30")) {
      return [
        { id: "t1", domain: "apple.com", was_blocked: false },
        { id: "t2", domain: "icloud.com", was_blocked: false },
        { id: "t3", domain: "tracker.bad", was_blocked: true },
      ];
    }
    if (path.endsWith("/policy")) {
      if (method === "GET") return { internet_enabled: true, block_start: null, block_end: null, blocked_domains: [] };
      if (method === "PUT") return JSON.parse(options.body);
    }
    if (path.endsWith("/findings")) {
      if (device.device_type === "iot_camera") {
        return [{ id: "f1", severity: "critical", title: "Default Password", description: "Device appears to be using factory credentials.", recommendation: "Log in and change the administrator password immediately." }];
      }
      return [];
    }
    if (path.endsWith("/authorization") && method === "PATCH") {
      const { state } = JSON.parse(options.body);
      device.is_authorized = state;
      return device;
    }
  }

  if (path.startsWith("/alerts/") && method === "PATCH") {
    const id = path.split("/")[2];
    const index = mockAlerts.findIndex(a => a.id === id);
    if (index > -1) mockAlerts.splice(index, 1);
    mockStatus.open_alert_count = mockAlerts.length;
    return {};
  }

  if (path === "/scan" && method === "POST") {
    return {};
  }

  if (path === "/settings") {
    if (method === "GET") return { household_name: "Demo Home", digest_email: "demo@example.com", dns_upstream: "1.1.1.1", notifications_enabled: false };
    if (method === "PATCH") return JSON.parse(options.body);
  }

  if (path === "/health") {
    return { status: "healthy", database: "Connected", disk: { free_percent: 84 }, dns: { enabled: true }, warnings: [] };
  }

  if (path === "/backups") {
    if (method === "GET") return { backups: [{ name: "backup-2023-01-01.tar.gz" }] };
    if (method === "POST") return {};
  }

  if (path === "/pair/start" && method === "POST") {
    return { code: "123456", expires_in: 300 };
  }

  if (path === "/pair/regenerate" && method === "POST") {
    return { token: "demo-token-" + Date.now() };
  }

  if (path === "/pair/local-token") {
    return { token: "demo-token" };
  }

  throw new Error(`Demo API not implemented for ${method} ${path}`);
}

export function demoDashboardSocket(onSnapshot) {
  let interval;
  const socket = {
    close: () => clearInterval(interval),
    onmessage: null,
    onclose: null,
    onerror: null,
  };

  // Simulate connected by calling onmessage with a heartbeat/snapshot
  setTimeout(() => {
    interval = setInterval(() => {
      const payload = {
        type: "snapshot",
        traffic: { ...mockTraffic, queries: mockTraffic.queries + Math.floor(Math.random() * 5) }
      };

      if (socket.onmessage) {
        socket.onmessage({ data: JSON.stringify(payload) });
      }

      // Some original socket callers pass an onSnapshot callback directly.
      // Call it so live updates work.
      if (typeof onSnapshot === 'function') {
        onSnapshot(payload);
      }
    }, 5000);
  }, 100);

  return socket;
}
