import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// vi.hoisted() gives us mock fns that exist before vi.mock's factory (which is hoisted
// above imports) runs, so the factory can close over them - and the test bodies below can
// still reach the very same fn objects to configure/inspect them per test.
const mocks = vi.hoisted(() => ({
  api: vi.fn(),
  dashboardSocket: vi.fn(),
  setStoredToken: vi.fn(),
}));

vi.mock("./api", () => ({
  api: mocks.api,
  dashboardSocket: mocks.dashboardSocket,
  setStoredToken: mocks.setStoredToken,
}));

import App from "./App";

// ---- fixtures -------------------------------------------------------------

const deviceTrusted = {
  id: 1,
  hostname: "kitchen-echo",
  vendor: "Amazon",
  model: "Echo Dot",
  ip: "192.168.1.10",
  mac: "AA:BB:CC:DD:EE:01",
  device_type: "smart_speaker",
  is_authorized: 1,
  trust_score: 92,
  last_seen: new Date().toISOString(),
  fingerprint_confidence: 0.9,
};

const devicePending = {
  id: 2,
  hostname: "unknown-iot",
  vendor: "Shenzhen Foo",
  model: "Cam1",
  ip: "192.168.1.20",
  mac: "AA:BB:CC:DD:EE:02",
  device_type: "iot_camera",
  is_authorized: 0,
  trust_score: 40,
  last_seen: new Date().toISOString(),
  fingerprint_confidence: 0.5,
};

const alertOpen1 = {
  id: 101,
  title: "New device joined the network",
  description: "An unrecognized device connected.",
  severity: "warn",
  is_resolved: false,
  created_at: new Date().toISOString(),
};

const alertOpen2 = {
  id: 102,
  title: "Port scan detected",
  description: "Repeated connection attempts observed.",
  severity: "danger",
  is_resolved: false,
  created_at: new Date().toISOString(),
};

const trafficFixture = {
  queries: 120,
  blocked: 5,
  bytes_sent: 1000,
  bytes_received: 2000,
  timeline: [],
  top_domains: [{ domain: "example.com", count: 10 }],
};

const statusFixture = {
  security_score: 88,
  open_alert_count: 2,
  device_count: 2,
  blocklist_domains: 50,
};

const dashboardFixture = {
  status: statusFixture,
  devices: [deviceTrusted, devicePending],
  alerts: [alertOpen1, alertOpen2],
  traffic: trafficFixture,
};

const settingsFixture = {
  household_name: "Test Home",
  digest_email: "",
  dns_upstream: "1.1.1.1",
  notifications_enabled: false,
};

const healthFixture = {
  status: "healthy",
  database: "ok",
  disk: { free_percent: 80 },
  dns: { enabled: true },
  warnings: [],
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// Default mock implementation for api(), dispatching on path. Individual tests can
// override with mocks.api.mockImplementation(...) for scenario-specific behavior.
function defaultApiImpl(path, options = {}) {
  if (path === "/dashboard") return Promise.resolve(clone(dashboardFixture));
  if (path === "/setup" && options.method === "POST") return Promise.resolve({ complete: true });
  if (path === "/setup") return Promise.resolve({ complete: true });
  if (path === "/scan") return Promise.resolve({});
  if (/^\/alerts\/\d+$/.test(path)) return Promise.resolve({});
  if (/^\/devices\/\d+\/trust$/.test(path)) return Promise.resolve({ reasons: ["Known vendor", "Long connection history"] });
  if (/^\/devices\/\d+\/traffic/.test(path)) return Promise.resolve([]);
  if (/^\/devices\/\d+\/policy$/.test(path) && options.method === "PUT") return Promise.resolve(JSON.parse(options.body));
  if (/^\/devices\/\d+\/policy$/.test(path)) return Promise.resolve({ internet_enabled: true, block_start: null, block_end: null, blocked_domains: [] });
  if (/^\/devices\/\d+\/findings$/.test(path)) return Promise.resolve([]);
  if (/^\/devices\/(\d+)\/authorization$/.test(path)) {
    const id = Number(path.match(/^\/devices\/(\d+)\/authorization$/)[1]);
    const { state } = JSON.parse(options.body);
    const original = dashboardFixture.devices.find((d) => d.id === id) || {};
    return Promise.resolve({ ...clone(original), is_authorized: state });
  }
  if (path === "/settings") return Promise.resolve(clone(settingsFixture));
  if (path === "/health") return Promise.resolve(clone(healthFixture));
  if (path === "/backups") return Promise.resolve({ backups: [] });
  if (path === "/pair/start") return Promise.resolve({ code: "123456", expires_in: 600 });
  if (path === "/pair/regenerate") return Promise.resolve({ token: "new-token-xyz" });
  // The app has grown additional panels/endpoints since this suite was written
  // (blocklists status, etc.) that aren't under test here -- resolve them
  // harmlessly rather than rejecting, so unrelated screens don't blow up tests
  // that never asserted on those calls in the first place.
  return Promise.resolve({});
}

let snapshotCallback;
let fakeSocket;

beforeEach(() => {
  vi.clearAllMocks();
  snapshotCallback = null;
  fakeSocket = { close: vi.fn(), onclose: null, onerror: null };
  mocks.dashboardSocket.mockImplementation((cb) => {
    snapshotCallback = cb;
    return fakeSocket;
  });
  mocks.api.mockImplementation(defaultApiImpl);
  mocks.setStoredToken.mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function renderApp() {
  const utils = render(<App />);
  await screen.findByRole("heading", { name: /your network at a glance/i });
  return utils;
}

// ---- initial render / navigation ------------------------------------------

describe("App navigation", () => {
  it("renders Overview by default and switches pages via the sidebar", async () => {
    await renderApp();

    const nav = screen.getByRole("navigation");
    const user = userEvent.setup();

    await user.click(within(nav).getByRole("button", { name: /devices/i }));
    await screen.findByRole("button", { name: /^scan network$/i });
    expect(screen.queryByRole("heading", { name: /your network at a glance/i })).not.toBeInTheDocument();

    await user.click(within(nav).getByRole("button", { name: /traffic/i }));
    await screen.findByRole("heading", { name: /^traffic$/i });
    expect(screen.queryByRole("button", { name: /^scan network$/i })).not.toBeInTheDocument();

    await user.click(within(nav).getByRole("button", { name: /alerts/i }));
    await screen.findByText(alertOpen1.title);
    expect(screen.getByText(alertOpen2.title)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /resolve/i }).length).toBeGreaterThan(0);

    await user.click(within(nav).getByRole("button", { name: /settings/i }));
    await screen.findByRole("button", { name: /save settings/i });
    expect(screen.queryByText(alertOpen1.title)).not.toBeInTheDocument();
  });
});

// ---- devices search filter ---------------------------------------------

describe("Devices search filter", () => {
  it("filters the device list to matching rows only", async () => {
    const { container } = await renderApp();
    const user = userEvent.setup();
    await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: /devices/i }));
    await screen.findByRole("button", { name: /^scan network$/i });

    const panel = container.querySelector(".devices-panel.full");
    expect(within(panel).getByText("kitchen-echo")).toBeInTheDocument();
    expect(within(panel).getByText("unknown-iot")).toBeInTheDocument();

    const search = screen.getByPlaceholderText(/search name, ip, mac, vendor/i);
    await user.type(search, "kitchen");

    expect(within(panel).getByText("kitchen-echo")).toBeInTheDocument();
    expect(within(panel).queryByText("unknown-iot")).not.toBeInTheDocument();
  });
});

// ---- alert resolve action ------------------------------------------------

describe("Alerts resolve action", () => {
  it("PATCHes /alerts/{id} with {resolved:true} and reloads the dashboard", async () => {
    await renderApp();
    const user = userEvent.setup();
    await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: /alerts/i }));
    await screen.findByText(alertOpen1.title);

    const dashboardCallsBefore = mocks.api.mock.calls.filter((c) => c[0] === "/dashboard").length;

    const card = screen.getByText(alertOpen1.title).closest(".alert-card");
    await user.click(within(card).getByRole("button", { name: /resolve/i }));

    await waitFor(() => {
      const resolveCall = mocks.api.mock.calls.find((c) => c[0] === `/alerts/${alertOpen1.id}`);
      expect(resolveCall).toBeTruthy();
      expect(resolveCall[1].method).toBe("PATCH");
      expect(JSON.parse(resolveCall[1].body)).toEqual({ resolved: true });
    });

    await waitFor(() => {
      const dashboardCallsAfter = mocks.api.mock.calls.filter((c) => c[0] === "/dashboard").length;
      expect(dashboardCallsAfter).toBeGreaterThan(dashboardCallsBefore);
    });
  });
});

// ---- device authorize / block actions -----------------------------------

describe("Device drawer authorize/block/reset actions", () => {
  it("opens the drawer and PATCHes /devices/{id}/authorization with the right state", async () => {
    const { container } = await renderApp();
    const user = userEvent.setup();
    await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: /devices/i }));
    await screen.findByRole("button", { name: /^scan network$/i });

    const panel = container.querySelector(".devices-panel.full");
    await user.click(within(panel).getByText("unknown-iot"));

    await screen.findByRole("button", { name: /^authorize$/i });

    await user.click(screen.getByRole("button", { name: /^authorize$/i }));
    await waitFor(() => {
      const call = mocks.api.mock.calls.find((c) => c[0] === `/devices/${devicePending.id}/authorization`);
      expect(call).toBeTruthy();
      expect(call[1].method).toBe("PATCH");
      expect(JSON.parse(call[1].body)).toEqual({ state: 1 });
    });

    await user.click(screen.getByRole("button", { name: /^block$/i }));
    await waitFor(() => {
      const calls = mocks.api.mock.calls.filter((c) => c[0] === `/devices/${devicePending.id}/authorization`);
      expect(calls.some((c) => JSON.parse(c[1].body).state === 2)).toBe(true);
    });

    await user.click(screen.getByRole("button", { name: /^reset$/i }));
    await waitFor(() => {
      const calls = mocks.api.mock.calls.filter((c) => c[0] === `/devices/${devicePending.id}/authorization`);
      expect(calls.some((c) => JSON.parse(c[1].body).state === 0)).toBe(true);
    });
  });
});

// ---- SetupWizard gating --------------------------------------------------

describe("SetupWizard gating", () => {
  function apiImplWithIncompleteSetup(path, options = {}) {
    if (path === "/setup" && options.method !== "POST") return Promise.resolve({ complete: false });
    return defaultApiImpl(path, options);
  }

  it("shows the wizard overlay above the shell, gates Continue on household name, and completes via POST /setup", async () => {
    mocks.api.mockImplementation(apiImplWithIncompleteSetup);
    render(<App />);

    await screen.findByText(/turn this machine into your network lookout/i);
    // underlying shell/sidebar is still present underneath the overlay
    expect(screen.getByRole("navigation")).toBeInTheDocument();

    const user = userEvent.setup();
    const nameInput = screen.getByLabelText(/what should we call this household/i);

    await user.clear(nameInput);
    expect(screen.getByRole("button", { name: /continue/i })).toBeDisabled();

    await user.type(nameInput, "The Smiths");
    expect(screen.getByRole("button", { name: /continue/i })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: /continue/i }));
    await screen.findByText(/choose safe network defaults/i);

    await user.click(screen.getByRole("button", { name: /continue/i }));
    await screen.findByText(/start with visibility, then activate dns/i);

    await user.click(screen.getByRole("button", { name: /open home radar/i }));

    await waitFor(() => {
      const call = mocks.api.mock.calls.find((c) => c[0] === "/setup" && c[1]?.method === "POST");
      expect(call).toBeTruthy();
      const body = JSON.parse(call[1].body);
      expect(body.household_name).toBe("The Smiths");
      expect(body.dns_upstream).toBe("1.1.1.1");
    });

    await waitFor(() => {
      expect(screen.queryByText(/turn this machine into your network lookout/i)).not.toBeInTheDocument();
    });
    expect(screen.getByRole("navigation")).toBeInTheDocument();
  });
});

// ---- alert notification diffing -----------------------------------------

describe("Alert browser-notification diffing", () => {
  let notifications;

  beforeEach(() => {
    notifications = [];
    class FakeNotification {
      constructor(title, options) {
        notifications.push({ title, options });
      }
    }
    FakeNotification.permission = "granted";
    vi.stubGlobal("Notification", FakeNotification);
  });

  it("does not re-notify for already-seen alerts; only genuinely new ones trigger a Notification", async () => {
    // Use an initially-empty-alerts dashboard fixture to isolate this scenario from the
    // initial /dashboard load's own alerts (see note below on the real, verified behavior).
    mocks.api.mockImplementation((path, options = {}) => {
      if (path === "/dashboard") return Promise.resolve({ status: {}, devices: [], alerts: [], traffic: {} });
      return defaultApiImpl(path, options);
    });

    await renderApp();
    expect(typeof snapshotCallback).toBe("function");
    expect(notifications).toHaveLength(0);

    // NOTE ON REAL, VERIFIED BEHAVIOR: App.jsx's `alertsInitialized` ref is flipped to
    // `true` during the component's very first mount-time effect run, which executes
    // synchronously over the pristine, empty initial `data.alerts` - strictly before the
    // initial /dashboard load or any socket snapshot can deliver real data. As a result,
    // the very first *real* batch of alerts to arrive (whether from the initial dashboard
    // load or the first socket snapshot) is NOT silently absorbed as a baseline the way the
    // adjacent code comment might suggest - it already triggers notifications for every
    // alert it contains. We verified this with an isolated repro before writing this test.
    // What IS true, and what matters most for correctness, is de-duplication: an alert id
    // already seen does not get re-notified when it reappears in a later snapshot - only
    // genuinely new ids do. That is what this test asserts.
    act(() => {
      snapshotCallback({ type: "snapshot", alerts: [alertOpen1] });
    });
    await waitFor(() => expect(notifications).toHaveLength(1));
    expect(notifications[0].title).toContain(alertOpen1.title);

    act(() => {
      snapshotCallback({ type: "snapshot", alerts: [alertOpen1, alertOpen2] });
    });
    await waitFor(() => expect(notifications).toHaveLength(2));
    expect(notifications[1].title).toContain(alertOpen2.title);
    // the previously-seen alert was not re-notified
    expect(notifications.filter((n) => n.title.includes(alertOpen1.title))).toHaveLength(1);
  });
});

// ---- Settings pairing panel ------------------------------------------------

describe("Settings pairing panel", () => {
  it("generates a pairing code via POST /pair/start and displays it", async () => {
    await renderApp();
    const user = userEvent.setup();
    await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: /settings/i }));
    await screen.findByRole("button", { name: /save settings/i });

    await user.click(screen.getByRole("button", { name: /generate pairing code/i }));

    await waitFor(() => {
      const call = mocks.api.mock.calls.find((c) => c[0] === "/pair/start");
      expect(call).toBeTruthy();
      expect(call[1].method).toBe("POST");
    });

    expect(await screen.findByText("123456")).toBeInTheDocument();
  });

  it("regenerates the token via POST /pair/regenerate and stores the new token", async () => {
    await renderApp();
    const user = userEvent.setup();
    await user.click(within(screen.getByRole("navigation")).getByRole("button", { name: /settings/i }));
    await screen.findByRole("button", { name: /save settings/i });

    await user.click(screen.getByRole("button", { name: /regenerate token/i }));

    await waitFor(() => {
      const call = mocks.api.mock.calls.find((c) => c[0] === "/pair/regenerate");
      expect(call).toBeTruthy();
      expect(call[1].method).toBe("POST");
    });

    await waitFor(() => {
      expect(mocks.setStoredToken).toHaveBeenCalledWith("new-token-xyz");
    });
  });
});
