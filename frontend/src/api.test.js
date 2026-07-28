import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TOKEN_KEY = "homeradar_token";

vi.hoisted(() => {
  try {
    globalThis.localStorage.setItem("homeradar_token", "seed-token-existing");
  } catch {
    // jsdom storage can be unavailable in unusual environments.
  }
});

vi.mock("./demo", () => ({
  handleDemoApi: vi.fn(),
  demoDashboardSocket: vi.fn(),
}));

import { api, dashboardSocket, getStoredToken, setStoredToken } from "./api";

function clearPairingUi() {
  document.querySelector(".hr-pairing-gate")?.remove();
  document.querySelector("style[data-homeradar-pairing]")?.remove();
}

describe("token storage", () => {
  beforeEach(() => {
    setStoredToken(null);
  });

  it("round-trips a token through localStorage and a same-site cookie", () => {
    setStoredToken("abc123");
    expect(localStorage.getItem(TOKEN_KEY)).toBe("abc123");
    expect(getStoredToken()).toBe("abc123");
    expect(document.cookie).toContain("homeradar_token=abc123");
  });

  it("clears browser token state", () => {
    setStoredToken("abc123");
    setStoredToken(null);
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(getStoredToken()).toBeNull();
  });
});

describe("api", () => {
  beforeEach(() => {
    setStoredToken("api-token");
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends the pairing token and JSON content type", async () => {
    fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({ hello: "world" }) });
    const result = await api("/dashboard");
    const [url, options] = fetch.mock.calls[0];
    expect(url).toBe("/dashboard");
    expect(options.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-HomeRadar-Token": "api-token",
    });
    expect(options.cache).toBe("no-store");
    expect(result).toEqual({ hello: "world" });
  });

  it("preserves method and body options", async () => {
    fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    const body = JSON.stringify({ resolved: true });
    await api("/alerts/5", { method: "PATCH", body });
    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe("PATCH");
    expect(options.body).toBe(body);
  });

  it("uses the API detail message for errors", async () => {
    fetch.mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: "bad request" }),
    });
    await expect(api("/foo")).rejects.toThrow("bad request");
  });

  it("returns null for a successful empty response", async () => {
    fetch.mockResolvedValue({ ok: true, status: 204, json: vi.fn() });
    await expect(api("/empty")).resolves.toBeNull();
  });
});

describe("secure bootstrap and pairing", () => {
  beforeEach(() => {
    localStorage.clear();
    document.cookie = `${TOKEN_KEY}=; Path=/; Max-Age=0`;
    clearPairingUi();
    vi.resetModules();
  });

  afterEach(() => {
    clearPairingUi();
    vi.unstubAllGlobals();
  });

  it("uses the appliance-only local bootstrap endpoint when available", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url) => {
      expect(String(url)).toContain("/pair/local-token");
      return { ok: true, status: 200, json: async () => ({ token: "local-token" }) };
    }));
    const freshApi = await import("./api");
    await expect(freshApi.tokenReady()).resolves.toBe("local-token");
    expect(freshApi.getStoredToken()).toBe("local-token");
  });

  it("shows a pairing screen and exchanges a six-digit code for a token", async () => {
    vi.stubGlobal("fetch", vi.fn(async (url, options = {}) => {
      if (String(url).includes("/pair/local-token")) {
        return { ok: false, status: 403, json: async () => ({ detail: "local only" }) };
      }
      if (String(url).includes("/pair/claim")) {
        expect(JSON.parse(options.body)).toEqual({ code: "123456" });
        return { ok: true, status: 200, json: async () => ({ token: "paired-token" }) };
      }
      throw new Error(`Unexpected URL: ${url}`);
    }));

    const freshApi = await import("./api");
    const ready = freshApi.tokenReady();
    await new Promise((resolve) => setTimeout(resolve, 0));

    const gate = document.querySelector(".hr-pairing-gate");
    expect(gate).not.toBeNull();
    const input = gate.querySelector("input");
    input.value = "123456";
    gate.querySelector("form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await expect(ready).resolves.toBe("paired-token");
    expect(freshApi.getStoredToken()).toBe("paired-token");
    expect(document.querySelector(".hr-pairing-gate")).toBeNull();
  });

  it("resolves immediately from a token already stored in a fresh module", async () => {
    localStorage.setItem(TOKEN_KEY, "fresh-seed-token");
    vi.stubGlobal("fetch", vi.fn());
    const freshApi = await import("./api");
    await expect(freshApi.tokenReady()).resolves.toBe("fresh-seed-token");
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("dashboardSocket", () => {
  class FakeWebSocket {
    constructor(url) {
      this.url = url;
      FakeWebSocket.instances.push(this);
    }
    close() {}
  }
  FakeWebSocket.instances = [];

  beforeEach(() => {
    FakeWebSocket.instances = [];
    setStoredToken("socket token/special");
    vi.stubGlobal("WebSocket", FakeWebSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses the same-origin cookie and keeps the token out of the WebSocket URL", async () => {
    const onSnapshot = vi.fn();
    const wrapper = dashboardSocket(onSnapshot);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const socket = FakeWebSocket.instances[0];
    expect(socket.url).toMatch(/\/ws$/);
    expect(socket.url).not.toContain("token=");

    const payload = { type: "snapshot", devices: [], alerts: [] };
    socket.onmessage({ data: JSON.stringify(payload) });
    expect(onSnapshot).toHaveBeenCalledWith(payload);
    wrapper.close();
  });

  it("ignores non-snapshot messages", async () => {
    const onSnapshot = vi.fn();
    dashboardSocket(onSnapshot);
    await new Promise((resolve) => setTimeout(resolve, 0));
    FakeWebSocket.instances[0].onmessage({ data: JSON.stringify({ type: "ping" }) });
    expect(onSnapshot).not.toHaveBeenCalled();
  });
});

describe("demo mode", () => {
  let original;
  beforeEach(() => {
    original = import.meta.env.VITE_DEMO_MODE;
    import.meta.env.VITE_DEMO_MODE = "true";
  });
  afterEach(() => {
    import.meta.env.VITE_DEMO_MODE = original;
    vi.clearAllMocks();
  });

  it("delegates API and socket behavior to the demo provider", async () => {
    const { handleDemoApi, demoDashboardSocket } = await import("./demo");
    handleDemoApi.mockResolvedValue({ demo: true });
    demoDashboardSocket.mockReturnValue({ close: vi.fn() });

    await expect(api("/dashboard")).resolves.toEqual({ demo: true });
    const socket = dashboardSocket(vi.fn());
    expect(demoDashboardSocket).toHaveBeenCalled();
    expect(socket).toBeTruthy();
  });
});
