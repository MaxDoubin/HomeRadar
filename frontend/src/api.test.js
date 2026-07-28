import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const TOKEN_KEY = "homeradar_token";
const SEED_TOKEN = "seed-token-existing";

// vi.hoisted() runs before any of this file's static imports are evaluated, so we can
// seed localStorage with a token before "./api" is imported below. With a token already
// present, api.js's module-level self-provisioning `fetch(".../pair/local-token")` call is
// skipped entirely (see the gotcha in api.js), which keeps the rest of this file's tests
// (that don't care about self-provisioning) from ever making a real network call.
vi.hoisted(() => {
  try {
    globalThis.localStorage.setItem("homeradar_token", "seed-token-existing");
  } catch {
    // ignore - defensive fetch stubbing below covers this case too
  }
});

import { api, dashboardSocket, getStoredToken, setStoredToken, tokenReady } from "./api";

describe("getStoredToken / setStoredToken", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("round-trips a token through localStorage", () => {
    setStoredToken("abc123");
    expect(localStorage.getItem(TOKEN_KEY)).toBe("abc123");
    expect(getStoredToken()).toBe("abc123");
  });

  it("removes the key when set to null", () => {
    setStoredToken("abc123");
    setStoredToken(null);
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(getStoredToken()).toBeNull();
  });
});

describe("api()", () => {
  beforeEach(() => {
    setStoredToken("api-token");
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("sends the X-HomeRadar-Token header plus Content-Type when a token is present", async () => {
    fetch.mockResolvedValue({ ok: true, json: async () => ({ hello: "world" }) });
    const result = await api("/foo");
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = fetch.mock.calls[0];
    expect(url).toBe("/foo");
    expect(options.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-HomeRadar-Token": "api-token",
    });
    expect(result).toEqual({ hello: "world" });
  });

  it("omits the token header when no token is present", async () => {
    setStoredToken(null);
    fetch.mockResolvedValue({ ok: true, json: async () => ({}) });
    await api("/foo");
    const [, options] = fetch.mock.calls[0];
    expect(options.headers).not.toHaveProperty("X-HomeRadar-Token");
    expect(options.headers).toMatchObject({ "Content-Type": "application/json" });
  });

  it("throws with the response's `detail` message on a non-OK JSON response", async () => {
    fetch.mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: "bad request" }),
    });
    await expect(api("/foo")).rejects.toThrow("bad request");
  });

  it("falls back to a generic message when the error body isn't parseable JSON", async () => {
    fetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => {
        throw new SyntaxError("Unexpected token");
      },
    });
    await expect(api("/foo")).rejects.toThrow("Request failed (500)");
  });

  it("resolves with the parsed JSON body on success", async () => {
    fetch.mockResolvedValue({ ok: true, json: async () => ({ devices: [1, 2, 3] }) });
    const result = await api("/dashboard");
    expect(result).toEqual({ devices: [1, 2, 3] });
  });

  it("passes method/body options through to fetch untouched", async () => {
    fetch.mockResolvedValue({ ok: true, json: async () => ({}) });
    const body = JSON.stringify({ resolved: true });
    await api("/alerts/5", { method: "PATCH", body });
    const [, options] = fetch.mock.calls[0];
    expect(options.method).toBe("PATCH");
    expect(options.body).toBe(body);
  });
});

describe("tokenReady() with a token already present at import time", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves with the pre-existing token and never calls fetch for /pair/local-token", async () => {
    vi.stubGlobal("fetch", vi.fn());
    const result = await tokenReady();
    expect(result).toBe(SEED_TOKEN);
    const calledLocalToken = fetch.mock.calls.some(([url]) => String(url).includes("pair/local-token"));
    expect(calledLocalToken).toBe(false);
  });
});

describe("tokenReady() self-provisioning with no token at import time", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("fetches /pair/local-token, resolves to the returned token, and stores it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url) => {
        expect(String(url)).toContain("/pair/local-token");
        return Promise.resolve({ ok: true, json: async () => ({ token: "abc" }) });
      })
    );
    const freshApi = await import("./api");
    const token = await freshApi.tokenReady();
    expect(token).toBe("abc");
    expect(freshApi.getStoredToken()).toBe("abc");
    expect(localStorage.getItem(TOKEN_KEY)).toBe("abc");
  });

  it("resolves to null (whatever getStoredToken returns) when the fetch rejects", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("network down"))));
    const freshApi = await import("./api");
    const token = await freshApi.tokenReady();
    expect(token).toBeNull();
    expect(freshApi.getStoredToken()).toBeNull();
  });

  it("resolves to null when the fetch returns a non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: false, status: 500 })));
    const freshApi = await import("./api");
    const token = await freshApi.tokenReady();
    expect(token).toBeNull();
    expect(freshApi.getStoredToken()).toBeNull();
  });
});

describe("dashboardSocket()", () => {
  class FakeWebSocket {
    constructor(url) {
      this.url = url;
      FakeWebSocket.instances.push(this);
    }
  }
  FakeWebSocket.instances = [];

  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeWebSocket);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("includes an encoded token query param in the URL when a token is present", () => {
    setStoredToken("t0k en/special");
    const onSnapshot = vi.fn();
    dashboardSocket(onSnapshot);
    const socket = FakeWebSocket.instances[0];
    expect(socket.url).toContain(`?token=${encodeURIComponent("t0k en/special")}`);
  });

  it("has no token query param at all when no token is present", () => {
    setStoredToken(null);
    const onSnapshot = vi.fn();
    dashboardSocket(onSnapshot);
    const socket = FakeWebSocket.instances[0];
    expect(socket.url).not.toContain("token=");
    expect(socket.url.includes("?")).toBe(false);
  });

  it("defaults the scheme/host from window.location when VITE_WS_ROOT isn't set", () => {
    setStoredToken(null);
    expect(import.meta.env.VITE_WS_ROOT).toBeFalsy();
    const onSnapshot = vi.fn();
    dashboardSocket(onSnapshot);
    const socket = FakeWebSocket.instances[0];
    const expectedProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    expect(socket.url).toBe(`${expectedProtocol}//${window.location.host}/ws`);
  });

  it("invokes onSnapshot with the parsed payload for a `snapshot` message", () => {
    setStoredToken("tok");
    const onSnapshot = vi.fn();
    const socket = dashboardSocket(onSnapshot);
    const payload = { type: "snapshot", devices: [], alerts: [] };
    socket.onmessage({ data: JSON.stringify(payload) });
    expect(onSnapshot).toHaveBeenCalledTimes(1);
    expect(onSnapshot).toHaveBeenCalledWith(payload);
  });

  it("does not invoke onSnapshot for a message of a different type", () => {
    setStoredToken("tok");
    const onSnapshot = vi.fn();
    const socket = dashboardSocket(onSnapshot);
    socket.onmessage({ data: JSON.stringify({ type: "something_else" }) });
    expect(onSnapshot).not.toHaveBeenCalled();
  });
});
