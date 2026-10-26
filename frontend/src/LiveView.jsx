import React, { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { DeviceIcon, Icon } from "./icons";
import { deviceName, deviceTypeLabel, explainAlert, plural, vendorHint } from "./insights";

export const SCENARIOS = [
  { kind: "new_device", label: "Unknown device joins", icon: "devices" },
  { kind: "malicious_dns", label: "Malware connection", icon: "stop" },
  { kind: "deauth", label: "Wi-Fi attack", icon: "wave" },
];
// Offered only when the appliance supports learned habits (feature-detected).
const HABITS_SCENARIO = { kind: "night_upload", label: "Camera awake at 3 AM", icon: "live" };

function hourLabel(hour) {
  if (hour === 0) return "12 AM";
  if (hour === 12) return "12 PM";
  return hour < 12 ? `${hour} AM` : `${hour - 12} PM`;
}

export function HabitProfile({ hours = [], highlightHour = null }) {
  const values = hours.length === 24 ? hours : Array(24).fill(0);
  const max = Math.max(1e-9, ...values);
  return <div className="habit-profile">
    <div className="habit-bars" role="img" aria-label="Typical activity by hour of day">
      {values.map((value, hour) => <span key={hour} className={hour === highlightHour ? "now" : ""} style={{ height: `${Math.max(4, (value / max) * 100)}%` }} title={hourLabel(hour)} />)}
    </div>
    <div className="habit-axis"><span>12 AM</span><span>6 AM</span><span>12 PM</span><span>6 PM</span><span>12 AM</span></div>
  </div>;
}

const MAX_MAP_DEVICES = 13;
const INTERNET = { x: 50, y: 7 };
const ROUTER = { x: 50, y: 30 };
const RADAR = { x: 22, y: 12 };

export function timeAgo(value) {
  if (!value) return "never";
  const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

const TOP_Y = 56;
const BOTTOM_Y = 84;

// Two staggered rows. Bottom-row devices sit in the gaps between top-row
// devices and their links curve down through those gaps, so no link ever
// passes underneath another device.
function layoutDevices(devices) {
  const shown = devices.filter((device) => !["router", "access_point"].includes(device.device_type)).slice(0, MAX_MAP_DEVICES);
  if (shown.length <= 6) {
    return shown.map((device, index) => {
      const x = shown.length === 1 ? 50 : 14 + (index * 72) / (shown.length - 1);
      return { device, x, y: 64, path: `M${ROUTER.x} ${ROUTER.y} L${x} 64` };
    });
  }
  const topCount = Math.ceil((shown.length + 1) / 2);
  const top = shown.slice(0, topCount).map((device, index) => {
    const x = 12 + (index * 76) / (topCount - 1);
    return { device, x, y: TOP_Y, path: `M${ROUTER.x} ${ROUTER.y} L${x} ${TOP_Y}` };
  });
  const bottom = shown.slice(topCount).map((device, index) => {
    const x = (top[index].x + top[index + 1].x) / 2;
    return { device, x, y: BOTTOM_Y, path: `M${ROUTER.x} ${ROUTER.y} C${ROUTER.x} ${ROUTER.y + 12} ${x} ${TOP_Y - 14} ${x} ${TOP_Y - 2} L${x} ${BOTTOM_Y}` };
  });
  return [...top, ...bottom];
}

export function mapLabel(device) {
  return deviceName(device).replace(/[-_]+/g, " ").trim();
}

function routerDevice(devices) {
  return devices.find((device) => ["router", "access_point"].includes(device.device_type));
}

function deviceState(device) {
  if (device.is_authorized === 2) return "blocked";
  if (device.is_authorized === 0) return "pending";
  return "trusted";
}

function LiveMap({ devices, event, onSelect }) {
  const placed = useMemo(() => layoutDevices(devices), [devices]);
  const router = routerDevice(devices);
  const hidden = Math.max(0, devices.length - (router ? 1 : 0) - placed.length);
  const focusId = event?.device?.id;
  const kind = event?.kind;
  const focus = placed.find((item) => item.device.id === focusId);
  const blockedTarget = kind === "malicious_dns" ? (event.alert?.title || "").split(": ").pop() : "";
  return <div className="live-map" aria-label="Map of your home network">
    <svg className="map-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
      <line x1={INTERNET.x} y1={INTERNET.y} x2={ROUTER.x} y2={ROUTER.y} />
      <line x1={RADAR.x} y1={RADAR.y} x2={ROUTER.x} y2={ROUTER.y} className="link-radar" />
      {placed.map(({ device, path }) => <path key={device.id} d={path}
        className={`${deviceState(device)}${device.id === focusId ? ` focus ${kind}` : ""}`} />)}
    </svg>
    <div className="map-node fixed" style={{ left: `${INTERNET.x}%`, top: `${INTERNET.y}%` }}>
      <span className="node-dot"><Icon name="internet" /></span><span className="node-label">Internet</span>
    </div>
    <div className={`map-node fixed router${kind === "deauth" ? " under-attack" : ""}`} style={{ left: `${ROUTER.x}%`, top: `${ROUTER.y}%` }}>
      <span className="node-dot"><DeviceIcon name="router" /></span>
      <span className="node-label">{router ? mapLabel(router) : "Router"}</span>
      {kind === "deauth" && <span key={event.id} className="wifi-waves" aria-hidden="true"><Icon name="wave" /></span>}
    </div>
    <div className={`map-node fixed radar${kind === "malicious_dns" ? " stopping" : ""}`} style={{ left: `${RADAR.x}%`, top: `${RADAR.y}%` }}>
      <span className="node-dot"><DeviceIcon name="radar" /></span>
      <span className="node-label">Home Radar</span>
      <span className="node-meta">Checks every request</span>
      {kind === "malicious_dns" && blockedTarget && <span key={event.id} className="stop-badge"><Icon name="stop" /> Blocked {blockedTarget}</span>}
    </div>
    {placed.map(({ device, x, y }) => {
      const state = deviceState(device);
      const isFocus = device.id === focusId;
      return <button key={device.id} type="button"
        className={`map-node ${state}${isFocus ? ` focus ${kind}` : ""}`}
        style={{ left: `${x}%`, top: `${y}%` }} onClick={() => onSelect(device)}>
        <span className="node-dot"><DeviceIcon type={device.device_type} />{isFocus && kind === "new_device" && <span key={event.id} className="scan-ring" aria-hidden="true" />}</span>
        <span className="node-label">{mapLabel(device)}</span>
        <span className="node-meta">{state === "blocked" ? "Blocked" : state === "pending" ? "Needs review" : device.ip}</span>
      </button>;
    })}
    {kind === "malicious_dns" && focus && <span key={event.id} className="packet" aria-hidden="true" style={{
      "--x0": `${focus.x}%`, "--y0": `${focus.y}%`, "--x1": `${ROUTER.x}%`, "--y1": `${ROUTER.y}%`, "--x2": `${RADAR.x}%`, "--y2": `${RADAR.y}%`,
    }} />}
    {hidden > 0 && <span className="map-more">+{plural(hidden, "more device")}</span>}
  </div>;
}

function useReveal(key, steps) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    setShown(0);
    if (!key) return undefined;
    const timers = Array.from({ length: steps }, (_, index) => setTimeout(() => setShown(index + 1), 600 * (index + 1)));
    return () => timers.forEach(clearTimeout);
  }, [key, steps]);
  return shown;
}

function Investigation({ event, device, onAct }) {
  const [trust, setTrust] = useState(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    setTrust(null);
    if (device?.id) api(`/devices/${device.id}/trust`).then((result) => { if (!cancelled) setTrust(result); }).catch(() => {});
    return () => { cancelled = true; };
  }, [device?.id, event.id]);
  const score = trust?.score ?? device.trust_score;
  const hint = vendorHint(device.vendor);
  const steps = [
    { label: "Manufacturer", value: device.vendor || "Unknown", detail: [device.mac ? `Its hardware address starts with ${device.mac.slice(0, 8)}.` : "", hint].filter(Boolean).join(" ") },
    { label: "Name", value: device.hostname || "No name broadcast", detail: device.hostname ? "It announced this name on the network." : "Many cheap smart-home gadgets don't announce a name." },
    { label: "First seen", value: timeAgo(device.first_seen), detail: "It hasn't been on this network before." },
    { label: "Looks like", value: deviceTypeLabel(device.device_type), detail: `${Math.round((device.fingerprint_confidence || 0) * 100)}% confident, based on its manufacturer and how it behaves.` },
    { label: "Trust score", value: score != null ? `${score} / 100` : "Calculating…", detail: "New devices stay low until your family approves them." },
  ];
  // Keep the panel screen-height: explain the manufacturer (the interesting
  // finding) and whichever step was just revealed; the rest show just the value.
  const shown = useReveal(event.id, steps.length + 1);
  const showDetail = (index) => index === 0 || index === shown - 1;
  const state = deviceState(device);
  const act = async (next) => {
    setBusy(next === 2 ? "block" : "trust");
    setError("");
    try {
      await onAct(event.alert, next);
    } catch (err) {
      setError(err.message || "That didn't work. Try again.");
    } finally {
      setBusy("");
    }
  };
  return <div className="investigation" aria-live="polite">
    <p className="panel-kicker">{state === "pending" ? (shown > steps.length ? "Investigation complete" : "Investigating new device…") : "Investigation complete"}</p>
    <h2>{deviceName(device)}</h2>
    <p className="mono subtle">{device.ip} · {device.mac}</p>
    <ol className="checks">
      {steps.map((step, index) => <li key={step.label} className={index < shown ? "done" : "waiting"}>
        <span className="check-mark">{index < shown && <Icon name="check" />}</span>
        <div><span>{step.label}</span><b>{index < shown ? step.value : "…"}</b>{index < shown && showDetail(index) && <p>{step.detail}</p>}</div>
      </li>)}
    </ol>
    {shown > steps.length && state === "pending" && <div className="verdict warn">
      <b>Not approved by your family yet.</b>
      <p>If nobody recognizes it, block it. Home Radar will stop answering its internet requests.</p>
      <div className="verdict-actions">
        <button className="danger-button" onClick={() => act(2)} disabled={!!busy}>{busy === "block" ? "Blocking…" : "Block this device"}</button>
        <button onClick={() => act(1)} disabled={!!busy}>{busy === "trust" ? "Saving…" : "It's mine"}</button>
      </div>
      {error && <p className="inline-error">{error}</p>}
    </div>}
    {state === "blocked" && <div className="verdict blocked"><b>Blocked.</b><p>{deviceName(device)} can no longer reach the internet through Home Radar. You can undo this from Devices.</p></div>}
    {state === "trusted" && <div className="verdict good"><b>Marked as yours.</b><p>Home Radar will keep watching it, but won't flag it as new again.</p></div>}
  </div>;
}

function BlockedRequest({ event, device }) {
  const guide = explainAlert(event.alert);
  const target = (event.alert?.title || "").split(": ").pop();
  return <div className="investigation" aria-live="polite">
    <p className="panel-kicker">Request stopped</p>
    <h2>Blocked {target}</h2>
    <p className="subtle">{device ? `${deviceName(device)}${device.ip ? ` (${device.ip})` : ""}` : "A device on your network"} tried to reach an address on a known threat list. Home Radar answered instead of the internet, so nothing got through.</p>
    <dl className="facts">
      <div><dt>From</dt><dd>{device ? deviceName(device) : "Unknown device"}</dd></div>
      <div><dt>To</dt><dd className="mono">{target}</dd></div>
      <div><dt>Result</dt><dd className="danger-text">Blocked</dd></div>
    </dl>
    <div className="verdict"><b>What to do</b><p>{guide.action}</p></div>
  </div>;
}

function WifiAttack({ event }) {
  const guide = explainAlert(event.alert);
  return <div className="investigation" aria-live="polite">
    <p className="panel-kicker">Wi-Fi attack detected</p>
    <h2>Someone is knocking devices off your Wi-Fi</h2>
    <p className="subtle">{guide.meaning}</p>
    <p className="subtle">This is called a deauthentication attack. Cheap tools can send these signals from outside your home, and they don't need your Wi-Fi password.</p>
    <div className="verdict"><b>What to do</b><p>{guide.action}</p></div>
  </div>;
}

function NightActivity({ event, device }) {
  const habits = event.habits || {};
  const hour = new Date(event.alert?.created_at || Date.now()).getHours();
  return <div className="investigation" aria-live="polite">
    <p className="panel-kicker">Unusual for this device</p>
    <h2>{device ? deviceName(device) : "A device"} is active at an odd hour</h2>
    <p className="subtle">{habits.explanation || explainAlert(event.alert).meaning}</p>
    <HabitProfile hours={habits.typical_active_hours} highlightHour={hour} />
    <p className="small-note subtle">Bars show when this device is normally active. The highlighted bar is now.</p>
    {habits.score != null && <dl className="facts"><div><dt>How unusual</dt><dd>{Math.round(habits.score * 100)} / 100</dd></div></dl>}
    <div className="verdict"><b>What to do</b><p>{explainAlert(event.alert).action}</p></div>
  </div>;
}

function Timeline({ alerts, deviceCount }) {
  return <div className="timeline">
    <p className="panel-kicker">Recent detections</p>
    {alerts.length ? <ol>{alerts.slice(0, 6).map((alert) => <li key={alert.id}>
      <i className={`sev ${alert.severity}`} aria-hidden="true" />
      <div><b>{alert.title}</b><small>{timeAgo(alert.created_at)}{explainAlert(alert).simulated ? " · simulated" : ""}</small></div>
    </li>)}</ol> : <p className="subtle">Nothing suspicious lately. Home Radar is watching {plural(deviceCount, "device")}.</p>}
  </div>;
}

export default function LiveView({ data, event, story, demoAvailable, onRunScenario, onPlayStory, onAct, onSelect }) {
  const devices = data.devices || [];
  const alerts = data.alerts || [];
  const current = event?.device ? devices.find((device) => device.id === event.device.id) || event.device : null;
  const busy = !!event?.pending || story.running;
  const showDemoLabel = story.running || (event && !event.error);
  const [habitsSupported, setHabitsSupported] = useState(false);
  useEffect(() => {
    let cancelled = false;
    api("/habits/summary").then((result) => { if (!cancelled) setHabitsSupported(!!result && typeof result.devices_learning === "number"); }).catch(() => {});
    return () => { cancelled = true; };
  }, []);
  const scenarios = habitsSupported ? [...SCENARIOS, HABITS_SCENARIO] : SCENARIOS;
  let panel = <Timeline alerts={alerts} deviceCount={devices.length} />;
  if (event?.kind === "new_device" && current) panel = <Investigation event={event} device={current} onAct={onAct} />;
  else if (event?.kind === "malicious_dns" && event.alert) panel = <BlockedRequest event={event} device={current} />;
  else if (event?.kind === "deauth" && event.alert) panel = <WifiAttack event={event} />;
  else if (event?.kind === "night_upload" && event.alert) panel = <NightActivity event={event} device={current} />;
  return <section className="live-page" data-testid="live-view">
    <div className="page-heading">
      <div><h1>Live view</h1><p className="subtle">Every device on your network, and what Home Radar does when something happens.</p></div>
      {showDemoLabel && <span className="demo-label">Demo: simulated events</span>}
    </div>
    {demoAvailable && <div className="scenario-bar" role="group" aria-label="Demo scenarios">
      <span className="scenario-title">Try a scenario</span>
      {scenarios.map((scenario) => <button key={scenario.kind} onClick={() => onRunScenario(scenario.kind)} disabled={busy}
        className={event?.kind === scenario.kind ? "selected" : ""}>
        <Icon name={scenario.icon} />{scenario.label}
      </button>)}
      <button className="primary" onClick={onPlayStory} disabled={busy}><Icon name="play" />{story.running ? `Playing ${story.step} of ${SCENARIOS.length}…` : "Play demo story"}</button>
    </div>}
    {event?.error && <p className="inline-error" role="alert">{event.error}</p>}
    <div className="live-layout">
      <LiveMap devices={devices} event={event?.error ? null : event} onSelect={onSelect} />
      <aside className="live-panel">{panel}</aside>
    </div>
  </section>;
}
