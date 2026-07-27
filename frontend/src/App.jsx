import { useEffect, useMemo, useRef, useState } from "react";
import { api, dashboardSocket } from "./api";

const NAV = ["Overview", "Devices", "Traffic", "Alerts", "Settings"];
const deviceGlyphs = {
  phone: "▯", tablet: "▭", computer: "⌨", server: "▤", router: "⌁",
  access_point: "⌁", network_switch: "⇄", printer: "▱", iot_camera: "◉",
  doorbell: "◉", smart_tv: "▰", streaming_device: "▶", game_console: "◇",
  smart_speaker: "◌", smart_home_hub: "⬡", smart_plug: "ϟ", thermostat: "◒",
  wearable: "◍", nas: "▥", media_server: "▶", iot_device: "⬢", unknown: "?",
};

function tone(score) {
  if (score >= 85) return "good";
  if (score >= 65) return "warn";
  return "danger";
}

function timeAgo(value) {
  if (!value) return "never";
  const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function Icon({ name }) {
  const paths = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
    devices: <><rect x="4" y="4" width="16" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></>,
    traffic: <><path d="M4 18V9M10 18V5M16 18v-7M22 18V3"/></>,
    alerts: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a2 2 0 0 0 .4 2.2l.1.1-2.6 2.6-.1-.1a2 2 0 0 0-2.2-.4 2 2 0 0 0-1.2 1.8V21h-3.6v-.2A2 2 0 0 0 9 19a2 2 0 0 0-2.2.4l-.1.1-2.6-2.6.1-.1A2 2 0 0 0 4.6 15 2 2 0 0 0 2.8 14H2v-4h.8A2 2 0 0 0 4.6 9a2 2 0 0 0-.4-2.2l-.1-.1 2.6-2.6.1.1A2 2 0 0 0 9 4.6 2 2 0 0 0 10.2 3V2h3.6v1A2 2 0 0 0 15 4.6a2 2 0 0 0 2.2-.4l.1-.1 2.6 2.6-.1.1A2 2 0 0 0 19.4 9a2 2 0 0 0 1.8 1H22v4h-.8a2 2 0 0 0-1.8 1Z"/></>,
  };
  return <svg className="icon" viewBox="0 0 24 24">{paths[name]}</svg>;
}

function ScoreRing({ score = 100 }) {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className={`score-ring ${tone(score)}`}>
      <svg viewBox="0 0 112 112">
        <circle className="score-track" cx="56" cy="56" r={radius} />
        <circle className="score-value" cx="56" cy="56" r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - score / 100)} />
      </svg>
      <div><strong>{score}</strong><span>SECURITY</span></div>
    </div>
  );
}

function Stat({ label, value, detail, accent = "green" }) {
  return <article className="stat card">
    <div className={`stat-mark ${accent}`} />
    <div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
  </article>;
}

function ActivityChart({ timeline = [] }) {
  const data = timeline.length ? timeline : Array.from({ length: 12 }, (_, i) => ({ queries: [5,8,6,12,9,15,11,18,13,21,16,12][i], blocked: 0 }));
  const max = Math.max(1, ...data.map((point) => point.queries));
  const points = data.map((point, index) => `${index * (100 / Math.max(1, data.length - 1))},${48 - (point.queries / max) * 42}`).join(" ");
  return <div className="activity-chart">
    <svg preserveAspectRatio="none" viewBox="0 0 100 50">
      <defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#39e6a2" stopOpacity=".34"/><stop offset="1" stopColor="#39e6a2" stopOpacity="0"/></linearGradient></defs>
      <polygon points={`0,50 ${points} 100,50`} fill="url(#area)" />
      <polyline points={points} fill="none" stroke="#39e6a2" strokeWidth="1.3" vectorEffect="non-scaling-stroke" />
    </svg>
  </div>;
}

function DeviceRow({ device, onSelect }) {
  const state = device.is_authorized === 1 ? "trusted" : device.is_authorized === 2 ? "blocked" : "pending";
  return <button className="device-row" onClick={() => onSelect(device)}>
    <span className={`device-glyph ${tone(device.trust_score)}`}>{deviceGlyphs[device.device_type] || "?"}</span>
    <span className="device-main"><strong>{device.hostname || device.model || device.vendor || "Unknown device"}</strong><small>{device.vendor || "Unknown manufacturer"} · {device.ip}</small></span>
    <span className={`pill ${state}`}>{state}</span>
    <span className={`trust ${tone(device.trust_score)}`}>{device.trust_score}</span>
    <span className="last-seen">{timeAgo(device.last_seen)}</span>
  </button>;
}

function NetworkMap({ devices, onSelect }) {
  const visible = devices.slice(0, 12);
  return <article className="card network-card">
    <header><div><span>LIVE TOPOLOGY</span><h3>Household network map</h3></div><small>{devices.length} devices</small></header>
    <div className="network-map">
      <div className="hub"><span>⌁</span><b>ROUTER</b></div>
      {visible.map((device, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(visible.length, 1) - Math.PI / 2;
        const x = 50 + Math.cos(angle) * 41;
        const y = 50 + Math.sin(angle) * 38;
        const label = device.hostname || device.vendor || device.ip;
        return <button key={device.id} style={{left:`${x}%`,top:`${y}%`}} onClick={() => onSelect(device)} title={label}><span>{deviceGlyphs[device.device_type] || "?"}</span><small>{label.slice(0,16)}</small></button>;
      })}
    </div>
  </article>;
}

function Overview({ data, onNavigate, onSelect }) {
  const { status = {}, devices = [], alerts = [], traffic = {} } = data;
  const pending = devices.filter((device) => device.is_authorized === 0).length;
  return <>
    <section className="hero-row">
      <div>
        <p className="eyebrow">HOUSEHOLD PROTECTION</p>
        <h1>Your network at a glance</h1>
        <p className="subtle">Live visibility across every device in your home.</p>
      </div>
      <div className="live"><i /> Live monitoring</div>
    </section>
    <section className="overview-grid">
      <article className="score-card card">
        <ScoreRing score={status.security_score ?? 100} />
        <div><span>Household security</span><h2>{status.security_score >= 85 ? "Looking strong" : status.security_score >= 65 ? "Needs attention" : "Action recommended"}</h2><p>{status.open_alert_count || 0} open alerts across {status.device_count || 0} devices.</p></div>
      </article>
      <div className="stats-grid">
        <Stat label="DEVICES" value={status.device_count || 0} detail={`${pending} awaiting review`} />
        <Stat label="BLOCKED · 24H" value={traffic.blocked || 0} detail={`${traffic.queries || 0} DNS queries`} accent="amber" />
        <Stat label="ACTIVE ALERTS" value={status.open_alert_count || 0} detail="Review recommended" accent="red" />
      </div>
    </section>
    <section className="two-column">
      <article className="card panel">
        <header><div><span>NETWORK ACTIVITY</span><h3>DNS requests · last 24 hours</h3></div><strong>{traffic.queries || 0}</strong></header>
        <ActivityChart timeline={traffic.timeline} />
        <footer><span><i className="dot green"/>Allowed</span><span><i className="dot amber"/>Blocked</span></footer>
      </article>
      <article className="card panel alert-panel">
        <header><div><span>RECENT ALERTS</span><h3>What needs your attention</h3></div><button onClick={() => onNavigate("Alerts")}>View all</button></header>
        <div className="alert-list">
          {alerts.slice(0, 4).map((alert) => <div className="alert-item" key={alert.id}><b className={alert.severity}>!</b><div><strong>{alert.title}</strong><p>{alert.description}</p></div><small>{timeAgo(alert.created_at)}</small></div>)}
          {!alerts.length && <div className="empty">No active alerts. Your network is quiet.</div>}
        </div>
      </article>
    </section>
    <article className="card panel devices-panel">
      <header><div><span>RECENT DEVICES</span><h3>Connected to your network</h3></div><button onClick={() => onNavigate("Devices")}>All devices</button></header>
      <div className="table-head"><span>DEVICE</span><span>STATUS</span><span>TRUST</span><span>LAST SEEN</span></div>
      {devices.slice(0, 6).map((device) => <DeviceRow key={device.id} device={device} onSelect={onSelect} />)}
      {!devices.length && <div className="empty">Run a discovery scan to build your inventory.</div>}
    </article>
  </>;
}

function Devices({ devices, onSelect, onScan, busy }) {
  const [query, setQuery] = useState("");
  const filtered = devices.filter((d) => JSON.stringify(d).toLowerCase().includes(query.toLowerCase()));
  return <section>
    <div className="page-heading"><div><p className="eyebrow">INVENTORY</p><h1>Devices</h1><p className="subtle">Identify, trust, or block anything on your network.</p></div><button className="primary" onClick={onScan} disabled={busy}>{busy ? "Scanning…" : "Scan network"}</button></div>
    <NetworkMap devices={devices} onSelect={onSelect}/>
    <div className="toolbar card"><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name, IP, MAC, vendor, or type…" /><span>{filtered.length} devices</span></div>
    <article className="card panel devices-panel full">
      <div className="table-head"><span>DEVICE</span><span>STATUS</span><span>TRUST</span><span>LAST SEEN</span></div>
      {filtered.map((device) => <DeviceRow key={device.id} device={device} onSelect={onSelect} />)}
    </article>
  </section>;
}

function DeviceDrawer({ device, onClose, onUpdate }) {
  const [trust, setTrust] = useState(null);
  const [traffic, setTraffic] = useState([]);
  useEffect(() => {
    if (!device) return;
    api(`/devices/${device.id}/trust`).then(setTrust).catch(() => {});
    api(`/devices/${device.id}/traffic?limit=30`).then(setTraffic).catch(() => {});
  }, [device]);
  if (!device) return null;
  const changeState = async (state) => {
    const updated = await api(`/devices/${device.id}/authorization`, { method: "PATCH", body: JSON.stringify({ state }) });
    onUpdate(updated);
  };
  return <div className="drawer-backdrop" onClick={onClose}><aside className="drawer" onClick={(e) => e.stopPropagation()}>
    <button className="close" onClick={onClose}>×</button>
    <span className={`device-glyph large ${tone(device.trust_score)}`}>{deviceGlyphs[device.device_type] || "?"}</span>
    <p className="eyebrow">{device.device_type.replaceAll("_", " ")}</p>
    <h2>{device.hostname || device.model || device.vendor || "Unknown device"}</h2>
    <p className="subtle">{device.vendor || "Unknown manufacturer"} · {device.model || "Model unavailable"}</p>
    <div className="detail-grid"><div><span>IP ADDRESS</span><strong>{device.ip}</strong></div><div><span>MAC ADDRESS</span><strong>{device.mac}</strong></div><div><span>TRUST SCORE</span><strong className={tone(device.trust_score)}>{device.trust_score}/100</strong></div><div><span>CONFIDENCE</span><strong>{Math.round((device.fingerprint_confidence || 0) * 100)}%</strong></div></div>
    <div className="drawer-actions"><button className="primary" onClick={() => changeState(1)}>Authorize</button><button className="danger-button" onClick={() => changeState(2)}>Block</button><button onClick={() => changeState(0)}>Reset</button></div>
    <section><h3>Trust breakdown</h3>{trust?.reasons?.map((reason) => <p className="reason" key={reason}>{reason}</p>) || <p className="subtle">Calculating…</p>}</section>
    <section><h3>Recent DNS activity</h3>{traffic.slice(0, 8).map((item) => <p className="traffic-line" key={item.id}><span>{item.domain || item.dest_ip}</span><b className={item.was_blocked ? "danger" : "good"}>{item.was_blocked ? "blocked" : "allowed"}</b></p>)}{!traffic.length && <p className="subtle">No traffic recorded yet.</p>}</section>
  </aside></div>;
}

function Traffic({ traffic }) {
  return <section><div className="page-heading"><div><p className="eyebrow">VISIBILITY</p><h1>Traffic</h1><p className="subtle">DNS activity and blocked destinations across your household.</p></div></div>
    <div className="stats-grid wide"><Stat label="DNS QUERIES · 24H" value={traffic.queries || 0} detail="Observed locally"/><Stat label="BLOCKED" value={traffic.blocked || 0} detail="Threats and trackers" accent="amber"/><Stat label="DATA OBSERVED" value={`${Math.round(((traffic.bytes_sent || 0) + (traffic.bytes_received || 0))/1024)} KB`} detail="DNS proxy metadata" accent="blue"/></div>
    <div className="two-column"><article className="card panel"><header><div><span>ACTIVITY</span><h3>Request volume</h3></div></header><ActivityChart timeline={traffic.timeline}/></article>
    <article className="card panel"><header><div><span>TOP DESTINATIONS</span><h3>Most requested domains</h3></div></header>{(traffic.top_domains || []).map((item, index) => <div className="rank" key={item.domain}><b>{String(index+1).padStart(2,"0")}</b><span>{item.domain}</span><strong>{item.count}</strong></div>)}{!traffic.top_domains?.length && <div className="empty">DNS data will appear after clients use Home Radar.</div>}</article></div>
  </section>;
}

function Alerts({ alerts, onResolve }) {
  return <section><div className="page-heading"><div><p className="eyebrow">ATTENTION</p><h1>Alerts</h1><p className="subtle">Prioritized security events with clear next actions.</p></div></div>
    <article className="card panel alert-page">{alerts.map((alert) => <div className="alert-card" key={alert.id}><b className={alert.severity}>!</b><div><span>{alert.severity}</span><h3>{alert.title}</h3><p>{alert.description}</p><small>{new Date(alert.created_at).toLocaleString()}</small></div><button onClick={() => onResolve(alert.id)}>Resolve</button></div>)}{!alerts.length && <div className="empty big">No open alerts. Everything looks calm.</div>}</article>
  </section>;
}

function Settings() {
  const [form, setForm] = useState({});
  const [message, setMessage] = useState("");
  useEffect(() => { api("/settings").then(setForm); }, []);
  const save = async (event) => {
    event.preventDefault();
    if (form.notifications_enabled && "Notification" in window && Notification.permission === "default") {
      await Notification.requestPermission();
    }
    setForm(await api("/settings", { method: "PATCH", body: JSON.stringify(form) }));
    setMessage("Settings saved");
  };
  return <section><div className="page-heading"><div><p className="eyebrow">APPLIANCE</p><h1>Settings</h1><p className="subtle">Configure your household, DNS, and digest preferences.</p></div></div>
    <form className="card settings-form" onSubmit={save}>
      <label><span>Household name</span><input value={form.household_name || ""} onChange={(e) => setForm({...form, household_name:e.target.value})}/></label>
      <label><span>Weekly digest email</span><input type="email" value={form.digest_email || ""} onChange={(e) => setForm({...form, digest_email:e.target.value})} placeholder="family@example.com"/></label>
      <label><span>Upstream DNS resolver</span><input value={form.dns_upstream || ""} onChange={(e) => setForm({...form, dns_upstream:e.target.value})}/></label>
      <label className="toggle-row"><span><b>Browser notifications</b><small>Show alerts while the dashboard is open.</small></span><input type="checkbox" checked={!!form.notifications_enabled} onChange={(e) => setForm({...form, notifications_enabled:e.target.checked})}/></label>
      <div className="form-footer"><span className="good">{message}</span><button className="primary">Save settings</button></div>
    </form>
  </section>;
}

export default function App() {
  const [page, setPage] = useState("Overview");
  const [data, setData] = useState({ status: {}, devices: [], alerts: [], traffic: {} });
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const seenAlerts = useRef(new Set());
  const alertsInitialized = useRef(false);
  const load = () => api("/dashboard").then(setData).catch(() => setConnected(false));
  useEffect(() => {
    load();
    let socket;
    let retry;
    const connect = () => {
      socket = dashboardSocket((snapshot) => { setData((current) => ({...current, ...snapshot})); setConnected(true); });
      socket.onclose = () => { setConnected(false); retry = setTimeout(connect, 2500); };
      socket.onerror = () => socket.close();
    };
    connect();
    return () => { clearTimeout(retry); socket?.close(); };
  }, []);
  useEffect(() => {
    for (const alert of data.alerts || []) {
      if (alertsInitialized.current && !seenAlerts.current.has(alert.id) && "Notification" in window && Notification.permission === "granted") {
        new Notification(`Home Radar: ${alert.title}`, { body: alert.description || "Open the dashboard for details." });
      }
      seenAlerts.current.add(alert.id);
    }
    alertsInitialized.current = true;
  }, [data.alerts]);
  const scan = async () => { setBusy(true); try { await api("/scan", {method:"POST"}); await load(); } finally { setBusy(false); } };
  const resolve = async (id) => { await api(`/alerts/${id}`, {method:"PATCH", body:JSON.stringify({resolved:true})}); await load(); };
  const title = useMemo(() => page === "Overview" ? "Command center" : page, [page]);
  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="radar-logo"><i/><i/><i/></div><div><strong>Home<span>Radar</span></strong><small>NETWORK DEFENSE</small></div></div>
      <nav>{NAV.map((item) => <button className={page === item ? "active" : ""} onClick={() => setPage(item)} key={item}><Icon name={item.toLowerCase()}/><span>{item}</span>{item === "Alerts" && data.alerts?.length > 0 && <b>{data.alerts.length}</b>}</button>)}</nav>
      <div className="appliance-status"><span><i className={connected ? "online" : ""}/>{connected ? "Appliance online" : "Reconnecting…"}</span><small>{data.status?.blocklist_domains || 0} blocked domains</small></div>
    </aside>
    <main><header className="topbar"><span>{title}</span><div><button className="scan-mini" onClick={scan} disabled={busy}>{busy ? "Scanning…" : "Run scan"}</button><span className={`score-chip ${tone(data.status?.security_score || 100)}`}>{data.status?.security_score ?? 100}</span></div></header>
      <div className="content">
        {page === "Overview" && <Overview data={data} onNavigate={setPage} onSelect={setSelected}/>}
        {page === "Devices" && <Devices devices={data.devices || []} onSelect={setSelected} onScan={scan} busy={busy}/>}
        {page === "Traffic" && <Traffic traffic={data.traffic || {}}/>}
        {page === "Alerts" && <Alerts alerts={data.alerts || []} onResolve={resolve}/>}
        {page === "Settings" && <Settings/>}
      </div>
    </main>
    <DeviceDrawer device={selected} onClose={() => setSelected(null)} onUpdate={(updated) => { setSelected(updated); load(); }}/>
  </div>;
}
