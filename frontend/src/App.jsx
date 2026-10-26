import React, { useEffect, useRef, useState } from "react";
import { api, dashboardSocket, setStoredToken } from "./api";
import { DeviceIcon, Icon } from "./icons";
import LiveView, { HabitProfile, SCENARIOS, timeAgo } from "./LiveView";
import {
  deviceName, deviceTypeLabel, explainAlert, friendlyError, gradeVerdict, letterGrade,
  overviewHeadline, plural, reportTips,
} from "./insights";

const NAV = [
  { id: "Overview", label: "Home", icon: "home" },
  { id: "Live", label: "Live view", icon: "live" },
  { id: "Devices", label: "Devices", icon: "devices" },
  { id: "Alerts", label: "Alerts", icon: "alerts" },
  { id: "Traffic", label: "Traffic", icon: "traffic" },
  { id: "Settings", label: "Settings", icon: "settings" },
];
const DEMO_STORY = SCENARIOS.map((scenario) => scenario.kind);
const STORY_DELAYS = [800, 9000, 7000];

function tone(score) {
  if (score >= 85) return "good";
  if (score >= 65) return "warn";
  return "danger";
}

function severityInfo(severity) {
  if (severity === "critical" || severity === "danger") return { tone: "danger", label: "Threat" };
  if (severity === "warning" || severity === "warn") return { tone: "warn", label: "Needs review" };
  return { tone: "info", label: "For your information" };
}

function stateLabel(device) {
  if (device.is_authorized === 1) return { key: "trusted", label: "Trusted" };
  if (device.is_authorized === 2) return { key: "blocked", label: "Blocked" };
  return { key: "pending", label: "Needs review" };
}

function GradeMark({ score }) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const grade = letterGrade(score);
  return <div className={`grade-mark ${tone(score)}`}>
    <svg viewBox="0 0 100 100" aria-hidden="true">
      <circle className="track" cx="50" cy="50" r={radius} />
      <circle className="value" cx="50" cy="50" r={radius} strokeDasharray={circumference} strokeDashoffset={circumference * (1 - score / 100)} />
    </svg>
    <strong data-testid="household-grade">{grade}</strong>
  </div>;
}

function ActivityChart({ timeline = [] }) {
  if (!timeline.length) return <p className="chart-empty">No DNS activity yet. Home Radar starts counting once it's your network's DNS server.</p>;
  const max = Math.max(1, ...timeline.map((point) => point.queries || 0));
  const width = 100 / timeline.length;
  return <svg className="activity-chart" viewBox="0 0 100 40" preserveAspectRatio="none" role="img" aria-label="Requests per hour, with blocked requests highlighted">
    {timeline.map((point, index) => {
      const total = ((point.queries || 0) / max) * 38;
      const blocked = ((point.blocked || 0) / max) * 38;
      return <g key={index}>
        <rect className="bar" x={index * width + width * 0.18} width={width * 0.64} y={40 - total} height={total} />
        {blocked > 0 && <rect className="bar blocked" x={index * width + width * 0.18} width={width * 0.64} y={40 - blocked} height={blocked} />}
      </g>;
    })}
  </svg>;
}

function BandwidthSparkline({ buckets }) {
  if (!buckets) return <small className="subtle">…</small>;
  let totals = buckets.map((b) => (b.bytes_sent || 0) + (b.bytes_received || 0));
  if (!totals.some((value) => value > 0)) return <small className="subtle">No traffic</small>;
  // A single hourly bucket can't draw a line on its own -- lead in from zero
  // so the one real data point still renders as a visible rise, not nothing.
  if (totals.length === 1) totals = [0, ...totals];
  const max = Math.max(1, ...totals);
  const points = totals.map((value, index) => `${index * (100 / Math.max(1, totals.length - 1))},${20 - (value / max) * 18}`).join(" ");
  return <svg className="sparkline" viewBox="0 0 100 20" preserveAspectRatio="none" aria-hidden="true">
    <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
  </svg>;
}

function DeviceRow({ device, onSelect, showBandwidth }) {
  const state = stateLabel(device);
  const [bandwidth, setBandwidth] = useState(null);
  useEffect(() => {
    if (!showBandwidth) return;
    let cancelled = false;
    api(`/devices/${device.id}/traffic/timeseries?hours=24`)
      .then((result) => { if (!cancelled) setBandwidth(result.buckets); })
      .catch(() => { if (!cancelled) setBandwidth([]); });
    return () => { cancelled = true; };
  }, [device.id, showBandwidth]);
  return <button className={`device-row${showBandwidth ? " wide" : ""}`} onClick={() => onSelect(device)}>
    <span className={`device-avatar ${state.key}`}><DeviceIcon type={device.device_type} /></span>
    <span className="device-main"><strong>{deviceName(device)}</strong><small>{deviceTypeLabel(device.device_type)} · {device.vendor || "Unknown maker"} · <span className="mono">{device.ip}</span></small></span>
    <span className={`status ${state.key}`}>{state.label}</span>
    <span className={`trust ${tone(device.trust_score)}`}>{device.trust_score}</span>
    <span className="last-seen">{timeAgo(device.last_seen)}</span>
    {showBandwidth && <span className="bandwidth-cell"><BandwidthSparkline buckets={bandwidth} /></span>}
  </button>;
}

function SimulatedTag({ alert }) {
  return explainAlert(alert).simulated ? <em className="sim-tag" title="Created by demo mode, not a real detection">Simulated</em> : null;
}

function AlertGuide({ alert, onAct }) {
  const guide = explainAlert(alert);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const act = async (state) => {
    setBusy(state === 2 ? "block" : "trust");
    setError("");
    try {
      await onAct(alert, state);
    } catch (err) {
      setError(err.message || "That didn't work. Try again.");
    } finally {
      setBusy("");
    }
  };
  const showActions = onAct && (guide.canBlock || guide.canTrust);
  return <div className="alert-guide">
    <p><b>What this means</b>{guide.meaning}</p>
    <p><b>What to do</b>{guide.action}</p>
    {showActions && <div className="alert-actions">
      {guide.canBlock && <button className="danger-button" onClick={() => act(2)} disabled={!!busy}>{busy === "block" ? "Blocking…" : "Block this device"}</button>}
      {guide.canTrust && <button onClick={() => act(1)} disabled={!!busy}>{busy === "trust" ? "Saving…" : "It's mine, trust it"}</button>}
    </div>}
    {error && <p className="inline-error">{error}</p>}
  </div>;
}

function Overview({ data, onNavigate, onSelect, onOpenReport, freshAlertIds = new Set() }) {
  const { status = {}, devices = [], traffic = {} } = data;
  const alerts = data.alerts || [];
  const score = status.security_score ?? 100;
  const grade = letterGrade(score);
  const deviceCount = status.device_count ?? devices.length;
  const blocked = traffic.blocked || 0;
  const openAlerts = status.open_alert_count ?? alerts.length;
  const headline = overviewHeadline({ alerts, devices, score });
  return <div className="overview" data-testid="overview">
    <section className="overview-hero">
      <h1 className={`headline ${headline.tone}`}>{headline.text}</h1>
      <p className="lead">Home Radar is watching {plural(deviceCount, "device")} and checking every website they try to reach.</p>
      <div className="hero-actions">
        {alerts.length > 0
          ? <button className="primary" onClick={() => onNavigate("Alerts")}>Review {plural(alerts.length, "alert")}</button>
          : <button className="primary" onClick={() => onNavigate("Devices")}>See your devices</button>}
        <button onClick={() => onNavigate("Live")}><Icon name="live" />Open live view</button>
      </div>
    </section>

    <section className="summary" aria-label="Protection summary">
      <div className="grade-cell">
        <GradeMark score={score} />
        <div>
          <span className="label">Security grade</span>
          <b>{gradeVerdict(grade)}</b>
          <small>Score {score} of 100 · {plural(openAlerts, "open alert")}</small>
        </div>
      </div>
      <div className="fact"><b>{deviceCount}</b><span>{deviceCount === 1 ? "device" : "devices"} protected</span></div>
      <div className="fact"><b>{blocked}</b><span>{blocked === 1 ? "threat" : "threats"} blocked today</span></div>
      <div className="fact"><b>$0</b><span>a month, no subscription</span></div>
      {onOpenReport && <button className="text-button report-inline" onClick={onOpenReport}><Icon name="report" />View report card</button>}
    </section>

    <section className="overview-columns">
      <article className="panel attention">
        <header><h2>Needs your attention</h2>{alerts.length > 0 && <button className="text-button" onClick={() => onNavigate("Alerts")}>See all</button>}</header>
        {alerts.slice(0, 3).map((alert) => {
          const severity = severityInfo(alert.severity);
          return <button key={alert.id} className={`attention-row${freshAlertIds.has(alert.id) ? " alert-new" : ""}`} onClick={() => onNavigate("Alerts")}>
            <i className={`sev ${severity.tone}`} aria-hidden="true" />
            <span><strong>{alert.title}</strong><SimulatedTag alert={alert} /><small>{explainAlert(alert).meaning}</small></span>
            <time>{timeAgo(alert.created_at)}</time>
          </button>;
        })}
        {!alerts.length && <p className="empty">Nothing needs you. Your network is quiet.</p>}
        {alerts.length > 3 && <p className="more-note">{plural(alerts.length - 3, "more alert")} on the Alerts page.</p>}
      </article>
      <article className="panel activity">
        <header><h2>Internet activity today</h2></header>
        <p className="figure"><b>{traffic.queries || 0}</b> lookups · <b className="warn-text">{blocked}</b> blocked</p>
        <ActivityChart timeline={traffic.timeline} />
        <p className="legend"><span><i className="key" />Requests</span><span><i className="key blocked" />Blocked</span></p>
      </article>
    </section>

    <article className="panel devices-panel">
      <header><h2>Devices on your network</h2><button className="text-button" onClick={() => onNavigate("Devices")}>See all {devices.length}</button></header>
      {devices.slice(0, 6).map((device) => <DeviceRow key={device.id} device={device} onSelect={onSelect} />)}
      {!devices.length && <p className="empty">No devices yet. Run a scan to find everything on your network.</p>}
    </article>
  </div>;
}

function Devices({ devices, onSelect, onScan, busy }) {
  const [query, setQuery] = useState("");
  const filtered = devices.filter((d) => JSON.stringify(d).toLowerCase().includes(query.toLowerCase()));
  const pending = devices.filter((device) => device.is_authorized === 0).length;
  return <section>
    <div className="page-heading">
      <div><h1>Devices</h1><p className="subtle">{plural(devices.length, "device")} on your network{pending ? `, ${pending} waiting for your review` : ""}.</p></div>
      <button className="primary" onClick={onScan} disabled={busy}><Icon name="scan" />{busy ? "Scanning…" : "Scan network"}</button>
    </div>
    <div className="search"><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name, IP, MAC, vendor, or type…" aria-label="Search devices" /><span>{plural(filtered.length, "result")}</span></div>
    <article className="panel devices-panel full">
      <div className="list-head wide"><span>Device</span><span>Status</span><span>Trust</span><span>Last seen</span><span>Data, 24h</span></div>
      {filtered.map((device) => <DeviceRow key={device.id} device={device} onSelect={onSelect} showBandwidth />)}
      {!filtered.length && <p className="empty">No devices match “{query}”.</p>}
    </article>
  </section>;
}

function DeviceDrawer({ device, onClose, onUpdate }) {
  const [trust, setTrust] = useState(null);
  const [traffic, setTraffic] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [findings, setFindings] = useState([]);
  const [saved, setSaved] = useState("");
  const [habits, setHabits] = useState(null);
  useEffect(() => {
    if (!device) return;
    setSaved("");
    setHabits(null);
    api(`/devices/${device.id}/habits`).then((result) => setHabits(result?.status ? result : null)).catch(() => setHabits(null));
    api(`/devices/${device.id}/trust`).then(setTrust).catch(() => {});
    api(`/devices/${device.id}/traffic?limit=30`).then(setTraffic).catch(() => {});
    api(`/devices/${device.id}/policy`).then(setPolicy).catch(() => {});
    api(`/devices/${device.id}/findings`).then(setFindings).catch(() => {});
  }, [device]);
  if (!device) return null;
  const state = stateLabel(device);
  const changeState = async (next) => {
    const updated = await api(`/devices/${device.id}/authorization`, { method: "PATCH", body: JSON.stringify({ state: next }) });
    onUpdate(updated);
  };
  const savePolicy = async () => {
    setPolicy(await api(`/devices/${device.id}/policy`, { method: "PUT", body: JSON.stringify(policy) }));
    setSaved("Saved");
  };
  return <div className="drawer-backdrop" onClick={onClose}><aside className="drawer" role="dialog" aria-modal="true" aria-label={deviceName(device)} onClick={(e) => e.stopPropagation()}>
    <button className="close" onClick={onClose} aria-label="Close"><Icon name="close" /></button>
    <div className="drawer-head">
      <span className={`device-avatar large ${state.key}`}><DeviceIcon type={device.device_type} /></span>
      <div><h2>{deviceName(device)}</h2><p className="subtle">{deviceTypeLabel(device.device_type)} · {device.vendor || "Unknown maker"}{device.model ? ` ${device.model}` : ""}</p></div>
    </div>
    <dl className="facts">
      <div><dt>Status</dt><dd><span className={`status ${state.key}`}>{state.label}</span></dd></div>
      <div><dt>Trust score</dt><dd className={`${tone(device.trust_score)}-text`}>{device.trust_score} / 100</dd></div>
      <div><dt>IP address</dt><dd className="mono">{device.ip}</dd></div>
      <div><dt>Hardware address</dt><dd className="mono">{device.mac}</dd></div>
      <div><dt>Identification</dt><dd>{Math.round((device.fingerprint_confidence || 0) * 100)}% confident</dd></div>
      <div><dt>First seen</dt><dd>{timeAgo(device.first_seen)}</dd></div>
    </dl>
    <div className="drawer-actions"><button className="primary" onClick={() => changeState(1)}>Authorize</button><button className="danger-button" onClick={() => changeState(2)}>Block</button><button onClick={() => changeState(0)}>Reset</button></div>
    {habits && <section className="habits"><h3>Learned habits</h3>
      {habits.status === "ready"
        ? <><HabitProfile hours={habits.typical_active_hours} /><p className="subtle">{habits.last_explanation || "Home Radar knows when this device is usually active and will flag anything unusual."}</p></>
        : <p className="subtle">Still learning: {habits.samples ?? 0} of {habits.samples_needed ?? 48} hours observed. Home Radar learns each device's normal routine before judging it.</p>}
    </section>}
    <section><h3>Why this trust score</h3>{trust?.reasons?.length ? <ul className="reasons">{trust.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p className="subtle">{trust ? "No notable signals yet." : "Calculating…"}</p>}</section>
    {policy && <section><h3>Internet access</h3>
      <label className="toggle-row"><span><b>Allow internet</b><small>Turn off to pause this device's internet lookups.</small></span><input type="checkbox" checked={policy.internet_enabled} onChange={(e) => setPolicy({ ...policy, internet_enabled: e.target.checked })} /></label>
      <div className="policy-times"><label><span>Quiet hours from</span><input type="time" value={policy.block_start || ""} onChange={(e) => setPolicy({ ...policy, block_start: e.target.value || null })} /></label><label><span>Until</span><input type="time" value={policy.block_end || ""} onChange={(e) => setPolicy({ ...policy, block_end: e.target.value || null })} /></label></div>
      <label className="field"><span>Blocked websites, separated by commas</span><input value={(policy.blocked_domains || []).join(", ")} onChange={(e) => setPolicy({ ...policy, blocked_domains: e.target.value.split(",").map((v) => v.trim()).filter(Boolean) })} placeholder="example.com, social.example" /></label>
      <div className="row-end"><span className="good-text">{saved}</span><button onClick={savePolicy}>Save</button></div>
    </section>}
    <section><h3>Exposure check</h3>{findings.map((finding) => <div className={`finding ${finding.severity}`} key={finding.id}><b>{finding.title}</b><p>{finding.description}</p><small>{finding.recommendation}</small></div>)}{!findings.length && <p className="subtle">Nothing risky found on this device.</p>}</section>
    <section><h3>Recent websites</h3>{traffic.slice(0, 8).map((item) => <p className="traffic-line" key={item.id}><span className="mono">{item.domain || item.dest_ip}</span><b className={item.was_blocked ? "danger-text" : "subtle"}>{item.was_blocked ? "Blocked" : "Allowed"}</b></p>)}{!traffic.length && <p className="subtle">No activity recorded yet.</p>}</section>
  </aside></div>;
}

function Traffic({ traffic }) {
  const kilobytes = Math.round(((traffic.bytes_sent || 0) + (traffic.bytes_received || 0)) / 1024);
  return <section>
    <div className="page-heading"><div><h1>Traffic</h1><p className="subtle">Which websites your devices look up, and what Home Radar stopped.</p></div></div>
    <section className="summary compact" aria-label="Traffic summary">
      <div className="fact"><b>{traffic.queries || 0}</b><span>lookups in the last 24 hours</span></div>
      <div className="fact"><b className="warn-text">{traffic.blocked || 0}</b><span>blocked threats and trackers</span></div>
      <div className="fact"><b>{kilobytes} KB</b><span>of traffic observed</span></div>
    </section>
    <div className="overview-columns">
      <article className="panel"><header><h2>Requests by hour</h2></header><ActivityChart timeline={traffic.timeline} /><p className="legend"><span><i className="key" />Requests</span><span><i className="key blocked" />Blocked</span></p></article>
      <article className="panel"><header><h2>Most visited</h2></header>
        <ol className="ranking">{(traffic.top_domains || []).map((item) => <li key={item.domain}><span className="mono">{item.domain}</span><b>{item.count}</b></li>)}</ol>
        {!traffic.top_domains?.length && <p className="empty">This fills in once devices use Home Radar for their internet lookups.</p>}
      </article>
    </div>
  </section>;
}

function Alerts({ alerts, onResolve, onAlertAction, freshAlertIds = new Set() }) {
  return <section>
    <div className="page-heading"><div><h1>Alerts</h1><p className="subtle">Every alert explained in plain English, with a one-tap fix.</p></div></div>
    <div className="alert-list">
      {alerts.map((alert) => {
        const severity = severityInfo(alert.severity);
        return <article className={`alert-card ${severity.tone}${freshAlertIds.has(alert.id) ? " alert-new" : ""}`} key={alert.id}>
          <i className={`sev ${severity.tone}`} aria-hidden="true" />
          <div className="alert-body">
            <p className="alert-meta"><span className={`${severity.tone}-text`}>{severity.label}</span><SimulatedTag alert={alert} /><time dateTime={alert.created_at}>{new Date(alert.created_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</time></p>
            <h3>{alert.title}</h3>
            <AlertGuide alert={alert} onAct={onAlertAction} />
            <details className="alert-detail"><summary>Technical details</summary><p>{alert.description}</p></details>
          </div>
          <button className="resolve" onClick={() => onResolve(alert.id)}>Resolve</button>
        </article>;
      })}
      {!alerts.length && <div className="panel empty-state"><Icon name="shield" /><h2>All clear</h2><p className="subtle">No open alerts. Home Radar will let you know if anything changes.</p></div>}
    </div>
  </section>;
}

function ReportCard({ data, onClose }) {
  const { status = {}, devices = [], alerts = [], traffic = {} } = data;
  const [household, setHousehold] = useState("");
  useEffect(() => {
    let cancelled = false;
    api("/settings").then((result) => { if (!cancelled) setHousehold(result?.household_name || ""); }).catch(() => {});
    return () => { cancelled = true; };
  }, []);
  const score = status.security_score ?? 100;
  const grade = letterGrade(score);
  const pending = devices.filter((device) => device.is_authorized === 0).length;
  const tips = reportTips({ devices, alerts });
  const today = new Date().toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
  return <div className="report-backdrop" role="dialog" aria-modal="true" aria-labelledby="report-title">
    <article className="report">
      <div className="report-actions">
        <button className="primary" onClick={() => window.print()}>Print / Save as PDF</button>
        <button onClick={onClose}>Close</button>
      </div>
      <header className="report-head">
        <span className="brand-mark"><DeviceIcon name="radar" /></span>
        <div><p className="kicker">Home security report card</p><h1 id="report-title">{household || "Your household"}</h1><p className="subtle">{today}</p></div>
      </header>
      <section className="report-grade">
        <strong className={`${tone(score)}-text`}>{grade}</strong>
        <div><h2>{gradeVerdict(grade)}</h2><p>Security score {score} of 100</p></div>
      </section>
      <section className="report-stats">
        <div><strong>{status.device_count ?? devices.length}</strong><span>Devices protected</span></div>
        <div><strong>{pending}</strong><span>Need review</span></div>
        <div><strong>{traffic.blocked || 0}</strong><span>Threats blocked today</span></div>
        <div><strong>{alerts.length}</strong><span>Open alerts</span></div>
      </section>
      <section className="report-section">
        <h3>What needs attention</h3>
        {alerts.slice(0, 5).map((alert) => {
          const guide = explainAlert(alert);
          return <div className="report-alert" key={alert.id}><b>{alert.title}{guide.simulated ? " (simulated)" : ""}</b><p>{guide.meaning}</p><p><i>What to do:</i> {guide.action}</p></div>;
        })}
        {!alerts.length && <p>Nothing right now. Your network is quiet.</p>}
      </section>
      <section className="report-section">
        <h3>Your next 3 steps</h3>
        <ol>{tips.map((tip) => <li key={tip}>{tip}</li>)}</ol>
      </section>
      <section className="report-section">
        <h3>Devices on your network</h3>
        <table className="report-table">
          <thead><tr><th>Device</th><th>Type</th><th>Status</th><th>Trust</th></tr></thead>
          <tbody>{devices.map((device) => <tr key={device.id}><td>{deviceName(device)}</td><td>{deviceTypeLabel(device.device_type)}</td><td>{stateLabel(device).label}</td><td>{device.trust_score ?? "-"}</td></tr>)}</tbody>
        </table>
        {!devices.length && <p>No devices discovered yet. Run a scan first.</p>}
      </section>
      <footer className="report-foot">Generated by Home Radar, free and open-source home network security. Your network data stays on your own computer.</footer>
    </article>
  </div>;
}

function SetupWizard({ onComplete }) {
  const [step, setStep] = useState(0);
  const [form, setForm] = useState({ household_name: "My Home", digest_email: "", dns_upstream: "1.1.1.1", notifications_enabled: true });
  const [busy, setBusy] = useState(false);
  const finish = async () => {
    setBusy(true);
    try {
      await api("/setup", { method: "POST", body: JSON.stringify(form) });
      onComplete();
    } finally { setBusy(false); }
  };
  return <div className="setup-backdrop"><section className="setup" aria-labelledby="setup-title">
    <div className="setup-top"><span className="brand-mark"><DeviceIcon name="radar" /></span><span>Home Radar</span><span className="step-count">Step {step + 1} of 3</span></div>
    {step === 0 && <><h1 id="setup-title">Turn this machine into your network lookout.</h1><p className="subtle">Home Radar finds every device on your network, blocks dangerous websites, and explains anything that needs your attention. Everything stays on this computer.</p><label className="field"><span>What should we call this household?</span><input value={form.household_name} onChange={(e) => setForm({ ...form, household_name: e.target.value })} /></label></>}
    {step === 1 && <><h1 id="setup-title">Choose safe network defaults.</h1><p className="subtle">Allowed requests go to this upstream DNS service. You'll test one device before changing anything on your router.</p><label className="field"><span>Upstream DNS</span><input value={form.dns_upstream} onChange={(e) => setForm({ ...form, dns_upstream: e.target.value })} /></label><label className="field"><span>Weekly summary email (optional)</span><input type="email" value={form.digest_email} onChange={(e) => setForm({ ...form, digest_email: e.target.value })} placeholder="family@example.com" /></label></>}
    {step === 2 && <><h1 id="setup-title">Start with visibility, then activate DNS.</h1><ol className="setup-checks"><li>Open the dashboard and run a scan.</li><li>Point one device at Home Radar for DNS and make sure it works.</li><li>Then update your router so every device uses it.</li></ol><label className="toggle-row"><span><b>Browser notifications</b><small>Get a notification here when something needs you.</small></span><input type="checkbox" checked={form.notifications_enabled} onChange={(e) => setForm({ ...form, notifications_enabled: e.target.checked })} /></label></>}
    <footer>{step > 0 ? <button onClick={() => setStep(step - 1)}>Back</button> : <span />}{step < 2 ? <button className="primary" onClick={() => setStep(step + 1)} disabled={!form.household_name.trim()}>Continue</button> : <button className="primary" onClick={finish} disabled={busy}>{busy ? "Saving…" : "Open Home Radar"}</button>}</footer>
  </section></div>;
}

function Notice({ tone: kind = "info", text, detail }) {
  if (!text) return null;
  return <div className={`notice ${kind}`} role="status"><p>{text}</p>{detail && detail !== text && <details><summary>Details</summary><p className="mono">{detail}</p></details>}</div>;
}

function Settings({ onRefreshDashboard, onPlayDemoStory, demoStory = {} }) {
  const [form, setForm] = useState({});
  const [message, setMessage] = useState("");
  const [health, setHealth] = useState(null);
  const [backups, setBackups] = useState([]);
  const [pairing, setPairing] = useState(null); // {code, expiresAt}
  const [pairError, setPairError] = useState("");
  const [pairBusy, setPairBusy] = useState(false);
  const [regenMessage, setRegenMessage] = useState("");
  const [regenBusy, setRegenBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [blocklists, setBlocklists] = useState(null);
  const [blocklistBusy, setBlocklistBusy] = useState(false);
  const [blocklistError, setBlocklistError] = useState("");
  const [digestPreview, setDigestPreview] = useState(null);
  const [digestBusy, setDigestBusy] = useState(false);
  const [digestNotice, setDigestNotice] = useState(null);
  const [cisaQuery, setCisaQuery] = useState("");
  const [cisaResults, setCisaResults] = useState(null);
  const [cisaBusy, setCisaBusy] = useState(false);
  const [cisaUpdateBusy, setCisaUpdateBusy] = useState(false);
  const [cisaNotice, setCisaNotice] = useState(null);
  const [demoBusy, setDemoBusy] = useState("");
  const [demoMsg, setDemoMsg] = useState("");
  const refreshSystem = () => {
    api("/health").then(setHealth).catch(() => {});
    api("/backups").then((result) => setBackups(result?.backups || [])).catch(() => {});
    api("/blocklists").then(setBlocklists).catch(() => {});
  };
  useEffect(() => { api("/settings").then(setForm).catch(() => {}); refreshSystem(); }, []);

  const updateBlocklists = async () => {
    setBlocklistBusy(true);
    setBlocklistError("");
    try {
      setBlocklists(await api("/blocklists/update", { method: "POST" }));
    } catch (err) {
      setBlocklistError(err.message || "Update failed");
    } finally {
      setBlocklistBusy(false);
    }
  };
  const loadDigestPreview = async () => {
    try {
      setDigestPreview(await api("/digest/preview"));
    } catch (err) {
      setDigestNotice({ tone: "warn", text: friendlyError(err.message), detail: err.message });
    }
  };
  const sendDigest = async () => {
    setDigestBusy(true);
    setDigestNotice(null);
    try {
      await api("/digest/send", { method: "POST" });
      setDigestNotice({ tone: "good", text: "Sent. Check your inbox." });
    } catch (err) {
      setDigestNotice({ tone: "warn", text: friendlyError(err.message), detail: err.message });
    } finally {
      setDigestBusy(false);
    }
  };
  const searchCisa = async (event) => {
    event.preventDefault();
    setCisaBusy(true);
    try {
      setCisaResults(await api(`/threat-intel/cisa-kev?query=${encodeURIComponent(cisaQuery)}`));
    } catch (err) {
      setCisaResults([]);
    } finally {
      setCisaBusy(false);
    }
  };
  const updateCisa = async () => {
    setCisaUpdateBusy(true);
    setCisaNotice(null);
    try {
      const result = await api("/threat-intel/cisa-kev/update", { method: "POST" });
      setCisaNotice({ tone: "good", text: `Updated: ${Number(result.records || 0).toLocaleString()} known vulnerabilities on file.` });
    } catch (err) {
      setCisaNotice({ tone: "warn", text: friendlyError(err.message, "update"), detail: err.message });
    } finally {
      setCisaUpdateBusy(false);
    }
  };
  useEffect(() => {
    if (!pairing) return;
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [pairing]);
  const pairRemaining = pairing ? Math.max(0, Math.round((pairing.expiresAt - now) / 1000)) : 0;
  useEffect(() => { if (pairing && pairRemaining <= 0) setPairing(null); }, [pairRemaining, pairing]);
  const save = async (event) => {
    event.preventDefault();
    if (form.notifications_enabled && "Notification" in window && Notification.permission === "default") {
      await Notification.requestPermission();
    }
    setForm(await api("/settings", { method: "PATCH", body: JSON.stringify(form) }));
    setMessage("Saved");
  };
  const startPairing = async () => {
    setPairBusy(true);
    setPairError("");
    try {
      const result = await api("/pair/start", { method: "POST" });
      setPairing({ code: result.code, expiresAt: Date.now() + result.expires_in * 1000 });
    } catch (err) {
      setPairError(err.message);
    } finally {
      setPairBusy(false);
    }
  };
  const regenerateToken = async () => {
    setRegenBusy(true);
    setRegenMessage("");
    try {
      const result = await api("/pair/regenerate", { method: "POST" });
      setStoredToken(result.token);
      setRegenMessage("Token regenerated");
    } catch (err) {
      setRegenMessage(err.message);
    } finally {
      setRegenBusy(false);
    }
  };
  const simulateAttack = async (kind) => {
    setDemoBusy(kind);
    setDemoMsg("");
    try {
      await api("/demo/simulate-attack", { method: "POST", body: JSON.stringify({ kind }) });
      setDemoMsg("Alert triggered. Check Home or Alerts.");
      await onRefreshDashboard?.();
    } catch (err) {
      setDemoMsg(
        err.status === 404
          ? "Demo mode isn't enabled on this appliance. Set HOMERADAR_DEMO_MODE=true to turn it on."
          : `Error: ${err.message}`,
      );
    } finally {
      setDemoBusy("");
    }
  };
  const domainCount = blocklists?.domain_count || 0;
  const healthy = health?.status === "healthy";
  return <section className="settings">
    <div className="page-heading"><div><h1>Settings</h1><p className="subtle">Your household, protection, and this computer.</p></div></div>

    <div className="settings-group">
      <h2>Household</h2>
      <form className="panel settings-form" onSubmit={save}>
        <label className="field"><span>Household name</span><input value={form.household_name || ""} onChange={(e) => setForm({ ...form, household_name: e.target.value })} /></label>
        <label className="field"><span>Weekly summary email</span><input type="email" value={form.digest_email || ""} onChange={(e) => setForm({ ...form, digest_email: e.target.value })} placeholder="family@example.com" /></label>
        <label className="field"><span>Upstream DNS</span><input value={form.dns_upstream || ""} onChange={(e) => setForm({ ...form, dns_upstream: e.target.value })} /></label>
        <label className="toggle-row"><span><b>Browser notifications</b><small>Show alerts while this page is open.</small></span><input type="checkbox" checked={!!form.notifications_enabled} onChange={(e) => setForm({ ...form, notifications_enabled: e.target.checked })} /></label>
        <details className="advanced"><summary>Advanced: custom DNS records</summary>
          <label className="field"><span>Names Home Radar should answer itself (JSON)</span><textarea className="mono" value={form.custom_dns_records || "{}"} onChange={(e) => setForm({ ...form, custom_dns_records: e.target.value })} placeholder='{"printer.lan": "192.168.1.20"}' /></label>
        </details>
        <div className="row-end"><span className="good-text">{message}</span><button className="primary">Save settings</button></div>
      </form>
    </div>

    <div className="settings-group">
      <h2>Protection</h2>
      <div className="panel">
        <div className="setting-row">
          <div><b>Dangerous website blocklists</b><p className="subtle">{domainCount ? `Blocking ${domainCount.toLocaleString()} known malware, phishing, and tracking domains${blocklists?.sources?.length ? ` from ${plural(blocklists.sources.length, "source")}` : ""}.` : "Blocklists haven't downloaded yet."}</p></div>
          <button onClick={updateBlocklists} disabled={blocklistBusy}>{blocklistBusy ? "Updating…" : "Update now"}</button>
        </div>
        <Notice tone="warn" text={blocklistError && friendlyError(blocklistError, "update")} detail={blocklistError} />
        <div className="setting-row stacked">
          <div><b>Known exploited vulnerabilities</b><p className="subtle">Search the U.S. government's CISA list of security flaws attackers are actively using.</p></div>
          <form className="inline-form" onSubmit={searchCisa}>
            <input type="text" value={cisaQuery} onChange={(e) => setCisaQuery(e.target.value)} placeholder="Search a brand, product, or CVE" aria-label="Search known vulnerabilities" />
            <button type="submit" disabled={cisaBusy}>{cisaBusy ? "Searching…" : "Search"}</button>
            <button type="button" onClick={updateCisa} disabled={cisaUpdateBusy}>{cisaUpdateBusy ? "Updating…" : "Update list"}</button>
          </form>
          <Notice {...(cisaNotice || {})} />
          {cisaResults && <ul className="cve-list">{cisaResults.length === 0 ? <li className="subtle">No matches.</li> : cisaResults.map((result) => <li key={result.cve_id}><b className="mono">{result.cve_id}</b><span>{result.vendor_project} {result.product}</span><small>{result.vulnerability_name}</small></li>)}</ul>}
        </div>
      </div>
    </div>

    <div className="settings-group">
      <h2>Weekly summary email</h2>
      <div className="panel">
        <div className="setting-row">
          <div><b>Security summary</b><p className="subtle">A short weekly email: new devices, blocked threats, and one tip.</p></div>
          <div className="button-pair">{!digestPreview && <button onClick={loadDigestPreview}>Preview</button>}<button onClick={sendDigest} disabled={digestBusy}>{digestBusy ? "Sending…" : "Send now"}</button></div>
        </div>
        <Notice {...(digestNotice || {})} />
        {digestPreview && <div className="email-preview"><b>{digestPreview.subject}</b><pre>{digestPreview.body}</pre></div>}
      </div>
    </div>

    <div className="settings-group">
      <h2>Phones and tablets</h2>
      <div className="panel">
        <div className="setting-row">
          <div><b>Pair the mobile app</b><p className="subtle">Get a one-time code, then type it into the Home Radar app on your phone.</p></div>
          {pairing
            ? <div className="pairing-code-block"><strong className="pairing-code mono">{pairing.code}</strong><small>Expires in {pairRemaining}s</small></div>
            : <button onClick={startPairing} disabled={pairBusy}>{pairBusy ? "Generating…" : "Generate pairing code"}</button>}
        </div>
        {pairError && <Notice tone="warn" text={pairError} />}
        <div className="setting-row">
          <div><b>Sign out every phone</b><p className="subtle">Creates a new access token, so paired phones have to pair again.</p></div>
          <button onClick={regenerateToken} disabled={regenBusy}>{regenBusy ? "Regenerating…" : "Regenerate token"}</button>
        </div>
        {regenMessage && <Notice tone={regenMessage === "Token regenerated" ? "good" : "warn"} text={regenMessage} />}
      </div>
    </div>

    <div className="settings-group">
      <h2>This computer</h2>
      <div className="panel">
        <div className="setting-row">
          <div><b className={health ? (healthy ? "good-text" : "warn-text") : ""}>{health ? (healthy ? "Running normally" : "Needs attention") : "Checking…"}</b><p className="subtle">Database {health?.database || "…"} · {health ? `${health.disk.free_percent}% disk free` : "…"} · {plural(backups.length, "backup")} · DNS filtering {health?.dns?.enabled ? "on" : "off"}</p></div>
          <div className="button-pair"><button onClick={async () => { await api("/backups", { method: "POST" }); refreshSystem(); }}>Create backup</button>{backups[0] && <a className="button" href={`/backups/${backups[0].name}`}>Download latest</a>}</div>
        </div>
        {(health?.warnings || []).map((warning) => <Notice key={warning} tone="warn" text={warning} />)}
      </div>
    </div>

    <div className="settings-group">
      <h2>Presentation mode</h2>
      <div className="panel">
        <div className="setting-row stacked">
          <div><b>Demo scenarios</b><p className="subtle">Show how Home Radar reacts without real attack traffic. Every simulated event is labeled as simulated.</p></div>
          <div className="demo-actions">
            <button className="primary" onClick={() => onPlayDemoStory?.()} disabled={!!demoBusy || demoStory.running}><Icon name="play" />{demoStory.running ? "Demo story playing…" : "Play demo story"}</button>
            <button onClick={() => simulateAttack("deauth")} disabled={!!demoBusy}>{demoBusy === "deauth" ? "Triggering…" : "Simulate Wi-Fi deauth attack"}</button>
            <button onClick={() => simulateAttack("malicious_dns")} disabled={!!demoBusy}>{demoBusy === "malicious_dns" ? "Triggering…" : "Simulate malicious connection"}</button>
          </div>
          <p className="subtle small-note">The demo story opens Live view: a new device joins, then it contacts a malware server, then a Wi-Fi attack starts.</p>
          {demoMsg && <Notice tone={demoMsg.startsWith("Error") || demoMsg.startsWith("Demo mode") ? "warn" : "good"} text={demoMsg} />}
          {demoStory.message && <Notice tone="warn" text={demoStory.message} />}
        </div>
      </div>
    </div>
  </section>;
}

export default function App() {
  const [page, setPage] = useState("Overview");
  const [data, setData] = useState({ status: {}, devices: [], alerts: undefined, traffic: {} });
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const [setupComplete, setSetupComplete] = useState(true);
  const [freshAlertIds, setFreshAlertIds] = useState(() => new Set());
  const [scanMessage, setScanMessage] = useState("");
  const [showReport, setShowReport] = useState(false);
  const [demoStory, setDemoStory] = useState({ running: false, step: 0, message: "" });
  const [liveEvent, setLiveEvent] = useState(null);
  const [demoKnownOff, setDemoKnownOff] = useState(false);
  const eventCounter = useRef(0);
  const storyTimer = useRef(null);
  const storyCancelled = useRef(false);
  useEffect(() => {
    storyCancelled.current = false;
    return () => { storyCancelled.current = true; clearTimeout(storyTimer.current); };
  }, []);
  useEffect(() => {
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
  }, [page]);
  const seenAlerts = useRef(new Set());
  const alertsInitialized = useRef(false);
  const load = () => api("/dashboard").then(setData).catch(() => setConnected(false));
  useEffect(() => {
    load();
    api("/setup").then((result) => setSetupComplete(result.complete)).catch(() => {});
    let socket;
    let retry;
    const connect = () => {
      socket = dashboardSocket((snapshot) => { setData((current) => ({ ...current, ...snapshot, status: { ...current.status, ...snapshot.status } })); setConnected(true); });
      socket.onclose = () => { setConnected(false); retry = setTimeout(connect, 2500); };
      socket.onerror = () => socket.close();
    };
    connect();
    return () => { clearTimeout(retry); socket?.close(); };
  }, []);
  useEffect(() => {
    if (!data.alerts) return; // still the pre-fetch placeholder, not real data yet
    const fresh = [];
    for (const alert of data.alerts) {
      if (alertsInitialized.current && !seenAlerts.current.has(alert.id)) {
        fresh.push(alert.id);
        if ("Notification" in window && Notification.permission === "granted") {
          new Notification(`Home Radar: ${alert.title}`, { body: alert.description || "Open the dashboard for details." });
        }
      }
      seenAlerts.current.add(alert.id);
    }
    alertsInitialized.current = true;
    if (!fresh.length) return;
    // Kept fresh for a fixed window (not "until the next snapshot arrives"):
    // the live websocket re-sends a full snapshot every ~3s even when nothing
    // changed, which would otherwise clear the highlight almost immediately.
    setFreshAlertIds((current) => new Set([...current, ...fresh]));
    const timer = setTimeout(() => {
      setFreshAlertIds((current) => {
        const next = new Set(current);
        fresh.forEach((id) => next.delete(id));
        return next;
      });
    }, 8000);
    return () => clearTimeout(timer);
  }, [data.alerts]);
  const scan = async () => {
    setBusy(true);
    setScanMessage("");
    try {
      const result = await api("/scan", { method: "POST" });
      const count = result?.devices_found ?? 0;
      setScanMessage(count > 0 ? `Scan complete. Found ${count} device${count === 1 ? "" : "s"}.` : "Scan complete. No devices responded. Check that this computer is on your home Wi-Fi or network cable.");
      await load();
    } catch (err) {
      setScanMessage(`Scan failed: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };
  const resolve = async (id) => { await api(`/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ resolved: true }) }); await load(); };
  const actOnAlertDevice = async (alert, state) => {
    try {
      await api(`/devices/${alert.device_id}/authorization`, { method: "PATCH", body: JSON.stringify({ state }) });
      await api(`/alerts/${alert.id}`, { method: "PATCH", body: JSON.stringify({ resolved: true }) });
    } finally {
      await load();
    }
  };
  // Throws on failure so the demo story can stop; single scenario clicks show the error inline.
  const runScenario = async (kind) => {
    eventCounter.current += 1;
    const id = eventCounter.current;
    setLiveEvent({ id, kind, pending: true });
    try {
      const result = await api("/demo/simulate-attack", { method: "POST", body: JSON.stringify({ kind }) });
      setLiveEvent({ id, kind, alert: result?.alert || null, device: result?.device || null, habits: result?.habits || null });
      await load();
    } catch (err) {
      if (err.status === 404) setDemoKnownOff(true);
      setLiveEvent({ id, kind, error: err.status === 404 ? "Demo mode isn't enabled on this appliance." : `That didn't work: ${err.message}` });
      throw err;
    }
  };
  const playDemoStory = async () => {
    if (demoStory.running) return;
    setPage("Live");
    setDemoStory({ running: true, step: 0, message: "" });
    try {
      for (let index = 0; index < DEMO_STORY.length; index += 1) {
        await new Promise((done) => { storyTimer.current = setTimeout(done, STORY_DELAYS[index]); });
        if (storyCancelled.current) return;
        setDemoStory({ running: true, step: index + 1, message: "" });
        await runScenario(DEMO_STORY[index]);
      }
      setDemoStory({ running: false, step: 0, message: "" });
    } catch (err) {
      setDemoStory({
        running: false,
        step: 0,
        message: err.status === 404
          ? "Demo story stopped: demo mode isn't enabled on this appliance."
          : `Demo story stopped: ${err.message}`,
      });
    }
  };
  const demoAvailable = typeof data.status?.demo_mode === "boolean" ? data.status.demo_mode : !demoKnownOff;
  const topbarMessage = demoStory.message || scanMessage;
  const blocklistCount = data.status?.blocklist_domains || 0;
  const alertCount = data.alerts?.length || 0;
  const navigate = (next) => { setPage(next); if (next !== "Live") setLiveEvent(null); };
  return <><div className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><DeviceIcon name="radar" /></span><strong>Home Radar</strong></div>
      <nav>{NAV.map((item) => <button className={page === item.id ? "active" : ""} aria-current={page === item.id ? "page" : undefined} onClick={() => navigate(item.id)} key={item.id}><Icon name={item.icon} /><span>{item.label}</span>{item.id === "Alerts" && alertCount > 0 && <b aria-label={`${alertCount} open`}>{alertCount}</b>}</button>)}</nav>
      <div className="appliance-status"><span><i className={connected ? "online" : ""} />{connected ? "Connected" : "Reconnecting…"}</span><small>{blocklistCount ? `Blocking ${blocklistCount.toLocaleString()} known bad domains` : "Loading blocklists…"}</small></div>
    </aside>
    <main><header className="topbar">
      <span className="topbar-brand"><span className="brand-mark"><DeviceIcon name="radar" /></span>Home Radar</span>
      <div className="topbar-actions">
        {demoStory.running && <span className="story-chip">Demo story · {demoStory.step}/{DEMO_STORY.length} · simulated</span>}
        {topbarMessage && <span className={`scan-result${topbarMessage.startsWith("Scan failed") || topbarMessage.startsWith("Demo story stopped") ? " danger-text" : ""}`} role="status">{topbarMessage}</span>}
        <button className="report-button" onClick={() => setShowReport(true)}>Report card</button>
        <button className="scan-mini" onClick={scan} disabled={busy}><Icon name="scan" />{busy ? "Scanning…" : "Run scan"}</button>
      </div>
    </header>
      <div className="content">
        {page === "Overview" && <Overview data={data} onNavigate={navigate} onSelect={setSelected} onOpenReport={() => setShowReport(true)} freshAlertIds={freshAlertIds} />}
        {page === "Live" && <LiveView data={data} event={liveEvent} story={demoStory} demoAvailable={demoAvailable} onRunScenario={(kind) => runScenario(kind).catch(() => {})} onPlayStory={playDemoStory} onAct={actOnAlertDevice} onSelect={setSelected} />}
        {page === "Devices" && <Devices devices={data.devices || []} onSelect={setSelected} onScan={scan} busy={busy} />}
        {page === "Traffic" && <Traffic traffic={data.traffic || {}} />}
        {page === "Alerts" && <Alerts alerts={data.alerts || []} onResolve={resolve} onAlertAction={actOnAlertDevice} freshAlertIds={freshAlertIds} />}
        {page === "Settings" && <Settings onRefreshDashboard={load} onPlayDemoStory={playDemoStory} demoStory={demoStory} />}
      </div>
    </main>
    <DeviceDrawer device={selected} onClose={() => setSelected(null)} onUpdate={(updated) => { setSelected(updated); load(); }} />
    {!setupComplete && <SetupWizard onComplete={() => setSetupComplete(true)} />}
  </div>
  {showReport && <ReportCard data={{ ...data, alerts: data.alerts || [] }} onClose={() => setShowReport(false)} />}
  </>;
}
