import React, { useEffect, useState } from "react";
import { api } from "./api";
import { DeviceIcon, Icon } from "./icons";
import { formatClock, friendlyError, plural, vulnerabilitySummary } from "./insights";

export const BEDTIME_PRESET = { block_start: "21:00", block_end: "07:00" };

function bedtimeWindow(start, end) {
  const from = formatClock(start);
  const to = formatClock(end);
  return from && to ? `${from} to ${to}` : "";
}

function catalogDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function BedtimeCard({ bedtime, onOpenDevice }) {
  const devices = bedtime?.devices;
  return <article className="panel bedtime-card" data-testid="bedtime-card">
    <header><h2>Bedtime</h2></header>
    {!bedtime && <p className="empty">Checking schedules…</p>}
    {devices && !devices.length && <p className="empty">No bedtimes yet. Open a device to give it one, like 9:00 PM to 7:00 AM for a kid's tablet.</p>}
    {devices?.map((entry) => <button key={entry.device_id} className="bedtime-row" onClick={() => onOpenDevice?.(entry.device_id)}>
      <span className={`bedtime-icon${entry.active_now ? " active" : ""}`}><Icon name="moon" /></span>
      <span>
        <strong>{entry.name}</strong>
        <small className={entry.schedule_valid === false ? "warn-text" : ""}>{entry.summary}</small>
        {entry.internet_enabled !== false && entry.schedule_valid !== false && bedtimeWindow(entry.block_start, entry.block_end) && <small>Every night, {bedtimeWindow(entry.block_start, entry.block_end)}</small>}
      </span>
      {entry.active_now && <span className="status pending">Offline now</span>}
    </button>)}
  </article>;
}

export function SecurityChecksCard({ vulnerabilities, onRefresh }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const update = async () => {
    setBusy(true);
    setError("");
    try {
      await api("/threat-intel/cisa-kev/update", { method: "POST" });
      await onRefresh?.();
    } catch (err) {
      setError(err.message || friendlyError("", "update"));
    } finally {
      setBusy(false);
    }
  };
  const data = vulnerabilities;
  const matches = (data?.devices || []).filter((entry) => entry.status === "catalog_matches" && entry.kev_count > 0);
  return <article className="panel security-card" data-testid="security-checks">
    <header><h2>Security checks</h2></header>
    {!data && <p className="empty">Checking…</p>}
    {data?.status === "catalog_empty" && <>
      <p className="subtle">{data.message}</p>
      <div className="row-start"><button onClick={update} disabled={busy}>{busy ? "Updating…" : "Update catalog"}</button></div>
    </>}
    {data?.status === "ok" && <>
      <p className="subtle">
        {data.catalog_is_sample
          ? `Checked ${plural(data.devices?.length || 0, "device")} against a demo sample of ${plural(Number(data.catalog_size || 0), "entry", "entries")} from CISA's list of actively exploited vulnerabilities.`
          : `Checked ${plural(data.devices?.length || 0, "device")} against CISA's list of ${Number(data.catalog_size || 0).toLocaleString()} actively exploited vulnerabilities${catalogDate(data.catalog_updated_at) ? `, updated ${catalogDate(data.catalog_updated_at)}` : ""}.`}
      </p>
      {matches.map((entry) => <div className="vuln-row" key={entry.device_id}>
        <i className="sev warn" aria-hidden="true" />
        <span><strong>{entry.name}</strong><small>{vulnerabilitySummary(entry)} Keep its software up to date.</small></span>
      </div>)}
      {!matches.length && <p className="good-text check-line"><Icon name="check" />No matches for the makers Home Radar recognized.</p>}
      {data.catalog_is_sample && <div className="row-start"><button onClick={update} disabled={busy}>{busy ? "Updating…" : "Download the full catalog"}</button></div>}
    </>}
    {error && <p className="inline-error">{error}</p>}
  </article>;
}

const PERIODS = [{ hours: 24, label: "Last 24 hours" }, { hours: 168, label: "Last 7 days" }];

export function Privacy({ onNavigate, onOpenDevice }) {
  const [hours, setHours] = useState(24);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setError("");
    api(`/privacy/report?hours=${hours}`)
      .then((result) => { if (!cancelled) setReport(result); })
      .catch((err) => { if (!cancelled) { setReport(null); setError(err.message || "error"); } });
    return () => { cancelled = true; };
  }, [hours, attempt]);
  const totals = report?.totals || {};
  const companies = report?.top_companies || [];
  const devices = report?.devices || [];
  const period = hours === 24 ? "the last 24 hours" : "the last 7 days";
  return <section className="privacy" data-testid="privacy-page">
    <div className="page-heading">
      <div><h1>Who's tracking you?</h1><p className="subtle">The advertising and analytics companies your devices contact, from the website lookups Home Radar handles.</p></div>
      <div className="segmented" role="group" aria-label="Time period">
        {PERIODS.map((item) => <button key={item.hours} className={hours === item.hours ? "selected" : ""} aria-pressed={hours === item.hours} onClick={() => setHours(item.hours)}>{item.label}</button>)}
      </div>
    </div>
    {error && <div className="panel empty-state"><Icon name="privacy" /><h2>Couldn't load the report</h2><p className="subtle">Home Radar didn't answer. Check that it's running, then try again.</p><div className="row-center"><button onClick={() => setAttempt((value) => value + 1)}>Try again</button></div></div>}
    {!error && !report && <p className="empty">Loading…</p>}
    {report && !totals.dns_queries && <div className="panel empty-state"><Icon name="privacy" /><h2>Nothing to report yet</h2><p className="subtle">This fills in once your devices use Home Radar for their website lookups (DNS). The Settings page explains how to turn that on.</p></div>}
    {report && totals.dns_queries > 0 && <>
      <section className="summary compact" aria-label="Tracking summary">
        <div className="fact"><b>{Number(totals.tracker_requests || 0).toLocaleString()}</b><span>tracker requests</span></div>
        <div className="fact"><b>{totals.companies || 0}</b><span>{totals.companies === 1 ? "company" : "companies"} seen</span></div>
        <div className="fact"><b className="good-text">{Number(totals.blocked_requests || 0).toLocaleString()}</b><span>blocked by Home Radar</span></div>
      </section>
      {!totals.tracker_requests
        ? <div className="panel empty-state"><Icon name="shield" /><h2>No trackers seen</h2><p className="subtle">None of your devices contacted a known tracking company in {period}.</p></div>
        : <div className="overview-columns">
          <article className="panel">
            <header><h2>Top companies</h2></header>
            <ol className="company-list">{companies.map((company) => <li key={company.company}>
              <span><strong>{company.company}</strong><small>{company.category} · {plural(company.devices || 0, "device")}</small></span>
              <span className="company-count"><b>{Number(company.requests).toLocaleString()}</b><small>{company.blocked ? `${Number(company.blocked).toLocaleString()} blocked` : "none blocked"}</small></span>
            </li>)}</ol>
          </article>
          <article className="panel">
            <header><h2>By device</h2></header>
            {devices.map((device) => {
              const share = device.dns_queries ? Math.round((device.tracker_requests / device.dns_queries) * 100) : 0;
              return <button className="privacy-device" key={device.device_id} onClick={() => onOpenDevice?.(device.device_id)}>
                <span className="device-avatar"><DeviceIcon type={device.device_type} /></span>
                <span>
                  <strong>{device.name}</strong>
                  <small>{Number(device.tracker_requests).toLocaleString()} of {Number(device.dns_queries).toLocaleString()} lookups ({share}%) went to trackers</small>
                  <small className="company-chips">{(device.companies || []).slice(0, 3).map((company) => <span key={company.company}>{company.company}</span>)}</small>
                </span>
              </button>;
            })}
          </article>
        </div>}
    </>}
    <p className="footnote">Home Radar compares each website lookup against a hand-checked list of well-known advertising, analytics, and device-telemetry domains. The check happens on this computer; nothing is sent anywhere. {onNavigate && <button className="text-button" onClick={() => onNavigate("Traffic")}>See all website lookups</button>}</p>
  </section>;
}

export function DeviceBedtime({ device, policy, onPolicySaved }) {
  const [start, setStart] = useState(policy?.block_start || "");
  const [end, setEnd] = useState(policy?.block_end || "");
  const [status, setStatus] = useState(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setStart(policy?.block_start || "");
    setEnd(policy?.block_end || "");
  }, [policy?.block_start, policy?.block_end]);
  useEffect(() => {
    let cancelled = false;
    api("/bedtime").then((result) => {
      if (!cancelled) setStatus((result?.devices || []).find((entry) => entry.device_id === device.id) || null);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [device.id, policy?.block_start, policy?.block_end]);
  const save = async (next) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const saved = await api(`/devices/${device.id}/policy`, {
        method: "PUT",
        body: JSON.stringify({ ...policy, block_start: next.block_start || null, block_end: next.block_end || null }),
      });
      onPolicySaved?.(saved);
      setMessage(next.block_start ? `Bedtime saved: ${bedtimeWindow(next.block_start, next.block_end)}.` : "Bedtime turned off.");
    } catch (err) {
      setError(err.fields?.block_start || err.fields?.block_end || err.message || "Couldn't save the bedtime.");
    } finally {
      setBusy(false);
    }
  };
  const current = bedtimeWindow(policy?.block_start, policy?.block_end);
  return <section className="device-bedtime" data-testid="device-bedtime">
    <h3>Bedtime</h3>
    <p className="subtle">{current ? `Every night, ${current}.` : "Pause this device's internet every night, automatically."}{status?.summary && current ? ` ${status.summary}.` : ""}</p>
    <div className="policy-times">
      <label><span>Offline from</span><input type="time" aria-label="Bedtime starts" value={start} onChange={(e) => setStart(e.target.value)} /></label>
      <label><span>Back online at</span><input type="time" aria-label="Bedtime ends" value={end} onChange={(e) => setEnd(e.target.value)} /></label>
    </div>
    <div className="button-pair">
      <button onClick={() => { setStart(BEDTIME_PRESET.block_start); setEnd(BEDTIME_PRESET.block_end); }}>9 PM to 7 AM</button>
      <button className="primary" disabled={busy || !start || !end} onClick={() => save({ block_start: start, block_end: end })}>{busy ? "Saving…" : "Save bedtime"}</button>
      {current && <button disabled={busy} onClick={() => save({ block_start: null, block_end: null })}>Turn off</button>}
    </div>
    {message && <p className="good-text small-note">{message}</p>}
    {error && <p className="inline-error">{error}</p>}
  </section>;
}

export function DeviceVulnerabilities({ deviceId }) {
  const [result, setResult] = useState(null);
  useEffect(() => {
    let cancelled = false;
    setResult(null);
    api(`/devices/${deviceId}/vulnerabilities`).then((value) => { if (!cancelled) setResult(value); }).catch(() => { if (!cancelled) setResult({ status: "error" }); });
    return () => { cancelled = true; };
  }, [deviceId]);
  const entry = result?.device;
  return <section data-testid="device-vulnerabilities">
    <h3>Known vulnerabilities</h3>
    {!result && <p className="subtle">Checking…</p>}
    {result?.status === "error" && <p className="subtle">Couldn't run this check right now.</p>}
    {result?.status === "catalog_empty" && <p className="subtle">{result.message}</p>}
    {entry && <>
      <p className={entry.kev_count ? "warn-text" : "subtle"}>{vulnerabilitySummary(entry)}</p>
      {entry.kev_count > 0 && <p className="subtle small-note">That doesn't mean this device is affected. Keeping its software up to date is the fix.</p>}
      {entry.recent?.length > 0 && <ul className="cve-list compact">{entry.recent.map((item) => <li key={item.cve_id}>
        <b className="mono">{item.cve_id}</b>
        <span>{item.vulnerability_name}</span>
        <small>Added to CISA's list {catalogDate(item.date_added) || "recently"}{item.known_ransomware_use ? " · used in ransomware attacks" : ""}</small>
      </li>)}</ul>}
    </>}
  </section>;
}

export function DevicePrivacy({ deviceId }) {
  const [result, setResult] = useState(null);
  useEffect(() => {
    let cancelled = false;
    setResult(null);
    api(`/devices/${deviceId}/privacy?hours=24`).then((value) => { if (!cancelled) setResult(value); }).catch(() => { if (!cancelled) setResult({ error: true }); });
    return () => { cancelled = true; };
  }, [deviceId]);
  return <section data-testid="device-privacy">
    <h3>Tracking</h3>
    {!result && <p className="subtle">Checking…</p>}
    {result?.error && <p className="subtle">Couldn't load tracking data right now.</p>}
    {result && !result.error && !result.tracker_requests && <p className="subtle">{result.dns_queries ? "No tracking companies contacted in the last 24 hours." : "No website lookups recorded yet."}</p>}
    {result?.tracker_requests > 0 && <>
      <p className="subtle">{Number(result.tracker_requests).toLocaleString()} of {Number(result.dns_queries).toLocaleString()} website lookups in the last 24 hours went to tracking companies.</p>
      <ol className="ranking">{(result.companies || []).slice(0, 4).map((company) => <li key={company.company}><span>{company.company} <small className="subtle">· {company.category}</small></span><b>{company.requests}</b></li>)}</ol>
    </>}
  </section>;
}
