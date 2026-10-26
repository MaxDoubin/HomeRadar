import React from "react";

const PATHS = {
  home: <><path d="M4 11.5 12 5l8 6.5"/><path d="M6.5 10v9h11v-9"/><path d="M10 19v-5h4v5"/></>,
  live: <><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1" fill="currentColor"/><path d="M12 12 17.5 6.5"/></>,
  devices: <><rect x="3.5" y="5" width="13" height="9" rx="1.5"/><path d="M7 18h6"/><rect x="17" y="9" width="4" height="9" rx="1"/></>,
  traffic: <><path d="M5 19V11M10 19V6M15 19v-5M20 19V9"/></>,
  alerts: <><path d="M18 9.5a6 6 0 0 0-12 0c0 6-2.5 7-2.5 7h17s-2.5-1-2.5-7"/><path d="M10.2 20a2 2 0 0 0 3.6 0"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></>,
  report: <><path d="M7 3.5h7l4 4V20a.5.5 0 0 1-.5.5h-10A.5.5 0 0 1 7 20Z"/><path d="M14 3.5V8h4M10 12h5M10 15.5h5"/></>,
  scan: <><path d="M4 12a8 8 0 0 1 13.7-5.6M20 12a8 8 0 0 1-13.7 5.6"/><path d="M18 3v4h-4M6 21v-4h4"/></>,
  shield: <><path d="M12 3.5 19 6v5.5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6Z"/><path d="m9 12 2.2 2.2L15.5 10"/></>,
  check: <><path d="m5 12.5 4.5 4.5L19 7.5"/></>,
  close: <><path d="M6 6l12 12M18 6 6 18"/></>,
  stop: <><circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/></>,
  play: <><path d="M8 5.5v13l10.5-6.5Z"/></>,
  wave: <><path d="M3 9.5c5-4.5 13-4.5 18 0M6 13c3.5-3 8.5-3 12 0M9.5 16.5c1.5-1.2 3.5-1.2 5 0"/><circle cx="12" cy="19.5" r=".8" fill="currentColor"/></>,
  arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
  privacy: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/></>,
  moon: <><path d="M19.5 14.5A7.5 7.5 0 0 1 9.5 4.5a7.5 7.5 0 1 0 10 10Z"/></>,
  internet: <><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.5 3.5 5.5 3.5 8.5s-1 6-3.5 8.5c-2.5-2.5-3.5-5.5-3.5-8.5s1-6 3.5-8.5Z"/></>,
};

export function Icon({ name, size }) {
  return <svg className="icon" viewBox="0 0 24 24" width={size} height={size} aria-hidden="true" focusable="false">{PATHS[name]}</svg>;
}

const DEVICE_PATHS = {
  phone: <><rect x="7" y="2.5" width="10" height="19" rx="2.2"/><path d="M11 18.5h2"/></>,
  tablet: <><rect x="4.5" y="3" width="15" height="18" rx="2"/><path d="M11 18h2"/></>,
  computer: <><rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2.5 19.5h19"/></>,
  server: <><rect x="4" y="4" width="16" height="6.5" rx="1.5"/><rect x="4" y="13.5" width="16" height="6.5" rx="1.5"/><path d="M7.5 7.25h.01M7.5 16.75h.01"/></>,
  router: <><rect x="3" y="12.5" width="18" height="7" rx="2"/><path d="M7 12.5 5.5 6M17 12.5 18.5 6M7 16h.01M10.5 16h.01"/></>,
  switch: <><rect x="3" y="8" width="18" height="8" rx="2"/><path d="M7 12h.01M10 12h.01M13 12h.01M16 12h.01"/></>,
  printer: <><path d="M7 8V3.5h10V8"/><rect x="3.5" y="8" width="17" height="8.5" rx="2"/><rect x="7" y="13.5" width="10" height="7" rx=".5"/></>,
  camera: <><circle cx="12" cy="10.5" r="6.5"/><circle cx="12" cy="10.5" r="2.5"/><path d="M8.5 20.5h7M12 17v3.5"/></>,
  tv: <><rect x="3" y="4.5" width="18" height="12" rx="1.5"/><path d="M8.5 20h7"/></>,
  console: <><path d="M7.5 8h9a4.5 4.5 0 0 1 4.3 5.8l-.9 3a2.3 2.3 0 0 1-4 .8L14.5 16h-5l-1.4 1.6a2.3 2.3 0 0 1-4-.8l-.9-3A4.5 4.5 0 0 1 7.5 8Z"/><path d="M8 11v3M6.5 12.5h3M15.5 12h.01M17 13.5h.01"/></>,
  speaker: <><rect x="6.5" y="2.5" width="11" height="19" rx="3"/><circle cx="12" cy="14.5" r="3"/><path d="M12 7h.01"/></>,
  chip: <><rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3.5V7M14 3.5V7M10 17v3.5M14 17v3.5M3.5 10H7M3.5 14H7M17 10h3.5M17 14h3.5"/></>,
  thermostat: <><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v4.5l3 2"/></>,
  watch: <><rect x="7" y="6.5" width="10" height="11" rx="3"/><path d="M9 6.5 9.5 3h5l.5 3.5M9 17.5l.5 3.5h5l.5-3.5"/></>,
  unknown: <><circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.4v.6"/><path d="M12 16.8h.01"/></>,
  radar: <><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1.2" fill="currentColor"/><path d="M12 12 17.5 6.5"/></>,
  internet: PATHS.internet,
};

const TYPE_TO_ICON = {
  phone: "phone", tablet: "tablet", computer: "computer", server: "server", nas: "server",
  media_server: "server", router: "router", access_point: "router", network_switch: "switch",
  printer: "printer", iot_camera: "camera", doorbell: "camera", smart_tv: "tv",
  streaming_device: "tv", game_console: "console", smart_speaker: "speaker",
  smart_home_hub: "chip", smart_plug: "chip", iot_device: "chip", thermostat: "thermostat",
  wearable: "watch", unknown: "unknown",
};

export function deviceIconName(type) {
  return TYPE_TO_ICON[type] || "unknown";
}

export function DeviceIcon({ type, name }) {
  const key = name || deviceIconName(type);
  return <svg className="icon device-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">{DEVICE_PATHS[key] || DEVICE_PATHS.unknown}</svg>;
}
