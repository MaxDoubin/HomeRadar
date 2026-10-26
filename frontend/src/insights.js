const GRADE_CUTOFFS = [
  [97, "A+"], [93, "A"], [90, "A-"],
  [87, "B+"], [83, "B"], [80, "B-"],
  [77, "C+"], [73, "C"], [70, "C-"],
  [67, "D+"], [63, "D"], [60, "D-"],
];

export function letterGrade(score) {
  const value = Number.isFinite(score) ? score : 100;
  for (const [cutoff, grade] of GRADE_CUTOFFS) {
    if (value >= cutoff) return grade;
  }
  return "F";
}

export function gradeVerdict(grade) {
  switch (grade[0]) {
    case "A": return "Your home network is in great shape.";
    case "B": return "Solid, with a few things worth reviewing.";
    case "C": return "Needs attention: a few risks to fix.";
    default: return "Action needed. Start with the alerts below.";
  }
}

const ALERT_GUIDES = [
  {
    kind: "new_device",
    match: /new device/i,
    meaning: "A device your family hasn't approved just joined your network. It could be a guest's phone or a new gadget, or someone who shouldn't be there.",
    action: "Recognize it? Mark it as yours. If not, block it and Home Radar cuts off its web access.",
  },
  {
    kind: "deauth",
    match: /deauth/i,
    meaning: "Someone nearby is sending signals that knock devices off your Wi-Fi. Attackers often do this first, to trick devices into reconnecting to a fake network.",
    action: "Use WPA3 (or WPA2) with a strong Wi-Fi password, and turn on \"Protected Management Frames\" in your router settings if it has them. That setting stops this attack.",
  },
  {
    kind: "malicious",
    match: /suspicious connection|malicious|threat/i,
    meaning: "One of your devices contacted an internet address that's on a known threat list. That can mean malware, a hacked smart gadget, or a dangerous ad.",
    action: "Block the device if you don't recognize this activity, then update it and run a malware scan.",
  },
  {
    kind: "blocked",
    match: /blocked dns request/i,
    meaning: "Home Radar stopped a device from reaching a website on a malware, phishing, or tracking blocklist. Nothing got through.",
    action: "No action needed. This is Home Radar doing its job.",
  },
  {
    kind: "anomaly",
    match: /anomaly|unusual/i,
    meaning: "This device is acting differently than it normally does, with far more traffic or far more websites than usual.",
    action: "Often harmless, like a big update or a new app. If it keeps happening or you don't recognize the device, block it.",
  },
  {
    kind: "exposure",
    match: /expos|open port|port scan/i,
    meaning: "A device on your network is reachable in a way that's riskier than it needs to be.",
    action: "Update the device and turn off features you don't use, like remote access.",
  },
];

const FALLBACK_GUIDE = {
  kind: "general",
  meaning: "Home Radar noticed something on your network worth a quick look.",
  action: "Check the details, then mark it resolved once you're comfortable.",
};

export function explainAlert(alert) {
  const title = alert?.title || "";
  const guide = ALERT_GUIDES.find((entry) => entry.match.test(title)) || FALLBACK_GUIDE;
  return {
    kind: guide.kind,
    meaning: guide.meaning,
    action: guide.action,
    simulated: /simulated/i.test(alert?.description || ""),
    canBlock: alert?.device_id != null && guide.kind !== "blocked" && guide.kind !== "deauth",
    canTrust: alert?.device_id != null && (guide.kind === "new_device" || guide.kind === "anomaly"),
  };
}

export function deviceTypeLabel(type) {
  const words = (type || "unknown").split("_").map((word) => ({ iot: "IoT", tv: "TV", nas: "NAS" }[word] || word));
  const label = words.join(" ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

export function deviceName(device) {
  return device?.hostname || device?.model || device?.vendor || "Unknown device";
}

// Non-breaking space keeps a number on the same line as its noun.
export function plural(count, word, pluralWord = `${word}s`) {
  return `${count}\u00a0${count === 1 ? word : pluralWord}`;
}

// What a chip maker's parts usually end up in. Phrased as a likelihood: a
// vendor prefix narrows the field, it doesn't identify the product.
const VENDOR_HINTS = [
  [/espressif/i, "Chips from this maker usually power smart plugs, bulbs, and other low-cost smart-home gadgets."],
  [/tuya/i, "This maker's modules usually power budget smart-home gadgets."],
  [/raspberry/i, "Usually a hobby computer someone in the house set up."],
  [/amazon/i, "Usually an Echo speaker, Fire TV, or Kindle."],
  [/apple/i, "Usually an iPhone, iPad, Mac, or Apple TV."],
  [/samsung|lg electronics|vizio|roku|tcl|hisense/i, "Usually a smart TV, streaming stick, or phone."],
  [/google|nest/i, "Usually a Nest speaker, display, camera, or Chromecast."],
  [/hikvision|dahua|wyze|reolink|ring/i, "Usually a security camera or video doorbell."],
  [/nintendo|sony|microsoft/i, "Usually a game console or controller."],
];

export function vendorHint(vendor) {
  const match = VENDOR_HINTS.find(([pattern]) => pattern.test(vendor || ""));
  return match ? match[1] : "";
}

export function overviewHeadline({ alerts = [], devices = [], score = 100 } = {}) {
  const threats = alerts.filter((alert) => alert.severity === "critical").length;
  const pending = devices.filter((device) => device.is_authorized === 0).length;
  const others = Math.max(0, alerts.length - threats);
  const strong = score >= 80;
  const lead = strong ? "Your home is protected." : "Home Radar is protecting your home.";
  if (threats) {
    return { tone: "danger", text: `Home Radar caught something. ${plural(threats, "alert needs", "alerts need")} you.` };
  }
  const review = pending || others;
  if (review) {
    const what = pending ? plural(pending, "device needs", "devices need") : plural(others, "alert needs", "alerts need");
    return { tone: "warn", text: `${lead} ${what} your review.` };
  }
  if (!strong) return { tone: "warn", text: `${lead} A few changes would make it safer.` };
  return { tone: "good", text: "Your home is protected. Nothing needs you right now." };
}

// Backend errors are written for developers. Turn the ones a household will
// actually hit into something calm, keeping the detail available.
export function friendlyError(message = "", context = "") {
  const text = String(message);
  if (/smtp|sender|recipient/i.test(text)) {
    return "Weekly email is off. Add your mail server to turn it on.";
  }
  if (/urlopen|ssl|certificate|timed out|timeout|network is unreachable|name or service|temporary failure|connection/i.test(text) || context === "update") {
    return "Couldn't update just now. Home Radar will retry automatically.";
  }
  return "Something went wrong. Try again in a moment.";
}

export function reportTips({ devices = [], alerts = [] } = {}) {
  const tips = [];
  const pending = devices.filter((device) => device.is_authorized === 0);
  if (pending.length) {
    tips.push(`Review ${pending.length} new device${pending.length === 1 ? "" : "s"}: mark the ones you recognize as trusted and block the rest.`);
  }
  const critical = alerts.filter((alert) => alert.severity === "critical");
  if (critical.length) {
    tips.push(`Handle ${critical.length} high-priority alert${critical.length === 1 ? "" : "s"} first. Each one comes with plain-English steps.`);
  }
  if (alerts.some((alert) => /deauth/i.test(alert.title || ""))) {
    tips.push("Turn on \"Protected Management Frames\" (PMF) in your router's Wi-Fi settings to stop knock-off-Wi-Fi attacks.");
  }
  const weakest = devices
    .filter((device) => device.is_authorized !== 2 && (device.trust_score ?? 100) < 60)
    .sort((a, b) => a.trust_score - b.trust_score)[0];
  if (weakest) {
    tips.push(`Check ${deviceName(weakest)}: its trust score is ${weakest.trust_score}/100. Update it, or block it if nobody uses it.`);
  }
  tips.push(
    "Change your router's admin password from the factory default and keep its firmware up to date.",
    "Put visitors and smart-home gadgets on a separate guest Wi-Fi network.",
    "Turn on automatic updates for phones, laptops, and smart TVs.",
  );
  return tips.slice(0, 3);
}
