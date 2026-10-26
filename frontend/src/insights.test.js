import { describe, expect, it } from "vitest";
import { deviceTypeLabel, explainAlert, formatClock, friendlyError, gradeVerdict, letterGrade, overviewHeadline, plural, reportTips, vendorHint, vulnerabilitySummary } from "./insights";

describe("deviceTypeLabel", () => {
  it("formats device types for people, keeping acronyms intact", () => {
    expect(deviceTypeLabel("iot_camera")).toBe("IoT camera");
    expect(deviceTypeLabel("smart_tv")).toBe("Smart TV");
    expect(deviceTypeLabel(undefined)).toBe("Unknown");
  });
});

describe("letterGrade", () => {
  it.each([
    [100, "A+"], [97, "A+"], [96, "A"], [93, "A"], [92, "A-"], [90, "A-"],
    [89, "B+"], [85, "B"], [80, "B-"], [75, "C"], [70, "C-"], [65, "D"],
    [60, "D-"], [59, "F"], [0, "F"],
  ])("maps %i to %s", (score, grade) => {
    expect(letterGrade(score)).toBe(grade);
  });

  it("treats a missing score as a clean slate rather than failing", () => {
    expect(letterGrade(undefined)).toBe("A+");
  });

  it("gives every letter family a verdict", () => {
    expect(gradeVerdict("A-")).toMatch(/great shape/i);
    expect(gradeVerdict("B+")).toMatch(/reviewing/i);
    expect(gradeVerdict("C")).toMatch(/attention/i);
    expect(gradeVerdict("F")).toMatch(/action needed/i);
  });
});

describe("explainAlert", () => {
  it("explains a new device and offers both block and trust when it has a device", () => {
    const guide = explainAlert({ title: "New device connected", device_id: 4, description: "x" });
    expect(guide.kind).toBe("new_device");
    expect(guide.meaning).toMatch(/hasn't approved/i);
    expect(guide.canBlock).toBe(true);
    expect(guide.canTrust).toBe(true);
  });

  it("offers block but not trust for a malicious connection", () => {
    const guide = explainAlert({ title: "Suspicious connection: 203.0.113.9", device_id: 4 });
    expect(guide.kind).toBe("malicious");
    expect(guide.canBlock).toBe(true);
    expect(guide.canTrust).toBe(false);
  });

  it("never offers device actions for an over-the-air deauth attack", () => {
    const guide = explainAlert({ title: "Wi-Fi Deauthentication Attack Detected", device_id: 7 });
    expect(guide.kind).toBe("deauth");
    expect(guide.action).toMatch(/protected management frames/i);
    expect(guide.canBlock).toBe(false);
    expect(guide.canTrust).toBe(false);
  });

  it("flags demo-mode alerts as simulated", () => {
    expect(explainAlert({ title: "x", description: "(Simulated for demonstration.)" }).simulated).toBe(true);
    expect(explainAlert({ title: "x", description: "real" }).simulated).toBe(false);
  });

  it("falls back to a generic explanation for unknown alerts", () => {
    expect(explainAlert({ title: "Something odd" }).kind).toBe("general");
  });
});

describe("reportTips", () => {
  it("leads with the household's actual problems and always returns three steps", () => {
    const tips = reportTips({
      devices: [
        { id: 1, hostname: "cam", is_authorized: 0, trust_score: 40 },
        { id: 2, hostname: "laptop", is_authorized: 1, trust_score: 95 },
      ],
      alerts: [{ title: "Suspicious connection: 1.2.3.4", severity: "critical" }],
    });
    expect(tips).toHaveLength(3);
    expect(tips[0]).toMatch(/review 1 new device/i);
    expect(tips[1]).toMatch(/1 high-priority alert/i);
    expect(tips[2]).toMatch(/check cam/i);
  });

  it("falls back to general advice for a quiet network", () => {
    const tips = reportTips({ devices: [], alerts: [] });
    expect(tips).toHaveLength(3);
    expect(tips[0]).toMatch(/router's admin password/i);
  });
});

describe("copy helpers", () => {
  it("pluralizes counts", () => {
    expect(plural(1, "open alert")).toBe("1\u00a0open alert");
    expect(plural(2, "open alert")).toBe("2\u00a0open alerts");
    expect(plural(2, "device needs", "devices need")).toBe("2\u00a0devices need");
  });

  it("leads the overview with what actually needs attention", () => {
    expect(overviewHeadline({ alerts: [], devices: [] }).text).toMatch(/nothing needs you/i);
    expect(overviewHeadline({ alerts: [], devices: [{ is_authorized: 0 }] }).text).toMatch(/^your home is protected\. 1\sdevice needs your review/i);
    expect(overviewHeadline({ alerts: [], devices: [{ is_authorized: 0 }], score: 74 }).text).toMatch(/^home radar is protecting your home\. 1\sdevice needs/i);
    expect(overviewHeadline({ alerts: [{ severity: "critical" }], devices: [] }).tone).toBe("danger");
  });

  it("only hints at what a vendor's chips usually power", () => {
    expect(vendorHint("Espressif Inc.")).toMatch(/usually power smart plugs/i);
    expect(vendorHint("Unknown Co")).toBe("");
  });

  it("turns developer errors into calm household language", () => {
    expect(friendlyError("SMTP host, sender, and recipient must be configured")).toMatch(/weekly email is off/i);
    expect(friendlyError("<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED]>")).toMatch(/couldn't update just now/i);
  });
});

describe("formatClock", () => {
  it("turns 24-hour times into friendly 12-hour times", () => {
    expect(formatClock("21:00")).toBe("9:00 PM");
    expect(formatClock("07:00:00")).toBe("7:00 AM");
    expect(formatClock("00:30")).toBe("12:30 AM");
    expect(formatClock("12:05")).toBe("12:05 PM");
  });

  it("returns nothing for values that aren't times", () => {
    expect(formatClock("25:99")).toBe("");
    expect(formatClock(null)).toBe("");
  });
});

describe("vulnerabilitySummary", () => {
  it("talks about the maker's products, not this device", () => {
    const text = vulnerabilitySummary({ status: "catalog_matches", kev_count: 1, brand: "TP-Link", advice: "x" });
    expect(text).toBe("1 known exploited vulnerability affects products from TP-Link.");
    expect(text).not.toMatch(/your device/i);
  });

  it("falls back to the server's advice for everything else", () => {
    expect(vulnerabilitySummary({ status: "chip_maker", kev_count: 0, advice: "Espressif makes network chips." })).toBe("Espressif makes network chips.");
  });
});

describe("reportTips with household insights", () => {
  it("adds a real vulnerability step and a bedtime suggestion", () => {
    const tips = reportTips({
      devices: [{ id: 1, device_type: "tablet", is_authorized: 1, trust_score: 90, hostname: "Kids tablet" }],
      alerts: [],
      extras: {
        vulnerabilities: { devices: [{ name: "Router", status: "catalog_matches", kev_count: 2, brand: "NETGEAR" }] },
        bedtime: { devices: [] },
      },
    });
    expect(tips[0]).toMatch(/update router: 2 known exploited vulnerabilities affect products from NETGEAR/i);
    expect(tips.some((tip) => /set a bedtime/i.test(tip))).toBe(true);
  });
});

describe("overviewHeadline counts", () => {
  it("uses the real open-alert count, not just the critical ones", () => {
    const alerts = [{ severity: "critical" }, { severity: "warn" }, { severity: "warn" }];
    expect(overviewHeadline({ alerts, devices: [], openAlerts: 3 }).text).toMatch(/caught something\. 3\salerts need you/i);
    expect(overviewHeadline({ alerts: [{ severity: "warn" }], devices: [], openAlerts: 4 }).text).toMatch(/4\salerts need your review/i);
    expect(overviewHeadline({ alerts: [{ severity: "warn" }], devices: [{ is_authorized: 0 }] }).text).toMatch(/1\salert needs your review/i);
  });
});
