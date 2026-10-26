import { describe, expect, it } from "vitest";
import { deviceTypeLabel, explainAlert, gradeVerdict, letterGrade, reportTips } from "./insights";

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
