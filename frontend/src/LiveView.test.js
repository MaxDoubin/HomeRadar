import { describe, expect, it } from "vitest";
import { mapLabel } from "./LiveView";

describe("mapLabel", () => {
  it("turns hostname dashes into spaces", () => {
    expect(mapLabel({ hostname: "Moms-MacBook-Air" })).toBe("Moms MacBook Air");
    expect(mapLabel({ hostname: "living_room_tv" })).toBe("living room tv");
  });

  it("keeps real hyphenated words intact", () => {
    expect(mapLabel({ hostname: "Kitchen-Wi-Fi-Extender" })).toBe("Kitchen Wi-Fi Extender");
    expect(mapLabel({ hostname: "Kids-E-Reader" })).toBe("Kids E-Reader");
    expect(mapLabel({ hostname: "pi-hole-old" })).toBe("pi-hole old");
  });

  it("never rewrites friendly names, vendors, or non-hostname strings", () => {
    expect(mapLabel({ hostname: "Kids' tablet" })).toBe("Kids' tablet");
    expect(mapLabel({ hostname: null, vendor: "Wi-Fi Alliance" })).toBe("Wi-Fi Alliance");
    expect(mapLabel({ hostname: "router.lan" })).toBe("router.lan");
  });
});
