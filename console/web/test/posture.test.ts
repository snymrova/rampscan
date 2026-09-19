import { describe, expect, it } from "vitest";
import { depthOf, railEntity } from "../lib/depth";
import { foldPosture, postureSentence, standingOf } from "../lib/posture";
import type { KsiCatalogRecord, MethodCellRecord, MethodRegisterRecord } from "../lib/types";

// The posture fold (U-R3, U-R4) and the depth rail's reading of a URL.

function ksi(id: string, theme: string, optional_at: string[] = []): KsiCatalogRecord {
  return {
    id,
    ksi: id,
    theme_key: theme,
    theme_name: `${theme} theme`,
    name: id,
    statement: null,
    controls: [],
    artifacts: [],
    optional_at,
  };
}

function reg(id: string, over: Partial<MethodRegisterRecord> & { states?: MethodCellRecord["state"][] }): MethodRegisterRecord {
  const { states = [], ...rest } = over;
  return {
    id,
    repo: "/r",
    ksi: id,
    methods: states.map((state, i) => ({ methodId: `m${i}`, state }) as MethodCellRecord),
    automated_methods: states.length,
    method_floor: 1,
    floor_met: null,
    fresh_as_of: "",
    stale_methods: 0,
    history_since: "",
    history_floor_months: null,
    history_met: null,
    history_lapse_at: "",
    artifacts: [],
    artifacts_present: 0,
    point_in_time_methods: 0,
    gap: "",
    ...rest,
  };
}

describe("standingOf — worst first (U-R4)", () => {
  it("takes the worst thing true of a KSI", () => {
    expect(standingOf(undefined)).toBe("none");
    expect(standingOf(reg("a", { states: [] , gap: "G1" }))).toBe("none");
    expect(standingOf(reg("a", { states: ["evidenced", "violated"], floor_met: true }))).toBe("violated");
    expect(standingOf(reg("a", { states: ["evidenced"], stale_methods: 1, floor_met: true }))).toBe("stale");
    expect(standingOf(reg("a", { states: ["unevidenced"], floor_met: false }))).toBe("short");
    expect(standingOf(reg("a", { states: ["evidenced"], floor_met: true }))).toBe("clear");
  });
});

describe("foldPosture", () => {
  const catalog = [
    ksi("KSI-AAA-ONE", "AAA"),
    ksi("KSI-AAA-TWO", "AAA"),
    ksi("KSI-BBB-ONE", "BBB"),
    ksi("KSI-BBB-TWO", "BBB"),
    ksi("KSI-BBB-OPT", "BBB", ["b"]),
  ];
  const registers = new Map([
    ["KSI-AAA-ONE", reg("KSI-AAA-ONE", { states: ["evidenced"], floor_met: true })],
    ["KSI-BBB-ONE", reg("KSI-BBB-ONE", { states: ["violated"], floor_met: true })],
    ["KSI-BBB-OPT", reg("KSI-BBB-OPT", { states: ["violated"] })],
  ]);
  const p = foldPosture(catalog, registers, (k) => k.optional_at.includes("b"));

  it("counts obliged indicators only, and the numeral is the board's own floor count", () => {
    expect(p.total).toBe(4);
    expect(p.floorMet).toBe(2);
    expect(p.counts).toEqual({ violated: 1, stale: 0, none: 2, short: 0, clear: 1 });
  });

  it("orders strata worst first and each stratum's KSIs worst first", () => {
    expect(p.strata.map((s) => s.key)).toEqual(["BBB", "AAA"]);
    expect(p.strata[0].ksis.map((k) => k.ksi)).toEqual(["KSI-BBB-ONE", "KSI-BBB-TWO"]);
    // the sum of the strata is the whole: nothing is counted twice or dropped
    const summed = p.strata.reduce((n, s) => n + s.total, 0);
    expect(summed).toBe(p.total);
  });

  it("says it in one sentence built from the same counts", () => {
    expect(postureSentence(p)).toBe(
      "2 of 4 obliged indicators meet the method floor · 1 has a violated check · 2 have no method at all.",
    );
    const clean = foldPosture([ksi("KSI-AAA-ONE", "AAA")], registers, () => false);
    expect(postureSentence(clean)).toBe("1 of 1 obliged indicators meet the method floor · none has a violated check.");
  });
});

describe("depthOf — where a URL sits on the rail", () => {
  const at = (url: string) => {
    const u = new URL(url, "http://x");
    return depthOf(u.pathname, u.searchParams);
  };
  it("places each entity URL at its level", () => {
    expect(at("/")).toEqual({ kind: "level", index: 0, entity: null });
    expect(at("/?theme=SCR")).toEqual({ kind: "level", index: 1, entity: "SCR" });
    expect(at("/?ksi=KSI-SCR-MON")).toEqual({ kind: "level", index: 2, entity: "KSI-SCR-MON" });
    expect(at("/ksi/KSI-SCR-MON")).toEqual({ kind: "level", index: 2, entity: "KSI-SCR-MON" });
    expect(at("/recipes?recipe=tests-in-ci&repo=%2Fr")).toEqual({ kind: "level", index: 3, entity: "tests-in-ci" });
    const d = "ab".repeat(32);
    expect(at(`/evidence/${d}`)).toEqual({ kind: "level", index: 4, entity: d });
    expect(at(`/artifacts/${d}`)).toEqual({ kind: "level", index: 5, entity: d });
  });
  it("reads the cross-cutting pages as lenses", () => {
    expect(at("/queue")).toEqual({ kind: "lens", lens: "Work" });
    expect(at("/clock")).toEqual({ kind: "lens", lens: "Time" });
    expect(at("/recipes")).toEqual({ kind: "lens", lens: "Record" });
    expect(at("/controls")).toEqual({ kind: "lens", lens: "Audit" });
    expect(at("/login")).toEqual({ kind: "none" });
  });
  it("shortens a digest and leaves an id whole", () => {
    expect(railEntity("ab".repeat(32))).toBe("abababababab…");
    expect(railEntity("KSI-SCR-MON")).toBe("KSI-SCR-MON");
  });
});
