import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import {
  artifactHref,
  checkHref,
  controlHref,
  defaultRepo,
  evidenceHref,
  ksiHref,
  repoLabel,
  runHref,
  safeNext,
  withScope,
} from "../lib/links";

// U0 (docs/PLAN-CONSOLE-DEPTH.md, U-R1): one canonical URL per entity, built
// in one place. U1 and U3 move the KSI and the check to pages of their own;
// when they do, these expectations change and no page does.

describe("canonical entity URLs (U-R1)", () => {
  it("builds each entity's one URL, encoding what it carries", () => {
    expect(ksiHref("KSI-IAM-APM")).toBe("/?ksi=KSI-IAM-APM");
    expect(checkHref("no-critical-reachable-advisories", "/repos/a b")).toBe(
      "/recipes?repo=%2Frepos%2Fa+b&recipe=no-critical-reachable-advisories",
    );
    expect(evidenceHref("ab".repeat(32))).toBe(`/evidence/${"ab".repeat(32)}`);
    expect(artifactHref("cd".repeat(32))).toBe(`/artifacts/${"cd".repeat(32)}`);
    expect(controlHref("ac-2(1)")).toBe("/controls?reg=controls&id=ac-2%281%29");
    expect(runHref({ scan: "run-1", collector: "syft" })).toBe("/runs?scan=run-1&collector=syft");
    expect(runHref({ repo: "/r", collector: "syft" })).toBe("/runs?repo=%2Fr&collector=syft");
  });

  it("carries the repo scope onto a path, replacing a stale one and never on a foreign URL", () => {
    expect(withScope("/queue", "/r")).toBe("/queue?repo=%2Fr");
    expect(withScope("/queue", null)).toBe("/queue");
    expect(withScope("/runs?scan=x&repo=%2Fold", "/r")).toBe("/runs?scan=x&repo=%2Fr");
    expect(withScope("/?ksi=KSI-A", "/r")).toBe("/?ksi=KSI-A&repo=%2Fr");
  });
});

describe("repo display (U-R5)", () => {
  it("shows the basename; the full path stays for the title", () => {
    expect(repoLabel("/home/x/fixtures/bare-app")).toBe("bare-app");
    expect(repoLabel("/home/x/fixtures/bare-app/")).toBe("bare-app");
    expect(repoLabel("C:\\src\\app")).toBe("app");
    expect(repoLabel("plain")).toBe("plain");
  });

  it("defaults to the repo with the newest scan, not the first alphabetically", () => {
    const runs = [
      { repo: "/a/bare-app", run_timestamp: "2026-09-19T10:00:00Z" },
      { repo: "/a/vulnerable-app", run_timestamp: "2026-09-19T11:00:00Z" },
      { repo: "/a/bare-app", run_timestamp: "2026-09-19T09:00:00Z" },
    ];
    expect(defaultRepo(runs, ["/a/bare-app", "/a/vulnerable-app"])).toBe("/a/vulnerable-app");
    // no run recorded: the first known repo, and nothing when there is none
    expect(defaultRepo([], ["/b", "/a"])).toBe("/a");
    expect(defaultRepo([], [])).toBeNull();
  });
});

describe("the sign-in return (U0)", () => {
  it("returns only to a path on this console", () => {
    expect(safeNext("/recipes?repo=%2Fr")).toBe("/recipes?repo=%2Fr");
    expect(safeNext(null)).toBe("/");
    expect(safeNext("https://evil.test/")).toBe("/");
    expect(safeNext("//evil.test/")).toBe("/");
    expect(safeNext("/\\evil.test")).toBe("/");
    expect(safeNext("/login?next=%2F")).toBe("/");
  });
});

describe("no page hand-writes an entity URL (U-R1)", () => {
  const root = join(import.meta.dirname, "..");
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.tsx?$/.test(name)) files.push(path);
    }
  };
  for (const dir of ["app", "components", "lib"]) walk(join(root, dir));

  // a path literal that opens an entity route — `/evidence/…`, `/controls?…`
  const HAND_WRITTEN = /[`"'](\/(evidence|artifacts|ksi|check)\/|\/(controls|runs|recipes)\?|\/\?ksi=)/;

  it("finds every entity path inside lib/links.ts and nowhere else", () => {
    const offenders = files
      .filter((f) => !f.endsWith(join("lib", "links.ts")) && !f.includes(join("app", "api")))
      .flatMap((f) =>
        readFileSync(f, "utf8")
          .split("\n")
          .map((line, i) => ({ line, at: `${relative(root, f)}:${i + 1}` }))
          .filter(({ line }) => HAND_WRITTEN.test(line) && !line.trim().startsWith("//")),
      )
      .map(({ at, line }) => `${at}  ${line.trim()}`);
    expect(offenders).toEqual([]);
  });
});
