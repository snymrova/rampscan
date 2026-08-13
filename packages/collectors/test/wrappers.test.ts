import { execSync } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { CollectContext } from "@rampscan/core";
import { finalBaseImage, gitleaks, normalizeSeverity, syft } from "../src/index.js";

// Wrapped-tool tests: pure helpers always run; spawn tests run only where the
// tool is installed (each collector's graceful-skip path covers the rest).

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const fixtureRoot = join(repoRoot, "fixtures/vulnerable-app");

function installed(tool: string): boolean {
  try {
    execSync(`command -v ${tool}`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

async function ctx(): Promise<CollectContext> {
  return {
    workspace: { root: fixtureRoot, repo: "fixtures/vulnerable-app", commit: "0".repeat(40) },
    artifactDir: await mkdtemp(join(tmpdir(), "rampscan-wrap-")),
    inputs: new Map(),
    runId: "test-run",
  };
}

// the fixture itself is built once for the whole run by vitest's globalSetup

describe("finalBaseImage", () => {
  it("takes the last FROM and strips the stage alias", () => {
    expect(finalBaseImage("FROM node:22 AS build\nFROM nginx:1.27\n")).toBe("nginx:1.27");
  });
  it("resolves a FROM that names an earlier stage", () => {
    expect(finalBaseImage("FROM node:16-alpine AS base\nFROM base\n")).toBe("node:16-alpine");
  });
  it("returns undefined for scratch", () => {
    expect(finalBaseImage("FROM scratch\n")).toBeUndefined();
  });
});

describe("normalizeSeverity", () => {
  it("maps CVSS scores to registers", () => {
    expect(normalizeSeverity("9.8")).toBe("CRITICAL");
    expect(normalizeSeverity("7.4")).toBe("HIGH");
    expect(normalizeSeverity("5.0")).toBe("MEDIUM");
    expect(normalizeSeverity("1.2")).toBe("LOW");
  });
  it("falls back to the database word", () => {
    expect(normalizeSeverity(undefined, "moderate")).toBe("MEDIUM");
    expect(normalizeSeverity(undefined, undefined)).toBe("UNKNOWN");
  });
});

describe.skipIf(!installed("gitleaks"))("gitleaks on the fixture", () => {
  it("finds the secret that lives only in history", async () => {
    const out = await gitleaks.collect(await ctx());
    expect(out.skipped).toBeUndefined();
    const rows = out.observations["no-secrets-in-history"]!;
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.some((r) => String(r["file"]).includes("config/.env"))).toBe(true);
    expect(out.findings.length).toBe(rows.length);
    expect(out.findings[0]!.severity).toBe("blocker");
    // redaction: no secret material in the observation rows
    expect(JSON.stringify(rows)).not.toContain("wJalrXUtnFEMI");
  }, 120_000);
});

describe.skipIf(!installed("syft"))("syft on the fixture", () => {
  it("produces a CycloneDX SBOM naming the vulnerable dependency", async () => {
    const out = await syft.collect(await ctx());
    expect(out.skipped).toBeUndefined();
    const row = out.observations["sbom-exists-and-fresh"]![0]!;
    expect(row["format"]).toBe("CycloneDX");
    expect(row["component_count"]).toBeGreaterThanOrEqual(1);
    expect(out.artifacts.map((a) => a.name)).toContain("sbom.cdx.json");
  }, 120_000);
});
