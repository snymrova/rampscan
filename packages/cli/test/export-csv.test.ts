import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

// The register CSV (plan I3e), pinned in the mvx-twin / action-queue posture:
// this test loads the CONSOLE's copy by path (a workspace import would break
// `tsc --build`, and the console is not a workspace package). The exit test
// for Phase I3 is "exported row count equals the on-screen register", so the
// property under test is arithmetic as much as formatting.

interface ExportModule {
  csvCell(value: string): string;
  toCsv(headers: string[], rows: string[][]): string;
  registerCsv(rows: unknown[], foldedAt: string): string;
  rollupCsv(rows: unknown[], foldedAt: string): string;
  scopingCsv(rows: unknown[], foldedAt: string): string;
  csvFilename(view: string, foldedAt: string): string;
}

const consoleLib = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../console/web/lib/export.ts",
);

let csvCell: ExportModule["csvCell"];
let toCsv: ExportModule["toCsv"];
let registerCsv: ExportModule["registerCsv"];
let rollupCsv: ExportModule["rollupCsv"];
let scopingCsv: ExportModule["scopingCsv"];
let csvFilename: ExportModule["csvFilename"];

beforeAll(async () => {
  const mod = (await import(consoleLib)) as ExportModule;
  ({ csvCell, toCsv, registerCsv, rollupCsv, scopingCsv, csvFilename } = mod);
});

function registerRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "r1",
    repo: "fixtures/vulnerable-app",
    recipe_id: "lockfile-pinned-deps",
    ksi_ids: ["KSI-SCR-MIT"],
    control_ids: ["si-7.1", "sr-5"],
    state: "evidenced" as const,
    cadence: "continuous",
    bundle_digest: "a".repeat(64),
    fresh_as_of: "2026-08-15T09:00:00.000Z",
    commit_sha: "abc123",
    pointers: null,
    introduced_at: "",
    introducing_commit: "",
    scoping: null,
    ...overrides,
  };
}

describe("csv serialization", () => {
  it("quotes only what RFC 4180 requires, and doubles inner quotes", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell("has,comma")).toBe('"has,comma"');
    expect(csvCell('say "this"')).toBe('"say ""this"""');
    expect(csvCell("line\nbreak")).toBe('"line\nbreak"');
  });

  it("emits a header row plus exactly one row per record", () => {
    const csv = toCsv(["a", "b"], [["1", "2"], ["3", "4"]]);
    expect(csv.trimEnd().split("\r\n")).toEqual(["a,b", "1,2", "3,4"]);
  });
});

describe("registerCsv", () => {
  it("row count equals the rows handed in — the Phase I3 exit property", () => {
    const rows = [registerRow(), registerRow({ id: "r2", recipe_id: "tests-in-ci" })];
    const lines = registerCsv(rows, "2026-08-15T10:00:00.000Z").trimEnd().split("\r\n");
    expect(lines.length - 1).toBe(rows.length);
  });

  it("carries the fold instant on every row, so a lifted row still dates itself", () => {
    const csv = registerCsv([registerRow()], "2026-08-15T10:00:00.000Z");
    expect(csv.trimEnd().split("\r\n")[1]).toContain("2026-08-15T10:00:00.000Z");
  });

  it("renders a justification with commas and quotes without breaking the row", () => {
    const csv = registerCsv(
      [
        registerRow({
          state: "notApplicable",
          scoping: {
            digest: "b".repeat(64),
            justification: 'no container, and the "image" is a fiction',
            proposedBy: "viewer@rampscan.local",
            approvedBy: "approver@rampscan.local",
            timestamp: "2026-08-14T09:00:00.000Z",
          },
        }),
      ],
      "2026-08-15T10:00:00.000Z",
    );
    const lines = csv.trimEnd().split("\r\n");
    expect(lines.length).toBe(2); // header + one row, not split by the comma
    expect(lines[1]).toContain('"no container, and the ""image"" is a fiction"');
    expect(lines[1]).toContain("approver@rampscan.local");
  });

  it("flattens pointers into one readable cell", () => {
    const csv = registerCsv(
      [
        registerRow({
          state: "violated",
          pointers: [
            { check: "eval-call", file: "src/render.js", line: 12 },
            { call_path: "src/index.js » src/render.js" },
          ],
        }),
      ],
      "2026-08-15T10:00:00.000Z",
    );
    const row = csv.trimEnd().split("\r\n")[1]!;
    expect(row).toContain("eval-call src/render.js:12");
    expect(row).toContain("src/index.js » src/render.js");
  });
});

describe("rollupCsv", () => {
  it("carries the attributable counts and the recipes behind them", () => {
    const csv = rollupCsv(
      [
        {
          id: "c1",
          repo: "fixtures/vulnerable-app",
          rollup_id: "si-7.1",
          state: "violated" as const,
          recipe_ids: ["lockfile-pinned-deps", "ci-provenance-present"],
          counts: { evidenced: 1, violated: 1, unevidenced: 0, notApplicable: 0, total: 2 },
        },
      ],
      "2026-08-15T10:00:00.000Z",
    );
    const [header, row] = csv.trimEnd().split("\r\n");
    expect(header).toContain("mapped_recipes");
    expect(row).toContain("si-7.1,violated,2,1,1,0,0");
    expect(row).toContain("lockfile-pinned-deps; ci-provenance-present");
  });
});

describe("scopingCsv", () => {
  it("keeps rejected decisions, with the signature status the server checked", () => {
    const csv = scopingCsv(
      [
        {
          decision: "rejected" as const,
          repo: "fixtures/vulnerable-app",
          recipeId: "container-runs-nonroot",
          ksiIds: ["KSI-IAM-ELP"],
          controlIds: ["ac-6"],
          justification: "kept in scope",
          proposedBy: "viewer@rampscan.local",
          decidedBy: "approver@rampscan.local",
          timestamp: "2026-08-14T11:00:00.000Z",
          problems: [],
        },
      ],
      "2026-08-15T10:00:00.000Z",
    );
    const row = csv.trimEnd().split("\r\n")[1]!;
    expect(row).toContain("rejected");
    expect(row).toContain("container-runs-nonroot");
  });
});

describe("csvFilename", () => {
  it("dates the file with the same instant the rows carry", () => {
    expect(csvFilename("board", "2026-08-15T10:00:00.000Z")).toBe(
      "rampscan-board-2026-08-15T10-00-00-000Z.csv",
    );
  });
});

// the twin lives where the console imports it from
it("loads the console's own copy, not a duplicate", () => {
  expect(consoleLib).toContain(join("console", "web", "lib", "export.ts"));
});
