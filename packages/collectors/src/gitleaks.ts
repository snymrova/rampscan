import { readFile } from "node:fs/promises";
import { join, posix } from "node:path";
import { z } from "zod";
import type { Collector, CollectOutput } from "@rampscan/core";
import { makeFinding, sha256 } from "./support.js";
import { absentReason, resolveTool } from "./tools.js";

// gitleaks — secrets over the FULL git history (plan C2): a secret added and
// then removed is still burned, and still in the clone every developer holds.

const GitleaksLeak = z.object({
  RuleID: z.string(),
  Description: z.string(),
  File: z.string(),
  StartLine: z.number(),
  Commit: z.string(),
  Fingerprint: z.string().optional(),
});
const GitleaksReport = z.array(GitleaksLeak.passthrough());

export const gitleaks: Collector = {
  manifest: {
    name: "gitleaks",
    toolVersion: "resolved-at-run",
    recipes: ["no-secrets-in-history"],
  },

  async collect(ctx): Promise<CollectOutput> {
    const tool = await resolveTool("gitleaks", {
      args: ["version"],
      parse: (out) => out.split("\n")[0]!.trim(),
    });
    if (!tool) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: "absent",
        exitCode: -1,
        skipped: { reason: absentReason("gitleaks") },
      };
    }
    const version = tool.version;

    const reportPath = join(ctx.artifactDir, "gitleaks-report.json");
    const reportArg = posix.join(tool.mount(ctx.artifactDir, "rw"), "gitleaks-report.json");
    // `gitleaks git` scans committed history, not just the working tree.
    // --redact keeps secret values out of the evidence artifact.
    // Exit 1 means "leaks found" — that is a result, not an error.
    const cmd = ["git", "--no-banner", "--redact", "--report-format", "json", "--report-path", reportArg, tool.mount(ctx.workspace.root, "ro")];
    const { exitCode, stderr } = await tool.exec(cmd);
    if (exitCode !== 0 && exitCode !== 1) {
      return {
        findings: [],
        artifacts: [],
        observations: {},
        toolVersion: version,
        exitCode,
        skipped: { reason: `gitleaks failed (exit ${exitCode}, via ${tool.runtime}): ${stderr.slice(0, 300)}` },
      };
    }

    const raw = await readFile(reportPath, "utf8").catch(() => "[]"); // no report file ⇒ no leaks
    const leaks = GitleaksReport.parse(JSON.parse(raw));
    const rows = leaks.map((l) => ({
      rule_id: l.RuleID,
      description: l.Description,
      file: l.File,
      line: l.StartLine,
      commit: l.Commit,
    }));

    const provenance = { analyzer: "gitleaks", version, runId: ctx.runId };
    const findings = leaks.map((l) =>
      makeFinding(
        {
          variable: "secrets",
          anchorNode: l.File,
          // the leak lives at a commit, not necessarily at HEAD — anchor to what identifies it
          anchorContentHash: sha256(`${l.Commit}:${l.File}:${l.StartLine}`),
          signature: `${l.RuleID} ${l.Commit} ${l.StartLine}`,
          severity: "blocker",
          summary: `${l.Description} in ${l.File} (commit ${l.Commit.slice(0, 8)})`,
          failureScenario:
            "the credential is recoverable by anyone with a clone of the repository — including every past contributor and any leaked backup — and remains valid until rotated",
          evidence: [
            {
              kind: "counterexample",
              path: l.File,
              note: `rule ${l.RuleID}, line ${l.StartLine}, commit ${l.Commit} (value redacted)`,
            },
          ],
          reproduce: `gitleaks git --redact ${ctx.workspace.root}`,
          ksiIds: ["KSI-SVC-ASM", "KSI-SVC-SIN"],
          controlIds: ["ia-5.6", "sc-28"],
        },
        provenance,
      ),
    );

    return {
      findings,
      artifacts: [{ name: "gitleaks-report.json", path: reportPath }],
      observations: { "no-secrets-in-history": rows },
      // history-wide evidence: no path anchor — it is anchored to the commit itself
      anchors: { "no-secrets-in-history": [] },
      toolVersion: version,
      exitCode,
    };
  },
};
