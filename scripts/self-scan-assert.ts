#!/usr/bin/env tsx
// The scheduled self-scan's coverage check (docs/PLAN-REACH.md N1-1), run by
// .github/workflows/scan.yml over the scan-result.json it just wrote.
//
//   pnpm exec tsx scripts/self-scan-assert.ts <scan-result.json> [--require-tools]
//
// Exit 1 when a registered collector neither ran nor was named as skipped,
// and — with --require-tools, the workflow's mode — when a collector skipped
// because its pinned tool could not be resolved. A tool absent in CI is a
// blocked coverage unit, printed, never a silent skip.
import { readFileSync } from "node:fs";
import { allCollectors } from "../packages/collectors/src/index.js";
import { assessSelfScan, renderSelfScanAssessment } from "../packages/cli/src/self-scan-assert.js";
import { ScanResult } from "../packages/schema/src/index.js";

const path = process.argv[2];
if (path === undefined) {
  console.error("usage: self-scan-assert.ts <scan-result.json> [--require-tools]");
  process.exit(2);
}
const requireTools = process.argv.includes("--require-tools");
const result = ScanResult.parse(JSON.parse(readFileSync(path, "utf8")));
const assessment = assessSelfScan(result, allCollectors, { requireTools });
console.log(renderSelfScanAssessment(assessment, requireTools));
process.exit(assessment.ok ? 0 : 1);
