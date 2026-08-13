// Record shapes as the projector writes them (packages/projector/src/pocketbase.ts).
// The projection is the only source — these types mirror, never invent.

export type RegisterState = "evidenced" | "violated" | "unevidenced" | "notApplicable";

export interface ScopingInfo {
  digest: string;
  justification: string;
  proposedBy: string;
  approvedBy: string;
  timestamp: string;
}

export interface RegisterRecord {
  id: string;
  repo: string;
  recipe_id: string;
  ksi_ids: string[];
  control_ids: string[];
  state: RegisterState;
  cadence: string;
  bundle_digest: string;
  fresh_as_of: string;
  commit_sha: string;
  scoping: ScopingInfo | null;
}

export interface CoverageRecord {
  id: string;
  repo: string;
  recipe_id: string;
  ksi_ids: string[];
  control_ids: string[];
  verdict: string;
  bundle_digest: string;
  state: "live" | "dead";
  cause: string;
  killing_commit: string;
  fresh_as_of: string;
}

export interface DriftRecord {
  id: string;
  at: string;
  repo: string;
  recipe_id: string;
  kind: "born" | "died" | "verdict-flipped" | "scoped";
  cause: string;
  killing_commit: string;
  from_verdict: string;
  to_verdict: string;
  bundle_digest: string;
}

export interface BundleRecord {
  id: string;
  digest: string;
  statement: {
    _type: string;
    subject: Array<{ name: string; digest: Record<string, string> }>;
    predicateType: string;
    predicate: Record<string, unknown>;
  };
  envelope: {
    payload: string;
    payloadType: string;
    signatures: Array<{ keyid: string; sig: string }>;
  } | null;
  appended_at: string;
}

export interface MetaRecord {
  id: string;
  dataset_version: string;
  projected_at: string;
  settings: { certClass: "b" | "c"; reproduceCommand: string } | null;
}

export interface ProposalRecord {
  id: string;
  repo: string;
  recipe_id: string;
  justification: string;
  status: "pending" | "approved" | "rejected";
  proposed_by: string;
  decided_by: string;
  scoping_digest: string;
  created: string;
  updated: string;
}

/** KSI theme = the middle segment: KSI-SVC-CLS → SVC. */
export function ksiTheme(id: string): string {
  const parts = id.split("-");
  return parts.length >= 2 ? parts[1]! : id;
}

/** Control family = the leading alpha token: si-7.1 → si. */
export function controlFamily(id: string): string {
  const match = /^[a-z]+/i.exec(id);
  return match ? match[0]!.toLowerCase() : id;
}
