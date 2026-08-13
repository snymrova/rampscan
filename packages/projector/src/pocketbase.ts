import type {
  CadenceGap,
  CoverageRow,
  DriftEvent,
  LedgerEntry,
  Projection,
  RegisterRow,
  RollupRow,
} from "@rampscan/core";

// PocketBase as projection store (SPEC §6, plan M3 E1). The rules that keep
// the choice safe are enforced here, not remembered:
//
//   1. The projector is the ONLY writer of projection collections — their
//      createRule/updateRule/deleteRule are null (superuser only), and this
//      module authenticates as the superuser identity `rampscan serve` owns.
//      Console writes (proposals) go to a separate, console-writable
//      collection and land in the LEDGER before they ever reach a register.
//   2. Every write is drop-and-refill (truncate → insert): the projection is
//      rebuildable, never merged. If PocketBase and the ledger disagree, the
//      ledger wins by construction.
//
// The client is plain fetch against the v0.23+ collections API — no SDK
// dependency on the server side.

export class PocketBaseAdmin {
  private token = "";

  constructor(readonly url: string) {}

  async auth(email: string, password: string): Promise<void> {
    const res = await this.request("POST", "/api/collections/_superusers/auth-with-password", {
      identity: email,
      password,
    });
    this.token = (res as { token: string }).token;
  }

  async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = this.token;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(`${this.url}${path}`, {
      method,
      headers,
      body: body === undefined ? null : JSON.stringify(body),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`PocketBase ${method} ${path} → HTTP ${res.status}: ${detail.slice(0, 300)}`);
    }
    if (res.status === 204) return undefined;
    const text = await res.text();
    return text ? JSON.parse(text) : undefined;
  }

  async health(): Promise<boolean> {
    try {
      const res = await fetch(`${this.url}/api/health`);
      return res.ok;
    } catch {
      return false;
    }
  }

  async hasCollection(name: string): Promise<boolean> {
    try {
      await this.request("GET", `/api/collections/${name}`);
      return true;
    } catch {
      return false;
    }
  }

  async ensureCollection(spec: CollectionSpec): Promise<void> {
    if (await this.hasCollection(spec.name)) return;
    await this.request("POST", "/api/collections", spec);
  }

  async truncate(name: string): Promise<void> {
    await this.request("DELETE", `/api/collections/${name}/truncate`);
  }

  async create(collection: string, record: Record<string, unknown>): Promise<void> {
    await this.request("POST", `/api/collections/${collection}/records`, record);
  }

  async listAll(collection: string): Promise<Array<Record<string, unknown>>> {
    const items: Array<Record<string, unknown>> = [];
    for (let page = 1; ; page++) {
      const res = (await this.request(
        "GET",
        `/api/collections/${collection}/records?page=${page}&perPage=500&skipTotal=1`,
      )) as { items: Array<Record<string, unknown>> };
      items.push(...res.items);
      if (res.items.length < 500) return items;
    }
  }
}

export interface CollectionSpec {
  name: string;
  type: "base";
  fields: Array<Record<string, unknown>>;
  listRule: string | null;
  viewRule: string | null;
  createRule: string | null;
  updateRule: string | null;
  deleteRule: string | null;
}

const AUTHED = '@request.auth.id != ""';
const text = (name: string, required = false) => ({ name, type: "text", required });
const json = (name: string) => ({ name, type: "json", maxSize: 2_000_000 });

/** Projection collections: readable by any logged-in console user, writable only by the projector (superuser). */
export const PROJECTION_COLLECTIONS: CollectionSpec[] = [
  {
    name: "registers",
    type: "base",
    fields: [
      text("repo", true),
      text("recipe_id", true),
      json("ksi_ids"),
      json("control_ids"),
      text("state", true),
      text("cadence"),
      text("bundle_digest"),
      text("fresh_as_of"),
      text("commit_sha"),
      json("scoping"),
    ],
    listRule: AUTHED,
    viewRule: AUTHED,
    createRule: null,
    updateRule: null,
    deleteRule: null,
  },
  {
    name: "coverage",
    type: "base",
    fields: [
      text("repo", true),
      text("recipe_id", true),
      json("ksi_ids"),
      json("control_ids"),
      text("verdict", true),
      text("bundle_digest"),
      text("state", true),
      text("cause"),
      text("killing_commit"),
      text("fresh_as_of"),
    ],
    listRule: AUTHED,
    viewRule: AUTHED,
    createRule: null,
    updateRule: null,
    deleteRule: null,
  },
  {
    name: "drift",
    type: "base",
    fields: [
      text("at", true),
      text("repo", true),
      text("recipe_id", true),
      text("kind", true),
      text("cause"),
      text("killing_commit"),
      text("from_verdict"),
      text("to_verdict"),
      text("bundle_digest", true),
    ],
    listRule: AUTHED,
    viewRule: AUTHED,
    createRule: null,
    updateRule: null,
    deleteRule: null,
  },
  ...(["controls", "ksis"] as const).map(
    (name): CollectionSpec => ({
      name,
      type: "base",
      fields: [
        text("repo", true),
        text("rollup_id", true), // "id" collides with PocketBase's record id
        text("state", true),
        json("recipe_ids"),
        json("counts"),
      ],
      listRule: AUTHED,
      viewRule: AUTHED,
      createRule: null,
      updateRule: null,
      deleteRule: null,
    }),
  ),
  {
    name: "gaps",
    type: "base",
    fields: [
      text("repo", true),
      text("recipe_id", true),
      text("bundle_digest", true),
      text("gap_start", true),
      text("gap_end", true),
      { name: "duration_ms", type: "number", required: false },
      { name: "ongoing", type: "bool", required: false },
    ],
    listRule: AUTHED,
    viewRule: AUTHED,
    createRule: null,
    updateRule: null,
    deleteRule: null,
  },
  {
    name: "bundles",
    type: "base",
    fields: [text("digest", true), json("statement"), json("envelope"), text("appended_at")],
    listRule: AUTHED,
    viewRule: AUTHED,
    createRule: null,
    updateRule: null,
    deleteRule: null,
  },
  {
    name: "meta",
    type: "base",
    fields: [text("dataset_version"), text("projected_at", true), json("settings")],
    listRule: AUTHED,
    viewRule: AUTHED,
    createRule: null,
    updateRule: null,
    deleteRule: null,
  },
];

/**
 * The console-writable surface: notApplicable proposals. Any logged-in user
 * may draft one; nobody edits or deletes through the API except the approve
 * flow (superuser), which stamps the outcome after the LEDGER records it.
 */
export const PROPOSALS_COLLECTION: CollectionSpec = {
  name: "proposals",
  type: "base",
  fields: [
    text("repo", true),
    text("recipe_id", true),
    { name: "justification", type: "text", required: true, max: 4000 },
    { name: "status", type: "select", required: true, maxSelect: 1, values: ["pending", "approved", "rejected"] },
    text("proposed_by", true),
    text("decided_by"),
    text("scoping_digest"),
    { name: "created", type: "autodate", onCreate: true },
    { name: "updated", type: "autodate", onCreate: true, onUpdate: true },
  ],
  listRule: AUTHED,
  viewRule: AUTHED,
  createRule: `${AUTHED} && @request.body.status = "pending"`,
  updateRule: null,
  deleteRule: null,
};

/** Console settings the projector stamps into meta — written by one hand only. */
export interface ProjectionSettings {
  certClass: "b" | "c";
  /** how a reader reproduces the evidence, e.g. "pnpm rampscan scan <path>" */
  reproduceCommand: string;
}

export async function ensureProjectionCollections(pb: PocketBaseAdmin): Promise<void> {
  for (const spec of PROJECTION_COLLECTIONS) await pb.ensureCollection(spec);
}

/**
 * Drop-and-refill every projection collection from a fold + the ledger
 * entries backing it. Statements and envelopes ride along so the evidence
 * detail view can show artifacts, assertions, and the signature without
 * touching the ledger directory.
 */
export async function writeProjectionPocketBase(
  projection: Projection,
  entries: LedgerEntry[],
  pb: PocketBaseAdmin,
  settings: ProjectionSettings,
): Promise<void> {
  await ensureProjectionCollections(pb);
  for (const spec of PROJECTION_COLLECTIONS) await pb.truncate(spec.name);

  for (const row of projection.registers) {
    await pb.create("registers", {
      repo: row.repo,
      recipe_id: row.recipeId,
      ksi_ids: row.ksiIds,
      control_ids: row.controlIds,
      state: row.state,
      cadence: row.cadence ?? "",
      bundle_digest: row.bundleDigest ?? "",
      fresh_as_of: row.freshAsOf ?? "",
      commit_sha: row.commit ?? "",
      scoping: row.scoping ?? null,
    });
  }
  for (const row of projection.rows) {
    await pb.create("coverage", {
      repo: row.repo,
      recipe_id: row.recipeId,
      ksi_ids: row.ksiIds,
      control_ids: row.controlIds,
      verdict: row.verdict,
      bundle_digest: row.bundleDigest ?? "",
      state: row.status.state,
      cause: row.status.state === "dead" ? row.status.cause : "",
      killing_commit: row.status.state === "dead" ? (row.status.killingCommit ?? "") : "",
      fresh_as_of: row.freshAsOf ?? "",
    });
  }
  for (const event of projection.drift) {
    await pb.create("drift", {
      at: event.at,
      repo: event.repo,
      recipe_id: event.recipeId,
      kind: event.kind,
      cause: event.cause ?? "",
      killing_commit: event.killingCommit ?? "",
      from_verdict: event.from ?? "",
      to_verdict: event.to ?? "",
      bundle_digest: event.bundleDigest,
    });
  }
  for (const [collection, rollupRows] of [
    ["controls", projection.controls],
    ["ksis", projection.ksis],
  ] as const) {
    for (const row of rollupRows) {
      await pb.create(collection, {
        repo: row.repo,
        rollup_id: row.id,
        state: row.state,
        recipe_ids: row.recipeIds,
        counts: row.counts,
      });
    }
  }
  for (const gap of projection.gaps) {
    await pb.create("gaps", {
      repo: gap.repo,
      recipe_id: gap.recipeId,
      bundle_digest: gap.bundleDigest,
      gap_start: gap.start,
      gap_end: gap.end,
      duration_ms: gap.durationMs,
      ongoing: gap.ongoing,
    });
  }
  for (const entry of entries) {
    await pb.create("bundles", {
      digest: entry.digest,
      statement: entry.bundle,
      envelope: entry.envelope ?? null,
      appended_at: entry.appendedAt,
    });
  }
  await pb.create("meta", {
    dataset_version: projection.datasetVersion,
    projected_at: projection.projectedAt,
    settings,
  });
}

/** Read the stored projection back — `rampscan rebuild` compares this against a fresh fold. */
export async function readProjectionPocketBase(pb: PocketBaseAdmin): Promise<Projection> {
  const [registerRecords, coverageRecords, driftRecords, controlRecords, ksiRecords, gapRecords, metaRecords] =
    await Promise.all([
      pb.listAll("registers"),
      pb.listAll("coverage"),
      pb.listAll("drift"),
      pb.listAll("controls"),
      pb.listAll("ksis"),
      pb.listAll("gaps"),
      pb.listAll("meta"),
    ]);

  const registers: RegisterRow[] = registerRecords.map((r: any) => {
    const row: RegisterRow = {
      repo: r.repo,
      recipeId: r.recipe_id,
      ksiIds: r.ksi_ids ?? [],
      controlIds: r.control_ids ?? [],
      state: r.state,
    };
    if (r.cadence) row.cadence = r.cadence;
    if (r.bundle_digest) row.bundleDigest = r.bundle_digest;
    if (r.fresh_as_of) row.freshAsOf = r.fresh_as_of;
    if (r.commit_sha) row.commit = r.commit_sha;
    if (r.scoping) row.scoping = r.scoping;
    return row;
  });
  const rows: CoverageRow[] = coverageRecords.map((r: any) => {
    const row: CoverageRow = {
      repo: r.repo,
      recipeId: r.recipe_id,
      ksiIds: r.ksi_ids ?? [],
      controlIds: r.control_ids ?? [],
      verdict: r.verdict,
      status:
        r.state === "live"
          ? { state: "live" }
          : { state: "dead", cause: r.cause, ...(r.killing_commit ? { killingCommit: r.killing_commit } : {}) },
    };
    if (r.bundle_digest) row.bundleDigest = r.bundle_digest;
    if (r.fresh_as_of) row.freshAsOf = r.fresh_as_of;
    return row;
  });
  const drift: DriftEvent[] = driftRecords.map((r: any) => {
    const event: DriftEvent = {
      at: r.at,
      repo: r.repo,
      recipeId: r.recipe_id,
      kind: r.kind,
      bundleDigest: r.bundle_digest,
    };
    if (r.cause) event.cause = r.cause;
    if (r.killing_commit) event.killingCommit = r.killing_commit;
    if (r.from_verdict) event.from = r.from_verdict;
    if (r.to_verdict) event.to = r.to_verdict;
    return event;
  });
  const toRollup = (r: any): RollupRow => ({
    repo: r.repo,
    id: r.rollup_id,
    state: r.state,
    recipeIds: r.recipe_ids ?? [],
    counts: r.counts,
  });
  const gaps: CadenceGap[] = gapRecords.map((r: any) => ({
    repo: r.repo,
    recipeId: r.recipe_id,
    bundleDigest: r.bundle_digest,
    start: r.gap_start,
    end: r.gap_end,
    durationMs: r.duration_ms,
    ongoing: r.ongoing === true,
  }));
  const meta = metaRecords[0] as any;
  return {
    rows,
    registers,
    drift,
    controls: controlRecords.map(toRollup),
    ksis: ksiRecords.map(toRollup),
    gaps,
    datasetVersion: meta?.dataset_version ?? "",
    projectedAt: meta?.projected_at ?? "",
  };
}
