import { z } from "zod";
import { Automatable, PipelineRecipe } from "./recipe.js";

// ValidationMethod — the register's unit after the KSI pivot (SPEC §12.2).
//
// A method validates exactly ONE KSI: the (source artifact × KSI) pair, not
// the artifact. A recipe claiming two KSIs derives two methods. Every owed
// number is per-KSI — the FRC-CSX-VVK floor, the five artifacts, the
// FRC-CSX-MOT history meter — and keying the method the same way makes each
// of them a count/min over methods rather than a join with a correction
// factor.
//
// What the method deliberately does NOT carry (§12.2):
//   - No window, no floor. Those are owed-side data, read from the pinned
//     catalog at evaluation — storing them here would be typing a number the
//     rules JSON owns, and the number moves (RFC-0033).
//   - No controls[]. The crosswalk rides the KSI in the pinned dataset; the
//     method inherits it by its `ksi` key.
//   - No run-level provenance. Tool versions, config hash, commit live in the
//     signed bundle (invariant 8). Method provenance names the MECHANISM;
//     bundle provenance names the RUN.
//
// Methods are DERIVED, never authored. There is no methods table anyone
// edits: each method is a pure function of its source artifact —
// `methodsOfRecipe` below for the pipeline source, `methodOfIngestedBundle`
// below for the aws-ingested source (Q4.1, SPEC §12.8), and
// `methodOfAttestation` for the attestation source (Q4.2, SPEC §12.9). The
// register stays a derivation over things that are already reviewed
// artifacts, so computed-never-typed holds for the register itself.

export const MethodSource = z.enum(["pipeline", "aws-ingested", "attestation"]);
export type MethodSource = z.infer<typeof MethodSource>;

/**
 * Which cadence family owns this method: machine → VDR-TFR-MVX (7d/3d by
 * class); non-machine → VDR-TFR-NMV (3 months). Follows `automated` today,
 * but STORED, not derived at read time — same reason `automated` is.
 */
export const MethodClock = z.enum(["machine", "non-machine"]);
export type MethodClock = z.infer<typeof MethodClock>;

/**
 * What this method claims FOR THIS KSI. The same three values as the
 * recipe's `automatable`, by construction rather than coincidence: standing
 * inherits it uniformly at derivation, with a per-KSI override permitted
 * (`PipelineRecipe.per_ksi`) — "this recipe genuinely evidences KSI-SCR-MIT
 * but only gestures at KSI-CMT-xxx" is two methods with different standing,
 * not one method with a footnote.
 */
export const MethodStanding = Automatable;
export type MethodStanding = z.infer<typeof MethodStanding>;

/**
 * Scan scope as declared method provenance (SPEC §12.6, resolving #16).
 * "Should a checkout scan read gitignored paths?" has no repository-wide
 * answer because the honest answer is per-mechanism — so every collector
 * manifest declares, and every derived pipeline method inherits, this block.
 * A method that read gitignored paths says so; one that didn't says that.
 * Strict for the contract-rule reason: a misspelled scope field would change
 * what was declared while looking like a declaration.
 */
export const MethodScope = z.strictObject({
  /**
   * Did the walked set include artifacts produced during the scan (§5's
   * `built: true` outputs), or only what the pinned commit fetch presents?
   */
  population: z.enum(["checkout", "checkout+generated"]),
  /** did it read git history beyond the pinned commit (gitleaks: yes)? */
  history: z.boolean(),
  /**
   * The #16 axis: paths a .gitignore at the pinned commit masks — relevant
   * exactly when population is "checkout+generated", which is where ignored
   * build outputs come into existence mid-scan.
   */
  gitignored: z.enum(["excluded", "included"]),
});
export type MethodScope = z.infer<typeof MethodScope>;

// Per-source provenance. Strict, all three: provenance is what an assessor
// pulls on (FRR-PVA-AA-06), and a field that parses to nothing is a question
// the interrogation view can no longer answer.

export const PipelineProvenance = z.strictObject({
  recipe_id: z.string().min(1),
  /** the collector whose manifest declares the recipe — and the scope */
  collector: z.string().min(1),
  scope: MethodScope,
});
export type PipelineProvenance = z.infer<typeof PipelineProvenance>;

export const AwsIngestedProvenance = z.strictObject({
  /** upstream's recipe id — their names, not ours */
  recipe_id: z.string().min(1),
  signer_identity: z.string().min(1),
  ingest_digest: z.string().min(1),
});
export type AwsIngestedProvenance = z.infer<typeof AwsIngestedProvenance>;

export const AttestationProvenance = z.strictObject({
  attestor_role: z.string().min(1),
  /** the two-key identities live in the ledger event, not here */
  statement_ref: z.string().min(1),
});
export type AttestationProvenance = z.infer<typeof AttestationProvenance>;

/**
 * `automated` is the FRC-CSX-VVK numerator. It is fixed per source today
 * (pipeline, aws-ingested → true; attestation → false) but STORED, not
 * derived at read time: the numerator of a legal floor is asserted where an
 * assessor can see it, and a future source may not be uniform.
 */
const methodBase = {
  /** deterministic: `${source}:${source_ref}#${ksi}` — see `methodId` */
  id: z.string().min(1),
  /** exactly one KSI id, mnemonic form ("KSI-SCR-MIT") */
  ksi: z.string().min(1),
  automated: z.boolean(),
  clock: MethodClock,
  standing: MethodStanding,
};

export const PipelineMethod = z.strictObject({
  ...methodBase,
  source: z.literal("pipeline"),
  provenance: PipelineProvenance,
});
export type PipelineMethod = z.infer<typeof PipelineMethod>;

export const AwsIngestedMethod = z.strictObject({
  ...methodBase,
  source: z.literal("aws-ingested"),
  provenance: AwsIngestedProvenance,
});
export type AwsIngestedMethod = z.infer<typeof AwsIngestedMethod>;

export const AttestationMethod = z.strictObject({
  ...methodBase,
  source: z.literal("attestation"),
  provenance: AttestationProvenance,
});
export type AttestationMethod = z.infer<typeof AttestationMethod>;

/**
 * The discriminant is `source`, and the union is CLOSED — a fourth source is
 * a schema change with its own provenance block and its own `automated`
 * decision, never a string somebody types (the contract.ts `kind` rule,
 * applied to the register's own unit).
 */
export const ValidationMethod = z.discriminatedUnion("source", [
  PipelineMethod,
  AwsIngestedMethod,
  AttestationMethod,
]);
export type ValidationMethod = z.infer<typeof ValidationMethod>;

/**
 * The deterministic method id. `source_ref` is the source artifact's own id
 * (the recipe id for pipeline methods); the `#` fragment is the KSI, so the
 * id reads as "this mechanism, for this KSI" — which is exactly what the
 * bundle's `method_id` joins on.
 */
export function methodId(source: MethodSource, sourceRef: string, ksi: string): string {
  return `${source}:${sourceRef}#${ksi}`;
}

/**
 * The pipeline derivation: one method per claimed KSI, `source: pipeline`.
 * Pure over two reviewed artifacts — the recipe, and the scope block its
 * collector's manifest declares (§12.6). No recipe content changes under the
 * pivot; the recipe simply stops being the register's unit and becomes the
 * thing methods derive from.
 *
 * A `per_ksi` override naming a KSI the recipe does not claim is a REFUSAL,
 * not a skip — an override that silently applies to nothing is the same typo
 * class strict parsing exists for, one level up from the field names.
 */
export function methodsOfRecipe(recipe: PipelineRecipe, scope: MethodScope): PipelineMethod[] {
  for (const key of Object.keys(recipe.per_ksi ?? {})) {
    if (!recipe.ksi_ids.includes(key)) {
      throw new Error(
        `recipe ${recipe.id}: per_ksi override names ${key}, which is not in ksi_ids — ` +
          `an override that applies to nothing is a typo, not a preference`,
      );
    }
  }
  return recipe.ksi_ids.map((ksi) => ({
    id: methodId("pipeline", recipe.id, ksi),
    ksi,
    source: "pipeline" as const,
    automated: true,
    clock: "machine" as const,
    standing: recipe.per_ksi?.[ksi]?.automatable ?? recipe.automatable,
    provenance: {
      recipe_id: recipe.id,
      collector: recipe.collection.collector,
      scope,
    },
  }));
}

/**
 * The aws-ingested derivation (SPEC §12.8, Q4.1): an ingested bundle's
 * contract yields its method — a pure function of the SIGNED bundle, so the
 * aws-ingested register is recoverable from the ledger alone, exactly as
 * §12.2 promised. `automated: true` and `clock: "machine"` are fixed per
 * source (the client ran an automated recipe; a human statement takes the
 * attestation path, Q4.2), and `standing: "full"` is fixed the same way
 * today — a submission-declared standing is a future contract field, not a
 * default this function invents.
 *
 * Two refusals, both the contract-rule class: a bundle without the `ingest`
 * block is not an ingested bundle (deriving a method from it would fabricate
 * provenance), and a multi-KSI ingested bundle does not exist under the
 * contract — the submission carries exactly one `ksi`, so more than one here
 * means the bundle was not minted through it.
 */
export function methodOfIngestedBundle(predicate: {
  recipe_id: string;
  ksi_ids: string[];
  ingest?: { signer_identity: string; ingest_digest: string } | undefined;
}): AwsIngestedMethod {
  if (predicate.ingest === undefined) {
    throw new Error(
      `bundle for recipe ${predicate.recipe_id} carries no ingest block — ` +
        `a method derived from it would fabricate provenance`,
    );
  }
  const ksi = predicate.ksi_ids[0];
  if (ksi === undefined || predicate.ksi_ids.length !== 1) {
    throw new Error(
      `ingested bundle for recipe ${predicate.recipe_id} names ${predicate.ksi_ids.length} KSIs — ` +
        `the ingestion contract mints exactly one per submission (SPEC §12.8)`,
    );
  }
  return {
    id: methodId("aws-ingested", predicate.recipe_id, ksi),
    ksi,
    source: "aws-ingested" as const,
    automated: true,
    clock: "machine" as const,
    standing: "full" as const,
    provenance: {
      recipe_id: predicate.recipe_id,
      signer_identity: predicate.ingest.signer_identity,
      ingest_digest: predicate.ingest.ingest_digest,
    },
  };
}

/**
 * The attestation derivation (SPEC §12.9, Q4.2): a signed two-key attestation
 * yields its method — pure over the event, so the attestation register is
 * recoverable from the ledger alone, exactly as the other two legs are.
 *
 * All three fixed values are fixed per source, for the reason `automated` is
 * stored rather than derived at read time (§12.2): the numerator of a legal
 * floor is asserted where an assessor can see it.
 *
 *   - `automated: false` — and this is the anti-gaming property, not a
 *     demotion. `FRC-CSX-VVK` counts automated methods, so no number of
 *     attestations carries a KSI to a class's floor; inventing four roles to
 *     reach class d's ≥4 moves nothing. What an attestation does is end G1.
 *   - `clock: "non-machine"` — `VDR-TFR-NMV`'s 3 months, the clock this whole
 *     path exists to sit on. A standing claim nobody re-signed is G3.
 *   - `standing: "narrative"` — what a human statement claims for a KSI.
 *
 * `source_ref` is the `statement_id` (the MECHANISM), never the event digest:
 * the same programme re-signed each quarter must stay ONE method whose clock
 * is satisfied again, or the history key (G4) and every count would read a
 * renewal as a new mechanism.
 *
 * One refusal, the contract-rule class: a `withdrawn` attestation yields no
 * method. Deriving one would count a retracted claim — and the caller that
 * hands a withdrawn event here has skipped the supersession the fold does.
 */
export function methodOfAttestation(event: {
  subject: { digest: Record<string, string> }[];
  predicate: {
    action: "attested" | "withdrawn";
    statement_id: string;
    ksi_id: string;
    attestor_role: string;
  };
}): AttestationMethod {
  const p = event.predicate;
  if (p.action !== "attested") {
    throw new Error(
      `attestation ${p.statement_id}#${p.ksi_id} is ${p.action} — ` +
        `a method derived from it would count a retracted claim`,
    );
  }
  const statementRef = event.subject[0]?.digest.sha256;
  if (statementRef === undefined) {
    throw new Error(
      `attestation ${p.statement_id}#${p.ksi_id} carries no sha256 subject digest — ` +
        `its provenance could not cite the words that were signed`,
    );
  }
  return {
    id: methodId("attestation", p.statement_id, p.ksi_id),
    ksi: p.ksi_id,
    source: "attestation" as const,
    automated: false,
    clock: "non-machine" as const,
    standing: "narrative" as const,
    provenance: {
      attestor_role: p.attestor_role,
      statement_ref: statementRef,
    },
  };
}
