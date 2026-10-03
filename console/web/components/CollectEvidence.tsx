"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getPb } from "../lib/pb";
import { useRepoScope } from "../lib/scope";

// "Collect evidence" (docs/PLAN-CLOUD-RUNNER.md T4-1, T4-4): inside a KSI
// row's drawer, the pinned AWS recipes that evidence this KSI — runnable
// under the served repository's `aws` block, or manual with every reason
// beneath. One click mints a signed RunRequest (a read, single-key). If no
// sidecar is registered, the dialog shows the CloudShell paste instead.
// Nothing here executes anything; the runner does, in the client's account.

interface RecipeChoice {
  recipe_id: string;
  runnable: boolean;
  reasons: string[];
  has_assertions: boolean;
}

interface Listing {
  ksi: string;
  recipes: RecipeChoice[];
  registered_runners: number;
}

type Minted =
  | { kind: "requested"; nonce: string; digest: string; steps: string[][] }
  | { kind: "manual"; reasons: string[] };

export function CollectEvidence({ ksi }: { ksi: string }) {
  const { scoped } = useRepoScope();
  const [listing, setListing] = useState<Listing | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [minted, setMinted] = useState<(Minted & { recipe_id: string }) | null>(null);
  const [paste, setPaste] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/runs/request?ksi=${encodeURIComponent(ksi)}`, { headers: { Authorization: getPb().authStore.token } })
      .then(async (r) => {
        const body = (await r.json()) as Listing & { error?: string };
        if (cancelled) return;
        if (!r.ok) setError(body.error ?? `HTTP ${r.status}`);
        else setListing(body);
      })
      .catch((e: unknown) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
  }, [ksi]);

  async function collect(recipe_id: string) {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/runs/request", {
        method: "POST",
        headers: { "content-type": "application/json", Authorization: getPb().authStore.token },
        body: JSON.stringify({ recipe_id, ksi }),
      });
      const body = (await r.json()) as Minted & { error?: string };
      if (!r.ok && body.kind !== "manual") {
        setError(body.error ?? `HTTP ${r.status}`);
        return;
      }
      setMinted({ ...body, recipe_id });
      if (body.kind === "requested" && (listing?.registered_runners ?? 0) === 0) {
        const t = await fetch("/api/runs/token", {
          method: "POST",
          headers: { "content-type": "application/json", Authorization: getPb().authStore.token },
          body: JSON.stringify({ nonce: body.nonce }),
        });
        const tb = (await t.json()) as { command?: string; error?: string };
        setPaste(tb.command ?? tb.error ?? null);
      }
    } finally {
      setBusy(false);
    }
  }

  if (error && !listing) {
    // a repository with no `aws` block has no runner surface — say so, do not hide the section
    return (
      <p className="faint" style={{ margin: "6px 0" }} data-testid="collect-evidence">
        collect evidence: {error}
      </p>
    );
  }
  if (!listing) return null;
  if (listing.recipes.length === 0) {
    return (
      <p className="faint" style={{ margin: "6px 0" }} data-testid="collect-evidence">
        no pinned AWS recipe evidences this KSI — nothing a runner could collect for it
      </p>
    );
  }
  return (
    <div data-testid="collect-evidence" style={{ margin: "6px 0 8px" }}>
      <div className="muted" style={{ fontSize: 12.5 }}>
        collect evidence — a runner in the client's account runs the published recipe under a read-only role; the appliance judges the bytes.{" "}
        {listing.registered_runners > 0
          ? `${listing.registered_runners} registered runner(s) will pick the request up.`
          : "No runner is registered: the request is handed to you as a CloudShell paste."}
      </div>
      <ul style={{ margin: "4px 0", paddingLeft: 18 }}>
        {listing.recipes.map((r) => (
          <li key={r.recipe_id} style={{ fontSize: 12.5, margin: "2px 0" }}>
            <span className="mono">{r.recipe_id}</span>
            {r.has_assertions ? <span className="faint"> · judged by machine</span> : <span className="faint"> · collected, then judged</span>}{" "}
            {r.runnable ? (
              <button type="button" className="btn small" disabled={busy} onClick={() => collect(r.recipe_id)} data-testid={`collect-${r.recipe_id}`}>
                Collect evidence
              </button>
            ) : (
              <span className="faint">manual</span>
            )}
            {!r.runnable && (
              <ul style={{ paddingLeft: 16 }}>
                {r.reasons.map((reason) => (
                  <li key={reason} className="faint">
                    {reason}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
      {error && <p className="error">{error}</p>}
      {minted?.kind === "requested" && (
        <p className="muted" style={{ fontSize: 12.5 }} data-testid="collect-requested">
          requested {minted.recipe_id} — nonce <span className="mono">{minted.nonce.slice(0, 8)}…</span>, {minted.steps.length} step(s); signed into the ledger as{" "}
          {/* a request event, not a bundle: no /evidence page holds it; the Runs page does */}
          <span className="mono" data-entity="ledger" title={minted.digest}>
            {minted.digest.slice(0, 12)}…
          </span>
          . Watch it on the <Link href={scoped("/runs")}>Runs page</Link>.
        </p>
      )}
      {minted?.kind === "manual" && (
        <p className="muted" style={{ fontSize: 12.5 }}>
          not runnable now: {minted.reasons.join("; ")}
        </p>
      )}
      {paste && (
        <div data-testid="collect-paste">
          <div className="muted" style={{ fontSize: 12.5 }}>
            paste this in AWS CloudShell in the account to collect — one run, one token, an ephemeral key; the transcript comes back here:
          </div>
          <pre className="mono" style={{ fontSize: 11.5, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {paste}
          </pre>
          <button type="button" className="btn small" onClick={() => navigator.clipboard?.writeText(paste)}>
            Copy
          </button>
        </div>
      )}
    </div>
  );
}
