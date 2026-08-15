"use client";

import { useState } from "react";
import { getPb } from "../lib/pb";
import { artifactTable, noTableReason, type ArtifactTable } from "../lib/artifacts";
import { DownloadButton } from "./DownloadButton";

// The artifact viewer (plan J4): what the tool actually said, beside the
// verdict it produced.
//
// The whole point of this component is the order of operations. It fetches
// `/api/artifact?digest=` — which resolved the digest against a SIGNED
// statement and re-hashed the bytes before serving them — and then RE-HASHES
// THEM AGAIN here, in the browser, with SubtleCrypto, against the digest the
// statement attests. Only then does it render a table.
//
// That second hash is not redundant. The evidence page tells its reader "don't
// trust this page — it renders a projection", and a table drawn from bytes
// this page merely received would be exactly the thing it warns about. After
// the check, the table is a rendering of bytes the READER'S OWN BROWSER
// confirmed are the attested ones.
//
// A refusal is an answer and is rendered as one: "not retained — the file of
// this name on disk is from a later run" is the common case on any machine
// where scans have run since, and it is louder here than a missing table.

type State =
  | { kind: "idle" }
  | { kind: "loading" }
  /** the server answered, and the answer is that there are no bytes */
  | { kind: "unavailable"; reason: string }
  /** something is wrong with the bytes themselves — never render these */
  | { kind: "refused"; reason: string }
  | { kind: "ready"; table: ArtifactTable | null; text: string; bytes: number };

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function ArtifactView({ name, digest }: { name: string; digest: string }) {
  const [state, setState] = useState<State>({ kind: "idle" });
  const [open, setOpen] = useState(false);

  async function load(): Promise<void> {
    setState({ kind: "loading" });
    try {
      const response = await fetch(`/api/artifact?digest=${encodeURIComponent(digest)}`, {
        headers: { Authorization: getPb().authStore.token },
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        setState({
          kind: "unavailable",
          reason: body?.error ?? `${response.status} ${response.statusText}`,
        });
        return;
      }
      const buffer = await response.arrayBuffer();
      // the reader's own check, against the digest the SIGNED statement
      // attests — not against anything this response claimed about itself
      const actual = await sha256Hex(buffer);
      if (actual !== digest) {
        setState({
          kind: "refused",
          reason: `the bytes served hash to ${actual.slice(0, 12)}…, not the attested ${digest.slice(0, 12)}… — refusing to render them`,
        });
        return;
      }
      const text = new TextDecoder().decode(buffer);
      let table: ArtifactTable | null = null;
      try {
        table = artifactTable(name, JSON.parse(text));
      } catch {
        table = null; // not JSON, or not JSON this viewer knows — raw it is
      }
      setState({ kind: "ready", table, text, bytes: buffer.byteLength });
    } catch (e) {
      setState({ kind: "refused", reason: e instanceof Error ? e.message : String(e) });
    }
  }

  function toggle(): void {
    const next = !open;
    setOpen(next);
    if (next && state.kind === "idle") void load();
  }

  return (
    <>
      <button className="btn" onClick={toggle} title={open ? "hide" : `render ${name}`}>
        {open ? "hide" : "view"}
      </button>{" "}
      <DownloadButton
        label="raw"
        url={`/api/artifact?digest=${encodeURIComponent(digest)}`}
        filename={name.split("/").pop() ?? name}
      />
      {open && (
        <div className="artifact-view">
          {state.kind === "loading" && <p className="muted">reading and re-hashing…</p>}
          {state.kind === "unavailable" && (
            <p className="muted">
              <strong>no bytes:</strong> {state.reason}
            </p>
          )}
          {state.kind === "refused" && (
            <p className="error">
              <strong>REFUSED —</strong> {state.reason}
            </p>
          )}
          {state.kind === "ready" && (
            <>
              <p className="muted artifact-verified">
                sha256 verified in this browser against the attested digest · {state.bytes} bytes
                {state.table && ` · ${state.table.total} row(s)`}
              </p>
              {state.table ? (
                <>
                  {state.table.note && <p className="muted">{state.table.note}</p>}
                  <div className="artifact-scroll">
                    <table className="reg subtable">
                      <thead>
                        <tr>
                          {state.table.columns.map((c) => (
                            <th key={c}>{c}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {state.table.rows.map((row, i) => (
                          <tr key={i}>
                            {row.map((cell, j) => (
                              <td key={j} className={j === 0 ? "mono" : "faint"}>
                                {cell}
                              </td>
                            ))}
                          </tr>
                        ))}
                        {state.table.rows.length === 0 && (
                          <tr>
                            <td className="empty" colSpan={state.table.columns.length}>
                              the tool recorded no rows — an empty artifact is a result, not a gap
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <>
                  <p className="muted">{noTableReason(name)}</p>
                  <pre className="raw">{state.text.slice(0, 4000)}</pre>
                </>
              )}
            </>
          )}
        </div>
      )}
    </>
  );
}
