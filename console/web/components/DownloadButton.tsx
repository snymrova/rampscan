"use client";

import { useState } from "react";
import { getPb } from "../lib/pb";

// One download posture for the whole console (I3b, reused by I3e): every
// export route is auth-gated like every read, and a plain <a href> would
// arrive without the PocketBase token — so: authorized fetch → blob → save.
// Failures are shown next to the button, never swallowed.

export function DownloadButton({
  label,
  url,
  filename,
  disabled,
  note,
  className = "btn",
}: {
  label: string;
  url: string;
  /** when omitted, the server's Content-Disposition names the file */
  filename?: string;
  disabled?: boolean;
  /** shown after the button when it is disabled — say why, never just grey out */
  note?: string;
  className?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(url, {
        headers: { Authorization: getPb().authStore.token },
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? `${response.status} ${response.statusText}`);
      }
      const disposition = response.headers.get("content-disposition") ?? "";
      const served = /filename="([^"]+)"/.exec(disposition)?.[1];
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = filename ?? served ?? "rampscan-download";
      anchor.click();
      URL.revokeObjectURL(href);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <span onClick={(e) => e.stopPropagation()}>
      <button
        className={className}
        disabled={busy || disabled}
        onClick={download}
        title={busy ? "assembling…" : label}
      >
        {busy ? "…" : label}
      </button>
      {disabled && note && <span className="faint"> — {note}</span>}
      {error && <span className="error"> {error}</span>}
    </span>
  );
}
