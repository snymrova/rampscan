// Pin drift (P1). Every pin in `pins.ts` is a decision taken against a file
// somebody else maintains, and the hard-fail on mismatch only fires once that
// file is IN this tree. Between an upstream release and the re-pin that reads
// it, nothing in this repository knows it is behind — the loaders are happy,
// the suite is green, and the only signal is a person remembering to look.
//
// So: one pure comparison, and one rendering of it. The scheduled job fetches
// upstream's `info.version` and calls this; it holds no logic of its own, which
// is why the same answer is reachable from a test and from the CLI. Nothing
// here fetches anything, and nothing here edits a pin: a drift notice is a
// notice. Bumping a pin stays a reviewed change (ground rule 2).

/** FedRAMP's own version shape, `YYYY.MM.DD.NN`, every field zero-padded */
const DATASET_VERSION = /^(\d{4})\.(\d{2})\.(\d{2})\.(\d{2})$/;

function parts(version: string): number[] {
  const m = DATASET_VERSION.exec(version);
  if (m === null) {
    throw new Error(
      `${JSON.stringify(version)} is not a dataset version (YYYY.MM.DD.NN) — refused rather than ordered, ` +
        "because a comparison that guesses reports clean while drifting",
    );
  }
  return m.slice(1).map((n) => Number(n));
}

/**
 * Negative when `a` is older, positive when newer, zero when the same. Field by
 * field rather than by string, so a release that drops a zero-pad fails the
 * parse instead of sorting into the wrong place.
 */
export function compareDatasetVersions(a: string, b: string): number {
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < x.length; i++) {
    if (x[i]! !== y[i]!) return x[i]! - y[i]!;
  }
  return 0;
}

export type PinDrift =
  /** upstream publishes exactly what this tree pins */
  | { kind: "current"; pin: string }
  /** upstream has published newer — the case the scheduled check exists for */
  | { kind: "behind"; pin: string; upstream: string }
  /**
   * The pin names a version newer than upstream publishes. Not a clean answer
   * dressed as one: either the pin was typed from a draft, or upstream has
   * withdrawn a release, and both mean this tree cites a file a reader cannot
   * fetch.
   */
  | { kind: "ahead"; pin: string; upstream: string };

export function pinDrift(pin: string, upstream: string): PinDrift {
  const c = compareDatasetVersions(pin, upstream);
  if (c === 0) return { kind: "current", pin };
  return c < 0 ? { kind: "behind", pin, upstream } : { kind: "ahead", pin, upstream };
}

/** one line for a job summary or `doctor`; the wording is the point on `behind` */
export function renderPinDrift(drift: PinDrift): string {
  switch (drift.kind) {
    case "current":
      return `dataset ${drift.pin}: at the pin — upstream publishes the version this tree reads`;
    case "behind":
      return (
        `dataset ${drift.pin}: BEHIND — FedRAMP/rules publishes ${drift.upstream}. ` +
        "Taking it is a reviewed change, not a version bump: the catalog loader parses prose that upstream " +
        "rewords, both legs of the dual-source contract move together, and every reviewed artifact keyed to " +
        "the old pin (the action allowlist, the literal table, the Phase One crosswalk, the adjudications) " +
        "is re-read rather than re-stamped."
      );
    case "ahead":
      return (
        `dataset ${drift.pin}: AHEAD of upstream, which publishes ${drift.upstream} — ` +
        "this tree cites a version upstream does not publish, so a reader cannot fetch what it claims to read"
      );
  }
}
