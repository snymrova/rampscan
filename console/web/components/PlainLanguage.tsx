import type { PlainLanguageRecord } from "../lib/types";

// The plain-language block (plan K1). One component for every surface that
// shows the recipe's authored English — the board's collapsed row and the
// evidence page's expanded panel — so the two can never end up describing the
// same check differently.
//
// The line at the bottom is not decoration. Everything else on an evidence
// page is computed from signed statements and says so; these three paragraphs
// are the one part a person wrote, and they describe the CHECK rather than
// this result. A reader who cannot tell those apart could take the prose for a
// finding, which is the exact confusion the rest of this console exists to
// prevent.

export function PlainLanguage({
  plain,
  recipeId,
}: {
  plain: PlainLanguageRecord;
  recipeId: string;
}) {
  return (
    <div className="plain">
      <dl>
        <dt>checks</dt>
        <dd>{plain.checks}</dd>
        <dt>a violation means</dt>
        <dd>{plain.violation}</dd>
        <dt>fixing it</dt>
        <dd>{plain.fix}</dd>
      </dl>
      <p className="plain-src">
        written for operators and kept in the <code>{recipeId}</code> recipe, so it travels with the
        check it describes — it explains the check, and states nothing about this repository
      </p>
    </div>
  );
}
