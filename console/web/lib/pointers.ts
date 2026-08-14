import type { OffenderPointer } from "./types";

// Fix-pointer phrasing (I2c), shared by the board's violated rows and the
// action queue so the two never describe the same pointer differently. Pure
// formatting: the pointers themselves were extracted by the evaluator at scan
// time and ride the evidence — nothing here derives, guesses, or re-parses.

/** one pointer, in the operator's terms: "check — file:line", best available parts */
export function describePointer(p: OffenderPointer): string {
  const loc = p.file !== undefined ? `${p.file}${p.line !== undefined ? `:${p.line}` : ""}` : undefined;
  const named = [p.check, loc].filter((v): v is string => v !== undefined).join(" — ");
  // a pointer with neither check nor file still carries a call path (extraction
  // drops fully-empty pointers before they ever reach the record)
  return named !== "" ? named : (p.call_path ?? "");
}

/** the first pointer plus an honest "+N more" — N counts only what the bounded list holds */
export function pointerSummary(pointers: OffenderPointer[]): string {
  if (pointers.length === 0) return "";
  const first = describePointer(pointers[0]!);
  return pointers.length > 1 ? `${first} (+${pointers.length - 1} more)` : first;
}
