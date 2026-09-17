import { awsActionOf } from "./aws-actions.js";

// Step labels (T2-5, SPEC §14.4a): the name an upstream assertion's
// `<label>.<JMESPath>` gives a step's document.
//
// UPSTREAM SUPPLIES IT NOW. At overlay 4.x every published command carries a
// `name`, and every assertion of every pinned recipe addresses a step by that
// name — so the label travels with the step from the overlay through the
// request into intake (`RecipeStep.label`), and neither the rule below nor
// the reviewed table that used to correct it decides anything. The table
// (`recipes/aws-actions/labels.json`) is gone with the five names it carried:
// it keyed steps by POSITION, and upstream renumbers freely, so a row that
// looked current was one inserted step away from labelling the wrong output.
//
// The rule survives for one job: a transcript that arrives with no labels at
// all — a hand-built one, or a fixture — still needs a name per step, and
// guessing from the argv is better than `step-3`. Nothing pinned takes this
// path.

/** the rule: `--config-rule-name X` (or the first of `--config-rule-names`), else the operation */
export function derivedStepLabel(argv: readonly string[]): string {
  const i = argv.findIndex((w) => w === "--config-rule-name" || w === "--config-rule-names");
  if (i !== -1 && argv[i + 1] !== undefined && !argv[i + 1]!.startsWith("--")) return argv[i + 1]!;
  const action = awsActionOf(argv.join(" "));
  return action === undefined ? "step" : action.split(" ")[1]!;
}
