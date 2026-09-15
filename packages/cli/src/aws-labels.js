import { readFile } from "node:fs/promises";
import { AwsStepLabels } from "@rampscan/schema";
import { awsActionOf } from "./aws-actions.js";
// Step labels (T2-5, SPEC §14.4a): the name an upstream assertion's
// `<label>.<JMESPath>` gives a step's document. By rule from the argv;
// by a reviewed row where upstream chose a name by hand.
export const DEFAULT_LABELS_PATH = "recipes/aws-actions/labels.json";
export async function loadAwsStepLabels(path) {
    return AwsStepLabels.parse(JSON.parse(await readFile(path, "utf8")));
}
/** the rule: `--config-rule-name X` (or the first of `--config-rule-names`), else the operation */
export function derivedStepLabel(argv) {
    const i = argv.findIndex((w) => w === "--config-rule-name" || w === "--config-rule-names");
    if (i !== -1 && argv[i + 1] !== undefined && !argv[i + 1].startsWith("--"))
        return argv[i + 1];
    const action = awsActionOf(argv.join(" "));
    return action === undefined ? "step" : action.split(" ")[1];
}
/** every step's label for one recipe: the reviewed row where there is one, the rule otherwise */
export function stepLabels(recipeId, steps, table) {
    return steps.map((argv, i) => {
        const row = table?.entries.find((e) => e.recipe === recipeId && e.step === i + 1);
        return row?.label ?? derivedStepLabel(argv);
    });
}
