import { AwsStepLabels } from "@rampscan/schema";
export declare const DEFAULT_LABELS_PATH = "recipes/aws-actions/labels.json";
export declare function loadAwsStepLabels(path: string): Promise<AwsStepLabels>;
/** the rule: `--config-rule-name X` (or the first of `--config-rule-names`), else the operation */
export declare function derivedStepLabel(argv: readonly string[]): string;
/** every step's label for one recipe: the reviewed row where there is one, the rule otherwise */
export declare function stepLabels(recipeId: string, steps: ReadonlyArray<readonly string[]>, table?: AwsStepLabels): string[];
//# sourceMappingURL=aws-labels.d.ts.map