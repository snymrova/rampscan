import { AwsActionAllowlist } from "@rampscan/schema";
import type { AwsActionEntry } from "@rampscan/schema";
/** the checked-in list; `rampscan runner policy` and `recipes --aws` read this path by default */
export declare const DEFAULT_ALLOWLIST_PATH = "recipes/aws-actions/allowlist.json";
export declare function loadAwsActionAllowlist(path: string): Promise<AwsActionAllowlist>;
/**
 * The `<service> <operation>` of one shell segment, or undefined when the
 * segment is not an `aws` invocation at all (a pipe into `base64`, `jq`, or
 * a bare word). Global options before the service (`aws --profile x iam …`)
 * are skipped; anything else is the caller's to refuse as a shell construct.
 */
export declare function awsActionOf(segment: string): string | undefined;
export type ActionClass = {
    kind: "admitted";
    entry: AwsActionEntry;
} | {
    kind: "refused";
    entry: AwsActionEntry;
}
/** on neither list: manual until a reviewer reads it — never runnable by default */
 | {
    kind: "unknown";
};
export declare function classifyAwsAction(list: AwsActionAllowlist, cli: string): ActionClass;
/** whether an admitted entry's operation is one the verb alone would have admitted */
export declare function isPlainlyRead(entry: AwsActionEntry): boolean;
//# sourceMappingURL=aws-actions.d.ts.map