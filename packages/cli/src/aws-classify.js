import { awsActionOf, classifyAwsAction } from "./aws-actions.js";
/** what a published pipe tail may be, exactly — anything else is a shell construct */
const TRANSFORM_TAILS = new Map([
    ["base64 --decode", "base64-decode"],
    ["base64 -d", "base64-decode"],
]);
const PLACEHOLDER = /<([A-Za-z][A-Za-z0-9_-]*)>/g;
/**
 * Split one published command into argv the way a POSIX shell would, and
 * name the first construct that means it is NOT one argv. Single quotes are
 * literal (a JMESPath backtick or `$LATEST` inside them is text); double
 * quotes honour backslash and still carry `$`/backtick substitution; outside
 * quotes, `|`, `;`, `&&`, `||`, `<`, `>`, `$(`, `${`, `$NAME` and backticks
 * are constructs. A construct is reported, never executed around.
 */
export function splitCommand(command) {
    const argv = [];
    let word = "";
    let inWord = false;
    let i = 0;
    const s = command;
    const push = () => {
        if (inWord)
            argv.push(word);
        word = "";
        inWord = false;
    };
    while (i < s.length) {
        const c = s[i];
        if (c === "'") {
            const end = s.indexOf("'", i + 1);
            if (end === -1)
                return { argv, construct: "substitution" };
            word += s.slice(i + 1, end);
            inWord = true;
            i = end + 1;
            continue;
        }
        if (c === '"') {
            let j = i + 1;
            while (j < s.length && s[j] !== '"') {
                if (s[j] === "\\" && j + 1 < s.length) {
                    word += s[j + 1];
                    j += 2;
                    continue;
                }
                if (s[j] === "$" || s[j] === "`")
                    return { argv, construct: "substitution" };
                word += s[j];
                j++;
            }
            if (j >= s.length)
                return { argv, construct: "substitution" };
            inWord = true;
            i = j + 1;
            continue;
        }
        if (c === "\\" && i + 1 < s.length) {
            word += s[i + 1];
            inWord = true;
            i += 2;
            continue;
        }
        if (c === " " || c === "\t" || c === "\n") {
            push();
            i++;
            continue;
        }
        if (c === "|")
            return { argv, construct: s[i + 1] === "|" ? "chain" : "pipe" };
        if (c === ";" || (c === "&" && s[i + 1] === "&"))
            return { argv, construct: "chain" };
        if (c === "<" || c === ">") {
            // `<NAME>` is a placeholder, not a redirection — it is bound, not read
            const m = /^<([A-Za-z][A-Za-z0-9_-]*)>/.exec(s.slice(i));
            if (c === "<" && m) {
                word += m[0];
                inWord = true;
                i += m[0].length;
                continue;
            }
            return { argv, construct: "redirect" };
        }
        if (c === "`" || (c === "$" && /[({A-Za-z_]/.test(s[i + 1] ?? ""))) {
            return { argv, construct: "substitution" };
        }
        word += c;
        inWord = true;
        i++;
    }
    push();
    return { argv };
}
/** the offset of the first `|` outside quotes, or -1 */
function pipeIndex(command) {
    let q;
    for (let i = 0; i < command.length; i++) {
        const c = command[i];
        if (q !== undefined) {
            if (c === "\\" && q === '"')
                i++;
            else if (c === q)
                q = undefined;
        }
        else if (c === "'" || c === '"')
            q = c;
        else if (c === "\\")
            i++;
        else if (c === "|")
            return i;
    }
    return -1;
}
/** every `<NAME>` in a command, in order, once each */
export function placeholdersOf(command) {
    const out = [];
    for (const m of command.matchAll(PLACEHOLDER))
        if (!out.includes(m[1]))
            out.push(m[1]);
    return out;
}
function bind(word, params) {
    return word.replace(PLACEHOLDER, (whole, name) => params[name] ?? whole);
}
/**
 * Classify one pinned recipe under the reviewed allowlist and the bound
 * parameters. `params` is what T1-3 binds from `rampscan.config.json`;
 * pass `{}` to see every placeholder as a reason.
 */
export function classifyAwsRecipe(recipe, list, params = {}) {
    const commands = recipe.collection.commands;
    if (!Array.isArray(commands) || commands.length === 0)
        return { kind: "manual", reasons: [{ kind: "no-commands" }] };
    const reasons = [];
    const steps = [];
    for (const raw of commands) {
        const command = String(raw);
        let split = splitCommand(command);
        let transform;
        if (split.construct === "pipe") {
            // a pipe whose tail is exactly a known transform is a step, not a
            // shell; the head is re-split on its own so its own constructs still count
            const at = pipeIndex(command);
            const tail = TRANSFORM_TAILS.get(command.slice(at + 1).trim());
            if (tail !== undefined) {
                split = splitCommand(command.slice(0, at));
                transform = tail;
            }
        }
        if (split.construct !== undefined) {
            reasons.push({ kind: "shell", construct: split.construct, command });
        }
        // the action is judged on the first segment even when a construct follows,
        // so a piped `ssm send-command` is reported as refused AND as a pipe
        const action = awsActionOf(command.split("|")[0]);
        if (action === undefined) {
            if (/^\s*kubectl\s/.test(command))
                reasons.push({ kind: "kubectl", command });
            else if (split.construct === undefined)
                reasons.push({ kind: "not-aws", command });
        }
        else {
            const cls = classifyAwsAction(list, action);
            if (cls.kind === "refused")
                reasons.push({ kind: "refused-action", action, why: cls.entry.why });
            else if (cls.kind === "unknown")
                reasons.push({ kind: "unknown-action", action });
        }
        for (const name of placeholdersOf(command)) {
            if (params[name] === undefined && !reasons.some((r) => r.kind === "unbound" && r.name === name)) {
                reasons.push({ kind: "unbound", name });
            }
        }
        if (split.construct === undefined) {
            const argv = split.argv.map((w) => bind(w, params));
            steps.push(transform === undefined ? { argv } : { argv, transform });
        }
    }
    return reasons.length > 0 ? { kind: "manual", reasons } : { kind: "runnable", steps };
}
/** one line per reason, for `rampscan recipes --aws` and the console's "manual because" */
export function describeReason(r) {
    switch (r.kind) {
        case "refused-action":
            return `refused action ${r.action}: ${r.why}`;
        case "unknown-action":
            return `action ${r.action} is on neither list — manual until reviewed`;
        case "unbound":
            return `unbound parameter <${r.name}>`;
        case "shell":
            return `shell ${r.construct} in: ${r.command}`;
        case "not-aws":
            return `not an aws invocation: ${r.command}`;
        case "kubectl":
            return `kubectl is a second axis the runner does not have yet (T1-4a): ${r.command}`;
        case "no-commands":
            return "the recipe publishes no commands";
    }
}
