// A DELIBERATE BREACH, and the only file in this repository that is one.
//
// `rampscan.config.json` declares `signer-only-through-the-cli`: the signer is
// reachable from `packages/cli` and from nowhere else, because the CLI is the
// only surface that holds a signing key. The projector reads the ledger and
// folds it; it has no business signing anything.
//
// This file exists so the gate can be watched breaking on a public pull
// request rather than described. The exit test's first clause — a breach gets a
// comment naming the file, the import chain and the authored fix sentence, and
// the job goes red — was proven locally and pinned in `check.e2e.test.ts`. It
// had never been demonstrated on the remote, where a stranger can read it.
//
// It is not to be merged.
import { createLocalSigner } from "@rampscan/signer";

export const demo = createLocalSigner;
