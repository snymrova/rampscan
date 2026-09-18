# P4: measuring reason 1 with a trust-center probe

Issue #213. Written 2026-09-18, in the same change as the code, because the
owner asked for the plan to be completed without stopping. The calls below
were taken without the owner and are marked **CALL**. Each says what
reversing it would cost.

## 1. The question

FedRAMP's first listed reason for rejecting a 20x submission
(FedRAMP/community#167) is: *"Your Trust Center requires acknowledgement
and/or acceptance of a privacy policy, terms of service or non-disclosure
agreement."* Three rules sit under it:

- `CDS-TRC-USH`: share certification data *"without interruption"*. The note
  prefers just-in-time access provisioning.
- `CDS-TRC-PAC`: *documented* programmatic access.
- `CDS-CSO-UTC`: use a trust center at all.

Whether a gate is in the way is a property of a live URL. No file shows it,
so `rampscan submission` has printed reason 1 as `unmeasured` since P2
(`RESEARCH-REJECTION-LINTER.md` §4). #213 asked three boundary questions:

1. Does the appliance fetch?
2. What counts as a gate?
3. How is a negative proven positively rather than inferred from a 200?

## 2. The answers

**CALL: a separate, explicit fetch; the register stays offline.** The new
`rampscan probe <url> --document <url>…` command is the only command that
makes a network request. It requests only the URLs on its own command line.
It sends GET requests anonymously: no cookie jar, no credential, no
JavaScript. It follows redirects by hand, so every hop is on the record, and
it writes a transcript. `rampscan submission --trust-center-probe <file>`
reads that transcript offline, the way it reads an SDR.

The cloud runner's answer (a second program that holds an AWS role) is not
needed here. There is no credential to keep away from the appliance, and the
question itself is what an anonymous reader gets. *Reversing it:* the
alternative is an operator-run `curl` whose output rampscan reads. That means
the same transcript schema with a different producer; nothing downstream
would change.

**A negative is proven positively (ground rule 7; the GHSA-7jff-6v53-r56x
class).** A landing page that loads proves that a page loaded. A
click-through rendered by script, an NDA modal, or a "request access" button
inside a SPA shell is invisible to a fetch. So a clean-looking 200 on HTML is
**`undetermined`**, never `open`.

**`open` takes one thing only:** a named certification *document* whose bytes
came back to an anonymous GET and validate against one of the pinned FedRAMP
document schemas (package overview, OCR, SDR). That is the data itself,
reached with no gate in the way. A 200 JSON error body does not validate, so
it stays `undetermined`. With no `--document` named, nothing can read open,
and the command says so.

**`gated` takes positive evidence**, each piece recorded with exactly what
matched: 401/403/407, a redirect into a login path or a known identity
provider, or a page marker. **A bare "Privacy Policy" footer link is not a
marker**, because it is on every page on the web. Terms or policy language
counts only when it sits beside an acceptance control ("I agree", "accept and
continue", "by clicking … you agree"). An NDA, a password field and a "request
access" flow count on their own.

**CALL: there are two kinds of gate, and only one is reason 1.** FedRAMP
*permits* an authenticated trust center. The package schema's repository
object carries `authenticationRequired` and requires
`accessRequestInstructions` exactly when it is true, and the USH note prefers
just-in-time access. #167 rejects **acceptance**, not a login. So a gated
target names its gate:

| Gate | Evidence | In the register |
|---|---|---|
| `click-through` | an NDA, or terms/policy language beside an acceptance control | **rejection**: this is reason 1 |
| `authentication` | 401/403, a login redirect, a password field, request-access | a **rejection** only if the offering declared `authenticationRequired: false`, since the package then states something false. If the offering declared it, the login is permitted, and the section stays **unmeasured**, because the probe cannot see whether a click-through waits behind the login |

*Reversing it:* counting every authentication gate as reason 1 is a one-line
change in `trustCenterSection`. It would reject trust centers that FedRAMP's
own schema allows.

**What `open` does not claim.** It proves the named documents, not every
document the trust center holds. The register's note says that every time it
prints the result.

**The probe claims `CDS-TRC-USH` and not `CDS-TRC-PAC`.** PAC asks for
*documented* programmatic access. A document that a program reached is not
documentation. `COMPUTED_RULES` gained USH only.

## 3. Also found

- **P2's declared-auth row overreached. Decided and removed 2026-09-18.**
  Since P2, `authenticationRequired: true` in the offering had printed as a
  rejection labelled *"the gate #167 names"*. The pinned rules say otherwise:
  `CDS-TRC-USH` shares with *"all necessary parties"*, not the public. Its
  note defines "without interruption" as no manual approval *each time*, and
  prefers just-in-time access provisioning. The package schema requires
  `accessRequestInstructions` exactly when authentication is declared. So a
  declared login is permitted, and the declaration row is now a plain
  `declared` row that says so. Reason 1 still rejects a click-through, and a
  login the offering denied having, and only a probe can show either one.
  The false rejection was also a contradiction: with a probe, the probe row
  said "permitted" while the declaration row above it still rejected.
- **The transcript is not signed.** Like the SDR input, it is read and
  re-checked, not trusted. The overall outcome is recomputed from the targets,
  and a transcript whose summary disagrees with its evidence is refused. An
  `open` target without a schema and digest is also refused. Signing it is
  possible later (the ledger's key is right there) but was not needed to stop
  a hand-edited "open".
- **No staleness threshold.** The register prints `probed_at` on every row.
  How old a probe may be before it stops counting is a policy that is not set
  here.

## 4. Build items, all landed 2026-09-18

- **P4-0.** `packages/cli/src/trust-center-probe.ts`: the transcript schema, a
  pure classifier, a hand-redirecting fetcher with a size cap and timeout, and
  a validator over the pinned document schemas.
- **P4-1.** `rampscan probe`; it exits 1 when gated.
- **P4-2.** `submission --trust-center-probe`: `trustCenterSection` reads the
  two gate kinds as §2 says. A probe of a different URL than the declared one
  leaves the section unmeasured. The footer no longer says the appliance
  cannot measure reason 1.
- **P4-3.** `trust-center-probe.test.ts`, 17 tests: the classifier's branches;
  a live `node:http` server serving a schema-valid document
  (`fixtures/trust-center-probe/`), a login redirect and an NDA page; the
  transcript refusals; and the register's six readings.
