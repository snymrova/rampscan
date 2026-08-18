<!--
The ground rules that decide this are in CONTRIBUTING.md, and most of them are
enforced by a named test rather than by review. Delete any section that does not
apply — an empty heading is worse than no heading.
-->

## What this changes, and why it went this way

<!--
Not a restatement of the diff. What decision was made, what the alternative was,
and why it lost. The history here is long-form on purpose.
-->

## What was verified

<!--
Ground rule 4 applies to this description: paste the command and its output, not
a summary of it. "Tests pass" is weaker than the command.
-->

```
pnpm test
pnpm typecheck
```

## Checklist

- [ ] `pnpm test` and `pnpm typecheck` are green locally
- [ ] Tests ride with the change (ground rule 6), not as a follow-up
- [ ] No number in any document, comment or output was typed rather than computed (ground rules 4 and 9)
- [ ] Nothing touching storage, signing, execution, scheduling or repo access bypasses a `packages/core` port (ground rule 1)
- [ ] If a plan document was proved wrong by execution, it is corrected in this PR with what was learned

### If this adds or changes a recipe

- [ ] `empty_means` is declared, and the `notes` name which of the five empty-set patterns it uses
- [ ] All three `plain` paragraphs are authored — `checks`, `violation`, `fix`
- [ ] `caveats` state what the recipe does not reach
- [ ] No path exists by which this recipe reports `evidenced` from having found nothing to check (ground rule 7)

### If this adds or changes an adjudication

- [ ] The `rationale` argues rather than asserts (ground rule 8)
- [ ] The `remainder` names the control's unreached limbs and the boundary limitation
- [ ] Where upstream has spoken, `citesUpstream` records agreement or divergence and argues it narrowly (ground rule 10)
