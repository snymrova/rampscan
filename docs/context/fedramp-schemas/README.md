# FedRAMP JSON schemas — pinned, not snapshotted

Everything else under `docs/context/` is a snapshot that is allowed to rot (see
[`../README.md`](../README.md)). **This directory is not.** These three files are
the export targets `rampscan exports` validates its own output against, so a
drifting copy here would not go stale quietly — it would silently change what
"schema-valid" means for every document this appliance generates.

They are therefore pinned twice, in `packages/cli/src/fedramp-schemas.ts`:

1. **On `$schemaVersion`**, per file, because FedRAMP semvers each schema
   independently — the three here read `0.1.4`, `0.3.0` and `0.2.0` from the
   same `2026-06-24` date stamp. One global constant would have been wrong on
   the day it was written, exactly as it was for `DEFAULT_OVERLAY_PINS`.
2. **On the sha256 of the bytes**, because these are draft CR26 schemas. A
   re-publication under an unchanged date *and* an unchanged `$schemaVersion` is
   a thing that can happen to a draft, and it is precisely the class of move
   `packages/dataset/src/pins.ts` exists to complain about: a version we reason
   against that nothing was checking.

The loader hard-fails on either mismatch. Bumping a pin is a reviewed change
with a re-read of the diff, never a side effect of refreshing a file.

| File | `$schemaVersion` | Rule that requires it |
|---|---|---|
| `fedramp-certification-package-overview-schema-2026-06-24.json` | 0.1.4 | `FRC-CSO-PKG`, `CDS-CSO-PUB` |
| `fedramp-ongoing-certification-report-schema-2026-06-24.json` | 0.2.0 | `CCM-OCR-AVL` |
| `fedramp-common-definitions-schema-2026-06-24.json` | 0.3.0 | referenced by both (`$ref` target) |

`FRC-CSO-JSN` is the rule that makes conformance mandatory: machine-readable
information MUST be valid against the corresponding FedRAMP schema when a rule
names one. Its own note is why the `x-rampscan` extension block in our exports
is legitimate rather than a liberty — the schemas "are designed to be
lightweight and flexible to establish a minimum set of structured information
while allowing providers to improve on the format and structure of the
information as needed", and none of the three sets `additionalProperties: false`.

## Source of truth

`https://www.fedramp.gov/schemas/<filename>` — fetched 2026-09-12. The eleven
draft CR26 schemas are also published as a set in
[FedRAMP/schemas](https://github.com/FedRAMP/schemas); the eight we do not
generate are deliberately not vendored, because a pinned file nothing validates
against is a pin nobody is checking.
