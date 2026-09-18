# Security Decision Record — Example Evidence Plane (EEP)

Example Cloud Inc. · class b · dataset 2026.09.13.02 · as of 2026-09-18T12:00:00.000Z

This is the human-readable half of the record `SDR-CSO-FRR` requires in both formats. It is rendered from `fedramp-security-decision-record.json` and says nothing that file does not.

JSON sha256: `dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd`

- **Version:** sha256:b75245058060
- **Last updated:** 2026-09-18T12:00:00.000Z
- **Update source:** rampscan (automated), rendered from the evidence ledger at head ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff against dataset 2026.09.13.02
- **Certification package overview:** https://trust.example.com/cpo.json

**Legend.** *Declared* text is the offering's own, passed through by rampscan unchanged. *Computed* values are derived by rampscan from signed ledger statements. An artifact body is quoted with its source (`authored`, `computed`, `attested` or `assessed`) and the sha256 of its bytes.

## Summary

- **KSI rows:** 41 — 40 Implemented, 1 Partially Implemented, 0 Not Implemented. The status is *computed*, and may understate but never overstate.
- **FedRAMP rules addressable at class b:** 129. Rows declared: 2 (1 addressed, 1 not implemented with a reason). Without a row: 127.
- **Schema (FRC-CSO-JSN):** valid against `fedramp-security-decision-record-schema-2026-06-24.json` @ 1.1.1

### Problems

Stated in full, as the JSON carries them:

- SDR-CSX-KSI artifact 1 (Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.) has no body on 1 obliged KSI row(s): KSI-SVC-SIN. It is the provider's own claim; rampscan does not write it (`rampscan artifacts scaffold`). The row carries nothing in its place.
- ksiAssessment is empty on every row: it is the independent assessor's summary to supply, and no assessed body is in the ledger
- evidenceLocation is an RFC 6920 `ni:` name over each bundle's digest: it identifies the signed bundle but a reader without this ledger cannot fetch it. Declare `offering.evidenceBaseUri` once the bundles are published
- 127 of 129 rules addressable at class b have no row: the offering's ruleCoverage does not declare them, and SDR-CSO-FRR wants each one explained as followed or not followed with a reason. Omitting a row is FedRAMP's rejection reason 3 (community #167). 16 of them are rules rampscan computes; the evidence exists, and a declaration is what gives it a row. They are listed in x-rampscan.unaddressedRules
- SDR-CSX-KMT (MUST at class b): historical metrics are carried under x-rampscan.metrics, outside the pinned schema, which has no field for them (FedRAMP/schemas#10). A reviewer reading only the schema's fields will not see them

## Key Security Indicators

### KSI-CED-RAT — Reviewing All Training

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CMT-LMC — Logging Changes

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CMT-RMV — Redeploying vs Modifying

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CMT-RVP — Reviewing Change Procedures

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CMT-VTD — Validating Throughout Deployment

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-DFP — Defining Functionality and Privileges

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-IBP — Implementing Best Practices

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-MAT — Minimizing Attack Surface

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-OFA — Optimizing for Availability

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-RNT — Restricting Network Traffic

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-RVP — Reviewing Protections

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-CNA-ULN — Using Logical Networking

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-IAM-AAM — Automating Account Management

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-IAM-APM — Adopting Passwordless Methods

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-IAM-ELP — Ensuring Least Privilege

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-IAM-JIT — Authorizing Just-in-Time

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-IAM-SNU — Securing Non-User Authentication

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-IAM-SUS — Responding to Suspicious Activity

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-INR-AAR — Generating After Action Reports

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-INR-RIR — Reviewing Incident Response Procedures

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-INR-RPI — Reviewing Past Incidents

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-MLA-EVC — Evaluating Configurations

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-MLA-LET — Logging Event Types

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-MLA-OSM — Operating SIEM Capability

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-MLA-RVL — Reviewing Logs

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-PIY-GIV — Generating Inventories

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-PIY-RES — Reviewing Executive Support

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-PIY-RIS — Reviewing Investments in Security

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-PIY-RSD — Reviewing Security in the SDLC

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-PIY-RVD — Reviewing Vulnerability Disclosures

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-RPL-ABO — Aligning Backups with Objectives

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-RPL-ARP — Aligning Recovery Plan

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-RPL-RRO — Reviewing Recovery Objectives

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-RPL-TRC — Testing Recovery Capabilities

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SCR-MIT — Mitigating Supply Chain Risk

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SCR-MON — Monitoring Supply Chain Risk

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SVC-ACM — Automating Configuration Management

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SVC-ASM — Automating Secret Management

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SVC-EIS — Evaluating and Improving Security

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SVC-SIN — Securing Information

**Status:** Partially Implemented (computed). Short of Implemented: 4 of 5 artifacts present.

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** — *missing: no body in this record.*

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

### KSI-SVC-VRI — Validating Resource Integrity

**Status:** Implemented (computed).

#### The five artifacts (SDR-CSX-KSI)

1. **Artifact 1 — Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.** _(authored; body sha256 111111111111…)_

> Body of artifact 1.

2. **Artifact 2 — Explanation of the cycle for any measures that are implemented persistently (if applicable).** _(computed; body sha256 222222222222…)_

> Body of artifact 2.

3. **Artifact 3 — Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.** _(authored; body sha256 333333333333…)_

> Body of artifact 3.

4. **Artifact 4 — Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.** _(computed; body sha256 444444444444…)_

> Body of artifact 4.

5. **Artifact 5 — Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.** _(computed; body sha256 555555555555…)_

> Body of artifact 5.

#### Assessment

*None: the independent assessor's summary is not in this record.*

#### Tests (computed)

- pipeline:secrets-scan — pipeline, automated, machine clock

#### Evidence (computed)

| Type | Updated | Result | Location |
|---|---|---|---|
| Report | 2026-09-17 | pipeline:secrets-scan: evidenced, process-generated evidence | `ni:///sha-256;qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo` |

## Historical metrics (SDR-CSX-KMT)

SDR-CSX-KMT asks for these in the Security Decision Record, and the pinned schema has no field for them (FedRAMP/schemas#10). They are carried here, outside the schema, until FedRAMP names a place.

No FedRAMP rule defines a metric (FedRAMP/schemas#10, question 3). FRC-CSX-MOT names one, status from persistent validation, so a KSI's metric for a day is the ksiImplementationStatus rampscan would have computed at that day's end, plus the counts it was computed from (the statusBasis fields of the same names). Each day is refolded from the ledger, never accumulated, so the same ledger at the same instant yields the same bytes. A day before the offering's first scan is absent: it is counted in daysAbsent and given no status, never a zero.

The series reaches from 2025-09-18 to 2026-09-17 (365 days; UTC days; a day's metric is folded at its last millisecond, and only days that ended at or before the record's instant are included). The first covered day is 2026-08-09. The daily data is not included at this class.

Days per status are Implemented / Partially Implemented / Not Implemented.

| KSI | Past 30 days: covered | Days per status | Last | Past year: covered | Days per status | Last |
|---|---|---|---|---|---|---|
| KSI-CED-RAT | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CMT-LMC | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CMT-RMV | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CMT-RVP | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CMT-VTD | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-DFP | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-IBP | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-MAT | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-OFA | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-RNT | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-RVP | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-CNA-ULN | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-IAM-AAM | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-IAM-APM | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-IAM-ELP | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-IAM-JIT | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-IAM-SNU | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-IAM-SUS | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-INR-AAR | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-INR-RIR | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-INR-RPI | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-MLA-EVC | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-MLA-LET | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-MLA-OSM | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-MLA-RVL | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-PIY-GIV | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-PIY-RES | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-PIY-RIS | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-PIY-RSD | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-PIY-RVD | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-RPL-ABO | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-RPL-ARP | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-RPL-RRO | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-RPL-TRC | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SCR-MIT | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SCR-MON | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SVC-ACM | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SVC-ASM | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SVC-EIS | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SVC-SIN | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |
| KSI-SVC-VRI | 30 of 30 | 5 / 25 / 0 | Implemented | 40 of 365 | 5 / 35 / 0 | Implemented |

## FedRAMP rules (SDR-CSO-FRR)

### Declared by the offering

| Rule | Force at class b | Status | Statement | Validation |
|---|---|---|---|---|
| FRC-APP-MLF | MUST | Not Implemented | Not implemented: the Marketplace listing request is filed and pending | — |
| FRC-CSX-VVK | SHOULD | Implemented | docs/ksi-methods.md §2 \| the floor | Validated by rampscan, which computes this rule: the method floor — the KSI register's automated-method numerator, and gaps G1/G2. |

### Without a row

Each rule below is addressable at this class and the offering declares nothing for it, so the record has no row for it. That omission is FedRAMP's rejection reason 3.

| Rule | Force at class b | rampscan computes it |
|---|---|---|
| AFC-CSO-ACK | SHOULD | — |
| AFC-CSO-CRA | MUST | — |
| AFC-CSO-EMR | MUST | — |
| AFC-CSO-IMA | SHOULD | — |
| AFC-CSO-INB | MUST | — |
| AFC-CSO-NOC | MUST | — |
| AFC-CSO-RCV | MUST | — |
| AFC-CSO-TFG | MUST | — |
| CCM-OCR-AFS | MUST | — |
| CCM-OCR-AVL | MUST | `rampscan exports` builds the Ongoing Certification Report and validates it against the pinned schema |
| CCM-OCR-FBM | MUST | — |
| CCM-OCR-NRD | MUST | the exports' problems channel reports an undeclared next-OCR date — a calendar commitment the ledger cannot compute |
| CCM-OCR-SOR | SHOULD | — |
| CCM-QTR-ACT | SHOULD | — |
| CCM-QTR-MTG | SHOULD | — |
| CCM-QTR-NRD | MUST | — |
| CCM-QTR-REG | MUST | — |
| CCM-QTR-RTR | SHOULD | — |
| CCM-QTR-SAR | SHOULD | — |
| CDS-CSO-AVR | MUST | — |
| CDS-CSO-CBF | MUST | — |
| CDS-CSO-FID | MUST | — |
| CDS-CSO-FRC | MUST | — |
| CDS-CSO-HAD | MUST | — |
| CDS-CSO-IRP | MUST | — |
| CDS-CSO-PUB | MUST | the exports' problems channel reports an undeclared independent assessment service |
| CDS-CSO-RIS | MUST | — |
| CDS-CSO-SVC | MUST | — |
| CDS-CSO-UTC | MUST | the exports' problems channel reports an undeclared trust center; serving it is out of scope for a local appliance |
| CDS-TRC-AAI | MUST | — |
| CDS-TRC-ACL | MUST | — |
| CDS-TRC-HMR | SHOULD | — |
| CDS-TRC-PAC | MUST | — |
| CDS-TRC-SSM | SHOULD | — |
| CDS-TRC-USH | MUST | `rampscan probe` fetches the declared trust center and named certification documents anonymously; a gate is reported on positive evidence, and `submission --trust-center-probe` reads the transcript |
| CDS-UTC-AAD | MUST | — |
| CDS-UTC-AGA | SHOULD | — |
| CMU-CSO-CAT | SHOULD | — |
| CMU-CSO-CMD | MUST | — |
| CPO-CSO-MTD | MUST | — |
| CPO-CSO-OSA | MUST | — |
| CPO-CSO-OVR | MUST | — |
| CPO-CSX-CPM | MUST | — |
| FRC-APP-AFC | MUST | — |
| FRC-APP-FCP | MUST | `applicationFreshness` computes the package's age from the register, with no config key that could have asserted it |
| FRC-APP-FIA | MUST | — |
| FRC-CSO-FCP | MUST | — |
| FRC-CSO-JSN | MUST | `rampscan conformance` validates each document against its pinned schema, and cross-checks the document's own stamp |
| FRC-CSO-MRA | MUST | — |
| FRC-CSO-PKG | MUST | `rampscan exports` builds the certification package overview |
| FRC-CSX-MAS | SHOULD | — |
| FRC-CSX-MOT | SHOULD | the history meter walks the KSI's instants across the owed span (#159) |
| FRC-CSX-VVR | SHOULD | — |
| IEC-CSO-AIR | SHOULD | — |
| IEC-CSO-DPR | MUST | — |
| IEC-CSO-EFI | SHOULD | — |
| IEC-CSO-EFR | MUST | — |
| IEC-CSO-FIR | MUST | — |
| IEC-CSO-IIR | MUST | — |
| IEC-CSO-OIR | MUST | — |
| IVV-CSO-DUS | MUST | — |
| IVV-CSO-FIA | MUST | — |
| IVV-CSO-ICP | MUST | — |
| IVV-CSO-SEE | MUST | — |
| IVV-CSO-SEI | MUST | — |
| IVV-CSO-STE | SHOULD | — |
| IVV-CSX-AIA | MUST | — |
| MAS-CSO-FLO | MUST | — |
| MAS-CSO-IIR | MUST | — |
| MAS-CSO-MDI | MUST | — |
| MAS-CSO-TPR | MUST | — |
| MKT-CSO-MLR | MUST | — |
| MKT-CSO-PML | MUST | — |
| SCG-CSO-AUP | MUST | — |
| SCG-CSO-PUB | SHOULD | — |
| SCG-CSO-RSC | MUST | — |
| SCG-CSO-SDF | SHOULD | — |
| SCG-ENH-API | SHOULD | — |
| SCG-ENH-CMP | SHOULD | — |
| SCG-ENH-EXP | SHOULD | — |
| SCG-ENH-MRG | SHOULD | — |
| SCG-ENH-VRH | SHOULD | — |
| SCN-ADP-NTF | MUST | — |
| SCN-CSO-EVA | MUST | — |
| SCN-CSO-HIS | MUST | — |
| SCN-CSO-HRM | MUST | — |
| SCN-CSO-INF | MUST | — |
| SCN-CSO-MAR | MUST | — |
| SCN-TRF-NAF | MUST | — |
| SCN-TRF-NAV | MUST | — |
| SCN-TRF-NFP | MUST | — |
| SCN-TRF-NIP | MUST | — |
| SCN-TRF-TPR | SHOULD | — |
| SCN-TRF-UPD | MUST | — |
| SDR-CSO-FRR | MUST | `rampscan sdr` writes the record's JSON with a row per declared rule and names every undeclared one; `rampscan submission --sdr` diffs a record's fedRampRequirements against the rules addressable at the class |
| SDR-CSO-MTD | MUST | `rampscan sdr` computes the record's metadata: a content-digest version, the fold instant, and the ledger head it was rendered from |
| SDR-CSX-KMT | MUST | `rampscan sdr` reports by name that the record carries no historical metrics, citing FedRAMP/schemas#10 — unmet until R3 carries them |
| SDR-CSX-KSI | MUST | the artifact plane (R0/R1): the five artifacts owed per KSI, rendered into each row of `rampscan sdr` |
| VDR-CSO-ADT | SHOULD | — |
| VDR-CSO-DAC | SHOULD | — |
| VDR-CSO-DET | MUST | — |
| VDR-CSO-DFR | SHOULD | — |
| VDR-CSO-FAV | MUST | the failure-to-vulnerability feed — gaps G13 |
| VDR-CSO-RES | MUST | — |
| VDR-TFR-KEV | SHOULD | — |
| VDR-TFR-MVX | MUST | the machine validation window meter for the reporting class |
| VDR-TFR-NMV | MUST | the non-machine validation window, three months, for attested methods |
| VDR-TFR-PCD | SHOULD | — |
| VDR-TFR-PDD | SHOULD | — |
| VDR-TFR-PSD | SHOULD | — |
| VDR-TFR-PVR | SHOULD | — |
| VDR-TFR-RMN | SHOULD | — |
| VER-EVA-AIA | MUST | — |
| VER-EVA-EFA | SHOULD | — |
| VER-EVA-EFP | SHOULD | — |
| VER-EVA-EIR | MUST | — |
| VER-EVA-ELX | MUST | — |
| VER-EVA-EPA | MUST | — |
| VER-EVA-GRV | SHOULD | — |
| VER-RPT-AVI | MUST | — |
| VER-RPT-HLO | SHOULD | — |
| VER-RPT-PER | MUST | — |
| VER-RPT-VDT | MUST | — |
| VER-TFR-EVU | SHOULD | — |
| VER-TFR-MAV | MUST | — |
| VER-TFR-MHR | MUST | — |
| VER-TFR-MRH | SHOULD | — |

## What this document does not contain

- The independent assessor's content (R4.5), portsAndProtocols and securityControls (Rev5) are not in this document
- KSIs class b does not oblige and that hold no evidence: KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM.
- A verification field. The schema has none. The two verifications `SDR-CSX-KSI` asks for (artifacts 3 and 4) are carried under `ksiValidation`, beside validation (artifact 5).
