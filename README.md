# Agentic Shared Field Protocol

> **Origin remains attributable. Access becomes fluid. Use is leased. Results return. Hazards do not recirculate. Fields federate without surrendering sovereignty.**

The Agentic Shared Field Protocol defines selectively permeable fields in which
humans, autonomous agents, organizations, and services can contribute, reuse,
transform, return, and circulate knowledge, memory, reasoning structures,
compute-related resources, and traceable value without erasing origin,
authorization, accountability, royalty obligations, or revocation rights.

Version `0.5.0` introduces the federation layer. Independently governed fields
can join a federation, negotiate the strict intersection of local and federation
policy, authorize bounded cross-field routes, reassess incoming resources at the
target boundary, settle value across multiple fields, and report circulation
health.

A federation is **not** a global super-field. It does not merge ownership,
governance, storage, policy, or ambient authority.

---

## Status

```text
Protocol version: 0.5.0
Release stage: Experimental
Codename: Federated Metabolic Mesh
Compatibility: Breaking changes remain possible before 1.0.0
```

---

## Core proposition

```text
Origin is preserved.
Participation is explicit.
Authority is bounded.
Use is leased.
Returns are reassessed.
Hazards are quarantined.
Revocation follows lineage.
Cross-field routes use the strictest applicable policy.
Royalty follows value across field boundaries.
```

The protocol separates attribution from exclusive lockout:

```text
exclusive possession
        ↓
closed storage
        ↓
restricted access
        ↓
one-way consumption
```

becomes:

```text
origin retained
        ↓
access authorized
        ↓
resource leased
        ↓
use traced
        ↓
result returned
        ↓
residual reassessed
        ↓
value and revocation propagated
```

---

## Protocol evolution

```text
v0.1  Field constitution and participant binding
v0.2  Controlled contribution boundary
v0.3  Authorized lease and metabolic circulation
v0.4  Anomaly evidence, residual classification, quarantine, and revocation
v0.5  Federated admission, policy negotiation, routing, settlement, and health
v1.0  Stable conformance and interoperability profile
```

---

## Architecture

### Single-field lifecycle

```text
Shared Field Profile
        ↓
Participant Binding
        ↓
Contribution Boundary
        ↓
Reuse Authorization
        ↓
Time-bounded Lease
        ↓
Circulation Receipt
        ↓
Anomaly Evidence
        ↓
Residual Assessment
   ┌────────────┬──────────┬────────────┬───────────┐
recoverable    dormant    hazardous    exhausted
   ↓             ↓           ↓             ↓
re-entry        hold      quarantine     tombstone
                               ↓
                    revocation propagation
```

A returned resource does not automatically re-enter a field. Even a
`recoverable` result must pass through the controlled contribution boundary.

### Federated lifecycle

```text
Federation Profile
        ↓
Source Field Admission
        ↓
Target Field Admission
        ↓
Policy Negotiation
        ↓
Cross-field Route Authorization
        ↓
Source Resource Selection
        ↓
Target Resource Envelope
        ↓
Target Contribution Boundary
        ↓
Cross-field Circulation Receipt
        ↓
Multi-field Royalty Settlement
        ↓
Federation Circulation Health Report
```

A route authorizes transport under bounded conditions. It cannot force the
target field to admit a resource. The target field independently decides whether
to admit, reject, quarantine, or require human review.

---

## Design principles

### 1. Field sovereignty

Each field retains its own governance, participant bindings, contribution
boundary, reuse policy, immune policy, retention policy, and revocation rights.
Federation membership does not surrender those controls.

### 2. No ambient cross-field authority

Admission to a federation does not authorize every route. Each source-target
pair requires an explicit policy negotiation and a bounded route authorization.

### 3. Stricter-policy intersection

A negotiated route cannot be more permissive than the source field, target
field, or federation. Scopes, lease duration, retention, audit, royalty,
revocation, and immune obligations are resolved using the strictest applicable
intersection.

```text
Source Field Policy
        ∩
Target Field Policy
        ∩
Federation Policy
        ↓
Negotiated Route Policy
```

### 4. Target reassessment

Cross-field circulation never bypasses the v0.2 contribution boundary. The
target field repeats origin, authorization, classification, size, audit, and
rights checks.

### 5. Immune continuity

A resource quarantined or revoked before transfer cannot be routed into another
field. Derivative coverage and revocation obligations continue across field
boundaries.

### 6. Traceable multi-field value

A completed cross-field circulation may allocate value to the origin, source
field, target field, participating agents, and federation common pool. The
allocation sum must reconcile exactly and satisfy federation minimum shares.

### 7. Observable circulation health

Federation health is derived from route failures, quarantine rates, settlement
completion, and revocation lag. A report cannot claim `healthy` while its own
metrics breach policy thresholds.

---

## Record types

### Field constitution

| Record                      | Purpose                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `shared-field-profile`      | Defines local governance, access, contribution, reuse, immune, and retention policy |
| `field-participant-binding` | Binds a participant to explicit scopes and resource domains                         |

### Controlled contribution

| Record                          | Purpose                                                                          |
| ------------------------------- | -------------------------------------------------------------------------------- |
| `shared-resource-envelope`      | Packages a proposed resource with origin, digest, classification, and rights     |
| `field-contribution-request`    | Requests admission, replacement, or versioned insertion                          |
| `field-contribution-assessment` | Evaluates origin, authorization, domain, classification, size, audit, and rights |
| `field-contribution-receipt`    | Records admission, rejection, quarantine, or human-review outcome                |

### Reuse and circulation

| Record                               | Purpose                                                              |
| ------------------------------------ | -------------------------------------------------------------------- |
| `field-resource-reuse-request`       | Requests temporary use of an admitted field resource                 |
| `field-resource-reuse-authorization` | Grants, denies, or escalates requested reuse                         |
| `field-resource-lease`               | Issues a bounded capability with exact scopes and expiry             |
| `field-circulation-receipt`          | Closes use with derivative, return, royalty, and revocation evidence |

### Immune and revocation layer

| Record                                | Purpose                                                                  |
| ------------------------------------- | ------------------------------------------------------------------------ |
| `field-anomaly-evidence`              | Records inspectable anomaly signals, severity, confidence, and detectors |
| `field-residual-assessment`           | Classifies resources and returns into four residual states               |
| `field-hazard-quarantine-record`      | Blocks access, reuse, propagation, and unsafe lease continuity           |
| `field-revocation-propagation-record` | Propagates invalidation to leases and known derivatives                  |

### Federation layer

| Record                                  | Purpose                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------- |
| `field-federation-profile`              | Defines federation governance, admission, routing, settlement, and health policy |
| `field-federation-admission-record`     | Admits, denies, suspends, or expires a field membership                          |
| `field-policy-negotiation-record`       | Resolves the source-target-federation policy intersection                        |
| `cross-field-route-authorization`       | Authorizes a bounded domain, scope, hop count, and lease duration                |
| `cross-field-circulation-receipt`       | Proves that a transfer closed through the target contribution boundary           |
| `multi-field-royalty-settlement-record` | Distributes traceable value across the federated path                            |
| `federation-circulation-health-report`  | Reports route, quarantine, settlement, and revocation health                     |

---

## Federation records

### `field-federation-profile`

Defines:

* federation stewards and approval quorum;
* field-admission requirements;
* allowed resource domains and scopes;
* maximum route hops and lease duration;
* policy-negotiation method;
* source-field, target-field, and common-pool settlement shares;
* circulation-health thresholds.

### `field-federation-admission-record`

A field is admitted only when:

* the field exists and is active when required;
* the applicant is an authorized field steward;
* requested domains and scopes fit both field and federation policy;
* compatibility checks pass;
* approval quorum is satisfied;
* trust level meets the federation minimum.

### `field-policy-negotiation-record`

The negotiation resolves:

```text
rights
retention
audit
immunity
royalty
revocation
```

An `agreed` negotiation cannot retain unresolved conflicts.

### `cross-field-route-authorization`

The route binds:

* source and target admission records;
* one resource domain;
* permitted scopes;
* maximum hop count;
* maximum lease duration;
* route validity;
* target reassessment;
* audit, royalty, revocation, and derivative-coverage duties.

### `cross-field-circulation-receipt`

A completed receipt proves that:

* the route was active;
* the source resource was admitted;
* the source resource was not already quarantined or revoked;
* the source and target lineage match;
* exercised scopes remained within route authorization;
* the target request and receipt close the same target envelope;
* the reported outcome matches the target field decision.

### `multi-field-royalty-settlement-record`

A settlement verifies that:

* the allocation sum equals the declared total;
* the declared total equals the gross value;
* source-field and target-field shares meet federation minimums;
* common-pool allocation matches federation policy;
* settlement follows a successfully completed cross-field circulation.

### `federation-circulation-health-report`

The report recalculates:

```text
failed_route_rate
quarantine_rate
settlement_completion_rate
```

It also checks maximum revocation lag and derives the correct health state:
`healthy`, `degraded`, or `critical`.

---

## Residual classifications

| Classification | Meaning                                                    | Required disposition        |
| -------------- | ---------------------------------------------------------- | --------------------------- |
| `recoverable`  | Useful and safe enough for another controlled intake       | `re-enter-through-boundary` |
| `dormant`      | Not presently useful, but worth retaining for reassessment | `hold-dormant`              |
| `hazardous`    | Unsafe, contaminated, misleading, or integrity-compromised | `quarantine-and-revoke`     |
| `exhausted`    | No meaningful reusable utility remains                     | `tombstone`                 |

---

## Key semantic invariants

### Local field invariants

* Default scopes are a subset of allowed scopes.
* Admitted participants cannot exceed field scopes or resource domains.
* Contribution size is bounded by both field and participant limits.
* Accepted and rejected classifications cannot overlap.
* Leases cannot exceed authorization, retention, or envelope expiry.
* Derivative use requires Trace, return evidence, and applicable Royalty state.
* Hazardous residuals require quarantine and revocation.
* Completed revocation propagation cannot hide pending or failed targets.
* Known direct derivatives must be covered when configured.

### Federation invariants

* Federation quorum cannot exceed steward count.
* Reserved settlement shares cannot exceed 100 percent.
* Admitted fields require compatibility checks and sufficient approvals.
* Negotiated scopes and domains must exist in the source-target-federation intersection.
* Route terms cannot exceed the negotiated policy.
* Target intake outcome must match the cross-field receipt.
* Quarantined or revoked source resources cannot be transferred afterward.
* Multi-field allocations must balance exactly.
* Federation health status must match calculated threshold breaches.

---

## Repository layout

```text
agentic-shared-field-protocol/
├── .github/
│   └── workflows/
│       └── validate.yml
├── examples/
│   ├── pass/
│   └── fail/
├── schemas/
│   ├── shared-field-profile.schema.json
│   ├── field-participant-binding.schema.json
│   ├── shared-resource-envelope.schema.json
│   ├── field-contribution-request.schema.json
│   ├── field-contribution-assessment.schema.json
│   ├── field-contribution-receipt.schema.json
│   ├── field-resource-reuse-request.schema.json
│   ├── field-resource-reuse-authorization.schema.json
│   ├── field-resource-lease.schema.json
│   ├── field-circulation-receipt.schema.json
│   ├── field-anomaly-evidence.schema.json
│   ├── field-residual-assessment.schema.json
│   ├── field-hazard-quarantine-record.schema.json
│   ├── field-revocation-propagation-record.schema.json
│   ├── field-federation-profile.schema.json
│   ├── field-federation-admission-record.schema.json
│   ├── field-policy-negotiation-record.schema.json
│   ├── cross-field-route-authorization.schema.json
│   ├── cross-field-circulation-receipt.schema.json
│   ├── multi-field-royalty-settlement-record.schema.json
│   └── federation-circulation-health-report.schema.json
├── scripts/
│   └── validate_examples.py
├── CHANGELOG.md
├── LICENSE
├── README.md
└── requirements.txt
```

---

## Validation

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run validation:

```bash
python scripts/validate_examples.py
```

The validator checks:

* required Schema files exist before loading;
* JSON Schema Draft 2020-12 meta-validity;
* YAML loading and document-root validity;
* protocol-version consistency;
* dependency-ordered pass-record construction;
* cross-record semantic invariants;
* expected-fail rejection behavior.

Validated set:

```text
21 schemas
42 pass examples
23 expected-fail examples
schema-meta-ok
yaml-load-ok
version-integrity-ok
Validation passed.
```

### Schema-file preflight

All 21 files declared by the validator must physically exist under `schemas/`.
In particular, the v0.5 federation layer requires:

```text
schemas/cross-field-circulation-receipt.schema.json
```

A missing file should be reported before Schema loading:

```text
[fatal] missing schema files:
  - schemas/cross-field-circulation-receipt.schema.json
```

This avoids a raw `FileNotFoundError` and makes repository-packaging omissions
immediately visible in local and CI runs.

---

## Security considerations

A federation amplifies both useful and harmful resources. Implementations should
assume that fields, participants, traces, policy references, digests, audits,
settlements, and health reports may be stale, incomplete, deceptive, or
malicious.

At minimum, implementations should provide:

* origin and authorization verification;
* policy-version pinning and digest verification;
* replay protection;
* target-side reassessment;
* contribution and lease limits;
* quarantine and revocation propagation;
* derivative-coverage checks;
* settlement reconciliation;
* route suspension;
* append-only or tamper-evident evidence.

> **Sharing without filtration is contamination. Federation without local sovereignty is merely centralization wearing a wider hat.**

---

## v1.0 direction

The intended v1.0 completion criteria are:

```text
stable identifiers
normative conformance language
cross-version migration rules
cross-protocol compatibility profiles
reference validation suite
federation revocation conformance
settlement and health-report conformance
```

---

## Human authorship note

Shidenkai Alpha is a human author and structural designer. The name does not
refer to an AI model or autonomous agent.

---

## License

MIT License. See `LICENSE`.
