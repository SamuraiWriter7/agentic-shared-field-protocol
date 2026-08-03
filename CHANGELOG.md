# Changelog

All notable changes to the Agentic Shared Field Protocol are documented in this
file.

The project follows Semantic Versioning after the `1.0.0` release. Versions
before `1.0.0` may introduce breaking changes.

---

## [Unreleased]

### Fixed

* Restored the omitted
  `schemas/cross-field-circulation-receipt.schema.json` file required by the
  v0.5 validator and federation record set.
* Added a Schema-file preflight so missing files are reported together before
  JSON loading instead of failing with a raw `FileNotFoundError`.
* Clarified the README validation requirements for all 21 Schema files.

---

## [0.5.0] - 2026-08-02

### Codename

**Federated Metabolic Mesh**

### Added

* `field-federation-profile` for federation governance, quorum, admission,
  routing, negotiation, settlement, and health policy.
* `field-federation-admission-record` for compatibility checks, trust levels,
  steward approvals, bounded grants, and membership lifecycle.
* `field-policy-negotiation-record` for strict source-target-federation policy
  intersection.
* `cross-field-route-authorization` for bounded resource domains, scopes, hop
  counts, lease duration, target reassessment, audit, Royalty, and revocation
  obligations.
* `cross-field-circulation-receipt` for closing transfers through the target
  field's normal contribution boundary.
* `multi-field-royalty-settlement-record` for allocations to origins, source
  fields, target fields, agents, and federation common pools.
* `federation-circulation-health-report` for failed-route rate, quarantine rate,
  settlement completion, revocation lag, threshold breaches, and health state.
* A second independently governed field and a complete source-to-target
  cross-field pass flow.
* Expected-fail examples for impossible settlement shares, insufficient
  admission quorum, scope-intersection violations, excessive route leases,
  target-outcome mismatch, allocation imbalance, and false healthy status.

### Changed

* Advanced all existing Schemas and examples from `0.4.0` to `0.5.0`.
* Expanded validation from 14 to 21 dependency-ordered record types.
* Expanded the validated corpus to 42 pass examples and 23 expected-fail
  examples.
* Preserved v0.4 immune continuity across field boundaries: a source resource
  quarantined or revoked before transfer is rejected.
* Required target fields to re-run the v0.2 intake boundary instead of trusting
  source-field admission.
* Fixed the v0.4 quarantine-assessment example version migration.

### Semantic invariants

* Federation quorum cannot exceed the number of declared stewards.
* Source-field, target-field, and common-pool reserved shares cannot exceed the
  full settlement amount.
* Field admission requires active membership state, compatible domains and
  scopes, passing checks, adequate trust, and sufficient approvals.
* Negotiated domains and scopes must exist in the source-target-federation
  intersection.
* Negotiated audit, derivative Trace, Royalty, revocation, and target
  reassessment terms follow the stricter applicable policy.
* Route authorization cannot exceed negotiated scope, lease duration, hop count,
  or expiry.
* Cross-field receipts must match the source resource, target envelope, target
  request, target receipt, lineage, resource domain, route, and target outcome.
* Active quarantine or prior revocation blocks cross-field transfer.
* Multi-field allocation sums must reconcile exactly and satisfy federation
  minimum shares.
* Health rates are recalculated from metrics, and health state must match
  threshold breaches.

### Validation

```text
21 schemas
42 pass examples
23 expected-fail examples
schema-meta-ok
yaml-load-ok
version-integrity-ok
Validation passed.
```

### Protocol boundary

Version `0.5.0` defines federation and cross-field circulation. It does not
create a global super-field, merge local governance, or grant ambient authority
across federation members.

---

## [0.4.0] - 2026-08-01

### Codename

**Field Immune Continuity**

### Added

* `field-anomaly-evidence` for inspectable anomaly signals, severity,
  confidence, detector references, and confirmation state.
* `field-residual-assessment` for `recoverable`, `dormant`, `hazardous`, and
  `exhausted` classification with fixed disposition mappings.
* `field-hazard-quarantine-record` for access, reuse, propagation, and active
  lease containment.
* `field-revocation-propagation-record` for downstream lease and derivative
  invalidation.
* Required field-level `immune_policy` governing evidence requirements,
  quarantine release, propagation depth, derivative coverage, dormant
  reassessment, and exhausted-resource handling.

### Semantic invariants

* `recoverable`, `dormant`, `hazardous`, and `exhausted` map to fixed
  dispositions.
* Hazardous residuals require quarantine and revocation.
* Safe resources cannot be quarantined without supporting anomaly evidence.
* Quarantine release requires the configured review or authorization evidence.
* Completed revocation propagation cannot leave required targets pending or
  failed.
* Known derivatives must be covered when derivative-completeness is required.

### Protocol boundary

Version `0.4.0` defines the immune and revocation-continuity layer within one
shared field.

---

## [0.3.0] - 2026-08-01

### Codename

**Leased Metabolic Circulation**

### Added

* `field-resource-reuse-request` for explicit temporary-use requests.
* `field-resource-reuse-authorization` for bounded reuse decisions.
* `field-resource-lease` for exact scopes, validity, and expiry.
* `field-circulation-receipt` for derivative, return, Royalty, revocation, and
  lease-closure evidence.

### Semantic invariants

* Granted scopes cannot exceed the request, participant binding, field policy,
  or resource rights.
* Lease duration cannot exceed authorization, retention, or envelope expiry.
* Use after lease expiry is rejected.
* Derivative use requires Trace evidence.
* A circulation cannot close without returned output, residual, or failure
  evidence.
* Applicable Royalty and revocation obligations remain visible at closure.

### Protocol boundary

Version `0.3.0` defines authorized reuse and circulation closure within one
shared field.

---

## [0.2.0] - 2026-08-01

### Codename

**Selective Intake Boundary**

### Added

* `shared-resource-envelope` for origin, digest, classification, and rights.
* `field-contribution-request` for controlled submission.
* `field-contribution-assessment` for authorization, compatibility, audit, and
  size evaluation.
* `field-contribution-receipt` for admission, rejection, quarantine, and
  human-review outcomes.
* Field-level contribution limits, accepted content modes, digest algorithms,
  duplicate handling, and quarantine support.

### Semantic invariants

* Contributors require the `contribute` scope.
* Resource domains must fit both the field and participant binding.
* Requested rights cannot exceed the resource envelope.
* Contribution size cannot exceed field or participant limits.
* Failed mandatory audits cannot produce an admitted receipt.
* Quarantine assessments cannot be rewritten as admitted outcomes.

### Protocol boundary

Version `0.2.0` defines controlled intake into a shared field.

---

## [0.1.0] - 2026-08-01

### Codename

**Selective Permeability Foundation**

### Added

* `shared-field-profile` for field identity, origin, governance, access,
  permeability, retention, and lifecycle policy.
* `field-participant-binding` for explicit participant admission, scopes,
  resource domains, conditions, and validity.
* Field kinds for knowledge, memory, reasoning, compute, value, and composite
  fields.
* Governance modes for stewarded, federated, and rule-bound fields.
* Resource classifications for verified, provisional, recoverable, dormant,
  hazardous, private, revoked, and exhausted resources.
* Initial JSON Schema Draft 2020-12 and semantic validation workflow.

### Semantic invariants

* Stewarded fields require at least one steward.
* Federated fields require at least two stewards.
* Default scopes must remain within allowed scopes.
* Accepted and rejected classifications cannot overlap.
* Admitted participants require explicit scopes and resource domains.
* Authorization receipts are required when field policy demands them.
* Only declared stewards may receive the `administer` scope.

### Protocol boundary

Version `0.1.0` defines field constitution and participant binding.
