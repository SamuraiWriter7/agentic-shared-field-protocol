#!/usr/bin/env python3
"""Validate Agentic Shared Field Protocol v0.5 examples."""

from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
PASS_DIR = ROOT / "examples" / "pass"
FAIL_DIR = ROOT / "examples" / "fail"

SCHEMA_FILES = {
    "shared-field-profile": SCHEMA_DIR / "shared-field-profile.schema.json",
    "field-participant-binding": SCHEMA_DIR
    / "field-participant-binding.schema.json",
    "shared-resource-envelope": SCHEMA_DIR
    / "shared-resource-envelope.schema.json",
    "field-contribution-request": SCHEMA_DIR
    / "field-contribution-request.schema.json",
    "field-contribution-assessment": SCHEMA_DIR
    / "field-contribution-assessment.schema.json",
    "field-contribution-receipt": SCHEMA_DIR
    / "field-contribution-receipt.schema.json",
    "field-resource-reuse-request": SCHEMA_DIR
    / "field-resource-reuse-request.schema.json",
    "field-resource-reuse-authorization": SCHEMA_DIR
    / "field-resource-reuse-authorization.schema.json",
    "field-resource-lease": SCHEMA_DIR
    / "field-resource-lease.schema.json",
    "field-circulation-receipt": SCHEMA_DIR
    / "field-circulation-receipt.schema.json",
    "field-anomaly-evidence": SCHEMA_DIR / "field-anomaly-evidence.schema.json",
    "field-residual-assessment": SCHEMA_DIR / "field-residual-assessment.schema.json",
    "field-hazard-quarantine-record": SCHEMA_DIR / "field-hazard-quarantine-record.schema.json",
    "field-revocation-propagation-record": SCHEMA_DIR / "field-revocation-propagation-record.schema.json",
    "field-federation-profile": SCHEMA_DIR / "field-federation-profile.schema.json",
    "field-federation-admission-record": SCHEMA_DIR / "field-federation-admission-record.schema.json",
    "field-policy-negotiation-record": SCHEMA_DIR / "field-policy-negotiation-record.schema.json",
    "cross-field-route-authorization": SCHEMA_DIR / "cross-field-route-authorization.schema.json",
    "cross-field-circulation-receipt": SCHEMA_DIR / "cross-field-circulation-receipt.schema.json",
    "multi-field-royalty-settlement-record": SCHEMA_DIR / "multi-field-royalty-settlement-record.schema.json",
    "federation-circulation-health-report": SCHEMA_DIR / "federation-circulation-health-report.schema.json",
}

TYPE_ORDER = [
    "shared-field-profile",
    "field-participant-binding",
    "shared-resource-envelope",
    "field-contribution-request",
    "field-contribution-assessment",
    "field-contribution-receipt",
    "field-resource-reuse-request",
    "field-resource-reuse-authorization",
    "field-resource-lease",
    "field-circulation-receipt",
    "field-anomaly-evidence",
    "field-residual-assessment",
    "field-hazard-quarantine-record",
    "field-revocation-propagation-record",
    "field-federation-profile",
    "field-federation-admission-record",
    "field-policy-negotiation-record",
    "cross-field-route-authorization",
    "cross-field-circulation-receipt",
    "multi-field-royalty-settlement-record",
    "federation-circulation-health-report",
]

ID_FIELDS = {
    "shared-field-profile": "field_id",
    "field-participant-binding": "binding_id",
    "shared-resource-envelope": "envelope_id",
    "field-contribution-request": "request_id",
    "field-contribution-assessment": "assessment_id",
    "field-contribution-receipt": "receipt_id",
    "field-resource-reuse-request": "reuse_request_id",
    "field-resource-reuse-authorization": "reuse_authorization_id",
    "field-resource-lease": "lease_id",
    "field-circulation-receipt": "circulation_receipt_id",
    "field-anomaly-evidence": "anomaly_evidence_id",
    "field-residual-assessment": "residual_assessment_id",
    "field-hazard-quarantine-record": "quarantine_record_id",
    "field-revocation-propagation-record": "propagation_record_id",
    "field-federation-profile": "federation_id",
    "field-federation-admission-record": "admission_id",
    "field-policy-negotiation-record": "negotiation_id",
    "cross-field-route-authorization": "route_authorization_id",
    "cross-field-circulation-receipt": "cross_field_receipt_id",
    "multi-field-royalty-settlement-record": "settlement_id",
    "federation-circulation-health-report": "health_report_id",
}

PARTICIPANT_PREFIXES = {
    "human": "human:",
    "agent": "agent:",
    "organization": "org:",
    "service": "service:",
}

RESOURCE_KIND_DOMAINS = {
    "knowledge-fragment": "knowledge",
    "memory-residue": "memory",
    "reasoning-artifact": "reasoning",
    "compute-offer": "compute",
    "value-claim": "value",
}

DIGEST_LENGTHS = {
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}

DECISION_OUTCOMES = {
    "accept": "admitted",
    "reject": "rejected",
    "quarantine": "quarantined",
    "human-review-required": "pending-human-review",
}

Registry = dict[str, dict[str, dict[str, Any]]]


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise ValueError("document root must be a mapping")

    return data


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError("schema root must be an object")

    return data


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_path(error: Any) -> str:
    if not error.absolute_path:
        return "<root>"

    return ".".join(str(part) for part in error.absolute_path)


def schema_errors(
    document: dict[str, Any],
    validators: dict[str, Draft202012Validator],
) -> list[str]:
    record_type = document.get("record_type")
    validator = validators.get(record_type)

    if validator is None:
        return [f"<root>: unknown record_type {record_type!r}"]

    errors = sorted(
        validator.iter_errors(document),
        key=lambda item: list(item.absolute_path),
    )

    return [
        f"{format_path(error)}: {error.message}"
        for error in errors
    ]


def get_record(
    registry: Registry,
    record_type: str,
    record_id: str,
    field_name: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    record = registry[record_type].get(record_id)

    if record is None:
        return None, [
            f"{field_name}: unknown {record_type} {record_id!r}"
        ]

    return record, []


def find_field_resource_receipt(
    registry: Registry,
    field_resource_id: str,
) -> dict[str, Any] | None:
    for receipt in registry["field-contribution-receipt"].values():
        if (
            receipt.get("outcome") == "admitted"
            and receipt.get("field_resource_id") == field_resource_id
        ):
            return receipt
    return None


def validate_shared_field_profile(
    document: dict[str, Any],
    _: Registry,
) -> list[str]:
    errors: list[str] = []

    governance = document["governance"]
    mode = governance["governance_mode"]
    stewards = governance["steward_ids"]

    if mode == "stewarded" and not stewards:
        errors.append(
            "governance.steward_ids: "
            "stewarded fields require at least one steward"
        )

    if mode == "federated" and len(stewards) < 2:
        errors.append(
            "governance.steward_ids: "
            "federated fields require at least two stewards"
        )

    field_kind = document["field_kind"]
    domains = set(document["resource_domains"])

    if field_kind != "composite" and domains != {field_kind}:
        errors.append(
            "resource_domains: a non-composite field must contain "
            f"exactly its field_kind {field_kind!r}"
        )

    if field_kind == "composite" and len(domains) < 2:
        errors.append(
            "resource_domains: a composite field requires at least "
            "two domains"
        )

    access = document["access_policy"]
    allowed_scopes = set(access["allowed_access_scopes"])
    default_scopes = set(access["default_access_scopes"])
    excess_defaults = sorted(default_scopes - allowed_scopes)

    if excess_defaults:
        errors.append(
            "access_policy.default_access_scopes: scopes not present "
            f"in allowed_access_scopes: {excess_defaults}"
        )

    if (
        access["anonymous_access_allowed"]
        and access["authorization_required"]
    ):
        errors.append(
            "access_policy: anonymous_access_allowed cannot be true "
            "when authorization_required is true"
        )

    inbound = document["permeability_policy"]["inbound"]
    accepted = set(inbound["accepted_classifications"])
    rejected = set(inbound["rejected_classifications"])
    overlap = sorted(accepted & rejected)

    if overlap:
        errors.append(
            "permeability_policy.inbound: accepted_classifications "
            "and rejected_classifications overlap: "
            f"{overlap}"
        )

    contribution = document["contribution_policy"]

    if (
        contribution["duplicate_handling"] == "replace"
        and document["retention_policy"]["tombstone_required"] is False
    ):
        errors.append(
            "contribution_policy.duplicate_handling: replace requires "
            "retention_policy.tombstone_required to be true"
        )

    reuse = document["reuse_policy"]
    reuse_scopes = set(reuse["allowed_reuse_scopes"])
    invalid_reuse_scopes = sorted(reuse_scopes - allowed_scopes)
    if invalid_reuse_scopes:
        errors.append(
            "reuse_policy.allowed_reuse_scopes: scopes not present in "
            f"access_policy.allowed_access_scopes: {invalid_reuse_scopes}"
        )

    if (
        reuse["derived_resource_return_required"]
        and "derive" not in reuse_scopes
    ):
        errors.append(
            "reuse_policy.derived_resource_return_required: derive must be "
            "an allowed reuse scope"
        )

    if (
        reuse["derived_resource_return_required"]
        and not reuse["circulation_receipt_required"]
    ):
        errors.append(
            "reuse_policy: derived resource return requires circulation "
            "receipts"
        )

    immune = document["immune_policy"]
    accepted_residuals = set(immune["accepted_residual_classifications"])
    required_residuals = {"recoverable", "dormant", "hazardous", "exhausted"}
    if accepted_residuals != required_residuals:
        errors.append(
            "immune_policy.accepted_residual_classifications: "
            "must contain all four residual classes exactly"
        )
    quarantine_classes = set(immune["quarantine_classifications"])
    if "hazardous" not in quarantine_classes:
        errors.append(
            "immune_policy.quarantine_classifications: hazardous is required"
        )
    if not quarantine_classes <= rejected:
        errors.append(
            "immune_policy.quarantine_classifications: must also be rejected "
            "by inbound permeability"
        )
    evidence_classes = set(immune["anomaly_evidence_required_for"])
    if not evidence_classes <= quarantine_classes:
        errors.append(
            "immune_policy.anomaly_evidence_required_for: must be a subset "
            "of quarantine classifications"
        )
    if quarantine_classes and not contribution["quarantine_supported"]:
        errors.append(
            "immune_policy: quarantine requires contribution quarantine support"
        )
    if (
        immune["revocation_propagation_required"]
        and not document["permeability_policy"]["outbound"][
            "revocation_propagation_required"
        ]
    ):
        errors.append(
            "immune_policy.revocation_propagation_required: outbound policy "
            "must also require propagation"
        )
    if (
        immune["require_known_derivative_coverage"]
        and not immune["revocation_propagation_required"]
    ):
        errors.append(
            "immune_policy.require_known_derivative_coverage: requires "
            "revocation propagation"
        )
    if (
        immune["exhausted_action"] in {"tombstone", "delete-after-tombstone"}
        and not document["retention_policy"]["tombstone_required"]
    ):
        errors.append(
            "immune_policy.exhausted_action: tombstone action requires "
            "retention_policy.tombstone_required"
        )

    retention = document["retention_policy"]
    has_maximum = "max_retention_seconds" in retention

    if retention["mode"] == "bounded" and not has_maximum:
        errors.append(
            "retention_policy.max_retention_seconds: required when "
            "mode is bounded"
        )

    if retention["mode"] != "bounded" and has_maximum:
        errors.append(
            "retention_policy.max_retention_seconds: allowed only "
            "when mode is bounded"
        )

    created_at = parse_datetime(document["created_at"])
    updated_at = parse_datetime(document["updated_at"])
    origin_created_at = parse_datetime(document["origin"]["created_at"])

    if updated_at < created_at:
        errors.append("updated_at: must not be earlier than created_at")

    if origin_created_at > created_at:
        errors.append(
            "origin.created_at: must not be later than field created_at"
        )

    return errors


def validate_field_participant_binding(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, lookup_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    errors.extend(lookup_errors)

    if field is None:
        return errors

    participant = document["participant"]
    participant_type = participant["participant_type"]
    participant_id = participant["participant_id"]
    expected_prefix = PARTICIPANT_PREFIXES[participant_type]

    if not participant_id.startswith(expected_prefix):
        errors.append(
            "participant.participant_id: expected prefix "
            f"{expected_prefix!r} for participant_type "
            f"{participant_type!r}"
        )

    access = field["access_policy"]

    if participant_type not in access["allowed_participant_types"]:
        errors.append(
            "participant.participant_type: type is not admitted by "
            "the field"
        )

    decision = document["decision"]
    scopes = set(document["granted_access_scopes"])
    domains = set(document["allowed_resource_domains"])
    lifecycle = document["lifecycle_status"]

    if decision == "admitted":
        if not scopes:
            errors.append(
                "granted_access_scopes: admitted participants need "
                "at least one scope"
            )
        if not domains:
            errors.append(
                "allowed_resource_domains: admitted participants need "
                "at least one domain"
            )
    else:
        if scopes:
            errors.append(
                "granted_access_scopes: denied or suspended "
                "participants must have no scopes"
            )
        if domains:
            errors.append(
                "allowed_resource_domains: denied or suspended "
                "participants must have no domains"
            )

    if decision in {"denied", "suspended"} and lifecycle != "inactive":
        errors.append(
            f"lifecycle_status: {decision} bindings must be inactive"
        )

    excess_scopes = sorted(
        scopes - set(access["allowed_access_scopes"])
    )
    if excess_scopes:
        errors.append(
            "granted_access_scopes: scopes exceed field policy: "
            f"{excess_scopes}"
        )

    excess_domains = sorted(
        domains - set(field["resource_domains"])
    )
    if excess_domains:
        errors.append(
            "allowed_resource_domains: domains exceed field profile: "
            f"{excess_domains}"
        )

    if (
        "administer" in scopes
        and participant_id not in field["governance"]["steward_ids"]
    ):
        errors.append(
            "granted_access_scopes: administer may be granted only "
            "to a field steward"
        )

    if (
        decision == "admitted"
        and access["authorization_required"]
        and not document.get("authorization_receipt_id")
    ):
        errors.append(
            "authorization_receipt_id: required for admission to "
            "this field"
        )

    if (
        decision == "admitted"
        and lifecycle == "active"
        and field["status"] != "active"
    ):
        errors.append(
            "lifecycle_status: an active binding cannot target a "
            "non-active field"
        )

    valid_from = parse_datetime(document["valid_from"])
    valid_until_raw = document.get("valid_until")
    if valid_until_raw is not None:
        valid_until = parse_datetime(valid_until_raw)
        if valid_until <= valid_from:
            errors.append("valid_until: must be later than valid_from")

    issued_at = parse_datetime(document["issued_at"])
    if issued_at > valid_from:
        errors.append("issued_at: must not be later than valid_from")

    conditions = document["conditions"]
    inbound = field["permeability_policy"]["inbound"]
    outbound = field["permeability_policy"]["outbound"]

    if "contribute" in scopes:
        if "max_contribution_bytes" not in conditions:
            errors.append(
                "conditions.max_contribution_bytes: required for "
                "participants with contribute scope"
            )
        elif conditions["max_contribution_bytes"] > field[
            "contribution_policy"
        ]["max_resource_bytes"]:
            errors.append(
                "conditions.max_contribution_bytes: must not exceed "
                "the field contribution limit"
            )

        if (
            inbound["audit_required"]
            and not conditions["contribution_audit_required"]
        ):
            errors.append(
                "conditions.contribution_audit_required: must be true "
                "for contributors"
            )

    derivative_scopes = {"derive", "redistribute", "commercialize"}
    if scopes & derivative_scopes:
        if (
            outbound["derivative_trace_required"]
            and not conditions["derivative_trace_required"]
        ):
            errors.append(
                "conditions.derivative_trace_required: must be true "
                "for derivative scopes"
            )
        if (
            outbound["royalty_settlement_required"]
            and not conditions.get("royalty_policy_ref")
        ):
            errors.append(
                "conditions.royalty_policy_ref: required for "
                "derivative scopes"
            )

    reusable_scopes = {
        "read", "derive", "execute", "redistribute", "commercialize"
    }
    if scopes & reusable_scopes:
        if "max_lease_seconds" not in conditions:
            errors.append(
                "conditions.max_lease_seconds: required for reusable scopes"
            )
        elif conditions["max_lease_seconds"] > field["reuse_policy"][
            "max_lease_seconds"
        ]:
            errors.append(
                "conditions.max_lease_seconds: must not exceed field reuse "
                "policy"
            )

        if "max_active_leases" not in conditions:
            errors.append(
                "conditions.max_active_leases: required for reusable scopes"
            )

    return errors


def validate_shared_resource_envelope(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, field_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    binding, binding_errors = get_record(
        registry,
        "field-participant-binding",
        document["contributor_binding_id"],
        "contributor_binding_id",
    )
    errors.extend(field_errors)
    errors.extend(binding_errors)

    if field is None or binding is None:
        return errors

    if binding["field_id"] != document["field_id"]:
        errors.append(
            "contributor_binding_id: binding belongs to a different field"
        )

    if binding["decision"] != "admitted" or binding[
        "lifecycle_status"
    ] != "active":
        errors.append(
            "contributor_binding_id: contributor binding must be "
            "admitted and active"
        )

    if "contribute" not in binding["granted_access_scopes"]:
        errors.append(
            "contributor_binding_id: binding lacks contribute scope"
        )

    domain = document["resource_domain"]
    expected_domain = RESOURCE_KIND_DOMAINS[document["resource_kind"]]

    if domain != expected_domain:
        errors.append(
            "resource_kind: does not match resource_domain; expected "
            f"{expected_domain!r}"
        )

    if domain not in field["resource_domains"]:
        errors.append(
            "resource_domain: domain is not exposed by the field"
        )

    if domain not in binding["allowed_resource_domains"]:
        errors.append(
            "resource_domain: domain is not granted to the contributor"
        )

    content = document["content"]
    contribution = field["contribution_policy"]

    if content["mode"] not in contribution["allowed_content_modes"]:
        errors.append(
            "content.mode: mode is not allowed by field policy"
        )

    algorithm = content["digest"]["algorithm"]
    digest_value = content["digest"]["value"]

    if algorithm not in contribution["required_digest_algorithms"]:
        errors.append(
            "content.digest.algorithm: algorithm is not accepted by "
            "field policy"
        )

    if len(digest_value) != DIGEST_LENGTHS[algorithm]:
        errors.append(
            "content.digest.value: digest length does not match "
            f"{algorithm}"
        )

    if content["size_bytes"] > contribution["max_resource_bytes"]:
        errors.append(
            "content.size_bytes: exceeds field max_resource_bytes"
        )

    binding_max = binding["conditions"].get("max_contribution_bytes")
    if binding_max is not None and content["size_bytes"] > binding_max:
        errors.append(
            "content.size_bytes: exceeds contributor binding limit"
        )

    inbound = field["permeability_policy"]["inbound"]
    if inbound["origin_trace_required"] and not document["origin"].get(
        "origin_trace_id"
    ):
        errors.append(
            "origin.origin_trace_id: required by field policy"
        )

    produced_at = parse_datetime(document["origin"]["produced_at"])
    created_at = parse_datetime(document["created_at"])
    if produced_at > created_at:
        errors.append(
            "origin.produced_at: must not be later than created_at"
        )

    expires_at_raw = document.get("expires_at")
    if expires_at_raw is not None:
        expires_at = parse_datetime(expires_at_raw)
        if expires_at <= created_at:
            errors.append("expires_at: must be later than created_at")

    if document["lifecycle_status"] != "proposed":
        errors.append(
            "lifecycle_status: a contribution envelope must be proposed"
        )

    rights = document["rights"]
    derivative_scopes = {"derive", "redistribute", "commercialize"}
    if (
        set(rights["permitted_scopes"]) & derivative_scopes
        and field["permeability_policy"]["outbound"][
            "royalty_settlement_required"
        ]
        and not rights.get("royalty_policy_ref")
    ):
        errors.append(
            "rights.royalty_policy_ref: required when derivative rights "
            "are permitted"
        )

    return errors


def validate_field_contribution_request(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, field_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    envelope, envelope_errors = get_record(
        registry,
        "shared-resource-envelope",
        document["envelope_id"],
        "envelope_id",
    )
    binding, binding_errors = get_record(
        registry,
        "field-participant-binding",
        document["contributor_binding_id"],
        "contributor_binding_id",
    )
    errors.extend(field_errors)
    errors.extend(envelope_errors)
    errors.extend(binding_errors)

    if field is None or envelope is None or binding is None:
        return errors

    if envelope["field_id"] != document["field_id"]:
        errors.append("envelope_id: envelope belongs to a different field")

    if binding["field_id"] != document["field_id"]:
        errors.append(
            "contributor_binding_id: binding belongs to a different field"
        )

    if envelope["contributor_binding_id"] != document[
        "contributor_binding_id"
    ]:
        errors.append(
            "contributor_binding_id: does not match envelope contributor"
        )

    if binding["decision"] != "admitted" or binding[
        "lifecycle_status"
    ] != "active":
        errors.append(
            "contributor_binding_id: binding must be admitted and active"
        )

    if "contribute" not in binding["granted_access_scopes"]:
        errors.append(
            "contributor_binding_id: binding lacks contribute scope"
        )

    if envelope["lifecycle_status"] != "proposed":
        errors.append("envelope_id: envelope is not proposed")

    requested_scopes = set(document["requested_access_scopes"])
    permitted_scopes = set(envelope["rights"]["permitted_scopes"])
    excess_scopes = sorted(requested_scopes - permitted_scopes)

    if excess_scopes:
        errors.append(
            "requested_access_scopes: scopes exceed envelope rights: "
            f"{excess_scopes}"
        )

    disposition = document["requested_disposition"]
    duplicate_policy = field["contribution_policy"]["duplicate_handling"]
    if disposition != "admit" and disposition != duplicate_policy:
        errors.append(
            "requested_disposition: does not match field duplicate policy "
            f"{duplicate_policy!r}"
        )

    submitted_at = parse_datetime(document["submitted_at"])
    created_at = parse_datetime(envelope["created_at"])
    if submitted_at < created_at:
        errors.append(
            "submitted_at: must not be earlier than envelope created_at"
        )

    valid_from = parse_datetime(binding["valid_from"])
    if submitted_at < valid_from:
        errors.append(
            "submitted_at: occurs before contributor binding validity"
        )

    valid_until_raw = binding.get("valid_until")
    if valid_until_raw and submitted_at >= parse_datetime(valid_until_raw):
        errors.append(
            "submitted_at: occurs after contributor binding validity"
        )

    requested_retention = document.get("requested_retention_seconds")
    retention = field["retention_policy"]
    if requested_retention is not None:
        if (
            retention["mode"] == "bounded"
            and requested_retention > retention["max_retention_seconds"]
        ):
            errors.append(
                "requested_retention_seconds: exceeds field retention limit"
            )

        expires_at_raw = envelope.get("expires_at")
        if expires_at_raw is not None:
            requested_end = submitted_at + timedelta(
                seconds=requested_retention
            )
            if requested_end > parse_datetime(expires_at_raw):
                errors.append(
                    "requested_retention_seconds: extends beyond envelope "
                    "expires_at"
                )

    return errors


def expected_assessment_checks(
    request: dict[str, Any],
    envelope: dict[str, Any],
    binding: dict[str, Any],
    field: dict[str, Any],
) -> dict[str, str]:
    inbound = field["permeability_policy"]["inbound"]
    classification = envelope["proposed_classification"]
    accepted = set(inbound["accepted_classifications"])
    rejected = set(inbound["rejected_classifications"])
    size_limit = min(
        field["contribution_policy"]["max_resource_bytes"],
        binding["conditions"].get(
            "max_contribution_bytes",
            field["contribution_policy"]["max_resource_bytes"],
        ),
    )

    return {
        "origin_trace": (
            "pass"
            if envelope["origin"].get("origin_trace_id")
            else "fail"
        ),
        "contributor_authorization": (
            "pass"
            if binding["decision"] == "admitted"
            and binding["lifecycle_status"] == "active"
            and "contribute" in binding["granted_access_scopes"]
            else "fail"
        ),
        "domain_compatibility": (
            "pass"
            if envelope["resource_domain"] in field["resource_domains"]
            and envelope["resource_domain"]
            in binding["allowed_resource_domains"]
            else "fail"
        ),
        "classification_compatibility": (
            "pass"
            if classification in accepted and classification not in rejected
            else "fail"
        ),
        "size_limit": (
            "pass"
            if envelope["content"]["size_bytes"] <= size_limit
            else "fail"
        ),
        "rights_compatibility": (
            "pass"
            if set(request["requested_access_scopes"])
            <= set(envelope["rights"]["permitted_scopes"])
            else "fail"
        ),
        "content_audit": (
            "not-required" if not inbound["audit_required"] else "pass"
        ),
    }


def validate_field_contribution_assessment(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    request, request_errors = get_record(
        registry,
        "field-contribution-request",
        document["request_id"],
        "request_id",
    )
    errors.extend(request_errors)

    if request is None:
        return errors

    envelope = registry["shared-resource-envelope"].get(
        request["envelope_id"]
    )
    field = registry["shared-field-profile"].get(request["field_id"])
    binding = registry["field-participant-binding"].get(
        request["contributor_binding_id"]
    )

    if envelope is None or field is None or binding is None:
        errors.append(
            "request_id: referenced request dependencies are incomplete"
        )
        return errors

    if document["field_id"] != request["field_id"]:
        errors.append("field_id: does not match contribution request")

    if document["envelope_id"] != request["envelope_id"]:
        errors.append("envelope_id: does not match contribution request")

    expected = expected_assessment_checks(
        request,
        envelope,
        binding,
        field,
    )

    for check_name in [
        "origin_trace",
        "contributor_authorization",
        "domain_compatibility",
        "classification_compatibility",
        "size_limit",
        "rights_compatibility",
    ]:
        actual = document["checks"][check_name]
        if actual != expected[check_name]:
            errors.append(
                f"checks.{check_name}: expected {expected[check_name]!r} "
                f"from referenced records, got {actual!r}"
            )

    inbound = field["permeability_policy"]["inbound"]
    decision = document["decision"]
    checks = document["checks"]
    failed_checks = sorted(
        name for name, result in checks.items() if result == "fail"
    )
    resolved = document.get("resolved_classification")

    if decision == "accept":
        if failed_checks:
            errors.append(
                "decision: accept is forbidden when checks fail: "
                f"{failed_checks}"
            )
        if inbound["audit_required"] and checks["content_audit"] != "pass":
            errors.append(
                "checks.content_audit: must pass before acceptance"
            )
        if resolved is None:
            errors.append(
                "resolved_classification: required for acceptance"
            )
        elif resolved not in inbound["accepted_classifications"]:
            errors.append(
                "resolved_classification: accepted contribution must use "
                "an accepted field classification"
            )

    elif decision == "reject":
        if not failed_checks:
            errors.append(
                "decision: reject requires at least one failed check"
            )

    elif decision == "quarantine":
        if not field["contribution_policy"]["quarantine_supported"]:
            errors.append(
                "decision: field does not support quarantine"
            )
        if not failed_checks and resolved != "hazardous":
            errors.append(
                "decision: quarantine requires a failed check or "
                "hazardous classification"
            )
        if resolved is None:
            errors.append(
                "resolved_classification: required for quarantine"
            )

    assessed_at = parse_datetime(document["assessed_at"])
    submitted_at = parse_datetime(request["submitted_at"])
    if assessed_at < submitted_at:
        errors.append(
            "assessed_at: must not be earlier than request submitted_at"
        )

    return errors


def validate_field_contribution_receipt(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    request, request_errors = get_record(
        registry,
        "field-contribution-request",
        document["request_id"],
        "request_id",
    )
    assessment, assessment_errors = get_record(
        registry,
        "field-contribution-assessment",
        document["assessment_id"],
        "assessment_id",
    )
    errors.extend(request_errors)
    errors.extend(assessment_errors)

    if request is None or assessment is None:
        return errors

    field = registry["shared-field-profile"].get(request["field_id"])
    if field is None:
        errors.append("request_id: referenced field is unavailable")
        return errors

    if assessment["request_id"] != document["request_id"]:
        errors.append(
            "assessment_id: assessment belongs to a different request"
        )

    if document["field_id"] != request["field_id"]:
        errors.append("field_id: does not match contribution request")

    if document["envelope_id"] != request["envelope_id"]:
        errors.append("envelope_id: does not match contribution request")

    expected_outcome = DECISION_OUTCOMES[assessment["decision"]]
    if document["outcome"] != expected_outcome:
        errors.append(
            "outcome: does not match assessment decision; expected "
            f"{expected_outcome!r}"
        )

    outcome = document["outcome"]
    field_resource_id = document.get("field_resource_id")
    quarantine_record_id = document.get("quarantine_record_id")
    admitted_at_raw = document.get("admitted_at")
    effective = document.get("effective_classification")
    resolved = assessment.get("resolved_classification")

    if effective is not None and resolved is not None and effective != resolved:
        errors.append(
            "effective_classification: must match assessment "
            "resolved_classification"
        )

    obligations = document["obligations"]
    outbound = field["permeability_policy"]["outbound"]

    if outcome == "admitted":
        if not field_resource_id:
            errors.append(
                "field_resource_id: required for admitted contributions"
            )
        if quarantine_record_id:
            errors.append(
                "quarantine_record_id: forbidden for admitted contributions"
            )
        if admitted_at_raw is None:
            errors.append("admitted_at: required for admitted contributions")
        if effective is None:
            errors.append(
                "effective_classification: required for admitted "
                "contributions"
            )
        elif effective not in field["permeability_policy"]["inbound"][
            "accepted_classifications"
        ]:
            errors.append(
                "effective_classification: is not accepted by field policy"
            )

        for key in [
            "derivative_trace_required",
            "royalty_settlement_required",
            "revocation_propagation_required",
        ]:
            if obligations[key] != outbound[key]:
                errors.append(
                    f"obligations.{key}: must mirror field outbound policy"
                )

        if admitted_at_raw is not None:
            admitted_at = parse_datetime(admitted_at_raw)
            assessed_at = parse_datetime(assessment["assessed_at"])
            if admitted_at < assessed_at:
                errors.append(
                    "admitted_at: must not be earlier than assessed_at"
                )

            requested_retention = request.get(
                "requested_retention_seconds"
            )
            retention_until_raw = obligations.get("retention_until")
            if requested_retention is not None:
                if retention_until_raw is None:
                    errors.append(
                        "obligations.retention_until: required when the "
                        "request specifies retention"
                    )
                else:
                    expected_until = admitted_at + timedelta(
                        seconds=requested_retention
                    )
                    if parse_datetime(retention_until_raw) != expected_until:
                        errors.append(
                            "obligations.retention_until: must equal "
                            "admitted_at plus requested_retention_seconds"
                        )

    elif outcome == "quarantined":
        if not quarantine_record_id:
            errors.append(
                "quarantine_record_id: required for quarantined "
                "contributions"
            )
        if field_resource_id:
            errors.append(
                "field_resource_id: forbidden for quarantined contributions"
            )
        if admitted_at_raw is not None:
            errors.append(
                "admitted_at: forbidden for quarantined contributions"
            )
        if obligations["derivative_trace_required"]:
            errors.append(
                "obligations.derivative_trace_required: must be false "
                "while quarantined"
            )
        if obligations["royalty_settlement_required"]:
            errors.append(
                "obligations.royalty_settlement_required: must be false "
                "while quarantined"
            )

    elif outcome in {"rejected", "pending-human-review"}:
        if field_resource_id:
            errors.append(
                "field_resource_id: forbidden unless outcome is admitted"
            )
        if quarantine_record_id:
            errors.append(
                "quarantine_record_id: forbidden unless outcome is "
                "quarantined"
            )
        if admitted_at_raw is not None:
            errors.append(
                "admitted_at: forbidden unless outcome is admitted"
            )

    issued_at = parse_datetime(document["issued_at"])
    assessed_at = parse_datetime(assessment["assessed_at"])
    if issued_at < assessed_at:
        errors.append(
            "issued_at: must not be earlier than assessment assessed_at"
        )

    return errors



def validate_field_resource_reuse_request(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, field_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    binding, binding_errors = get_record(
        registry,
        "field-participant-binding",
        document["requester_binding_id"],
        "requester_binding_id",
    )
    errors.extend(field_errors)
    errors.extend(binding_errors)

    resource_receipt = find_field_resource_receipt(
        registry,
        document["field_resource_id"],
    )
    if resource_receipt is None:
        errors.append(
            "field_resource_id: no admitted contribution receipt exists"
        )

    if field is None or binding is None or resource_receipt is None:
        return errors

    if resource_receipt["field_id"] != document["field_id"]:
        errors.append(
            "field_resource_id: resource belongs to a different field"
        )

    if binding["field_id"] != document["field_id"]:
        errors.append(
            "requester_binding_id: binding belongs to a different field"
        )

    if (
        binding["decision"] != "admitted"
        or binding["lifecycle_status"] != "active"
    ):
        errors.append(
            "requester_binding_id: binding must be admitted and active"
        )

    envelope = registry["shared-resource-envelope"].get(
        resource_receipt["envelope_id"]
    )
    if envelope is None:
        errors.append(
            "field_resource_id: admitted resource envelope is unavailable"
        )
        return errors

    requested_scopes = set(document["requested_scopes"])
    field_scopes = set(field["reuse_policy"]["allowed_reuse_scopes"])
    binding_scopes = set(binding["granted_access_scopes"])
    rights_scopes = set(envelope["rights"]["permitted_scopes"])

    excess_field = sorted(requested_scopes - field_scopes)
    if excess_field:
        errors.append(
            "requested_scopes: scopes exceed field reuse policy: "
            f"{excess_field}"
        )

    excess_binding = sorted(requested_scopes - binding_scopes)
    if excess_binding:
        errors.append(
            "requested_scopes: scopes exceed requester binding: "
            f"{excess_binding}"
        )

    excess_rights = sorted(requested_scopes - rights_scopes)
    if excess_rights:
        errors.append(
            "requested_scopes: scopes exceed resource rights: "
            f"{excess_rights}"
        )

    if envelope["resource_domain"] not in binding["allowed_resource_domains"]:
        errors.append(
            "requester_binding_id: binding does not permit the resource domain"
        )

    requested_lease = document["requested_lease_seconds"]
    max_lease = min(
        field["reuse_policy"]["max_lease_seconds"],
        binding["conditions"].get(
            "max_lease_seconds",
            field["reuse_policy"]["max_lease_seconds"],
        ),
    )
    if requested_lease > max_lease:
        errors.append(
            "requested_lease_seconds: exceeds field or participant lease limit"
        )

    requested_at = parse_datetime(document["requested_at"])
    admitted_at = parse_datetime(resource_receipt["admitted_at"])
    if requested_at < admitted_at:
        errors.append(
            "requested_at: must not be earlier than resource admission"
        )

    valid_from = parse_datetime(binding["valid_from"])
    if requested_at < valid_from:
        errors.append(
            "requested_at: occurs before requester binding validity"
        )
    valid_until_raw = binding.get("valid_until")
    if valid_until_raw and requested_at >= parse_datetime(valid_until_raw):
        errors.append(
            "requested_at: occurs after requester binding validity"
        )

    retention_until_raw = resource_receipt["obligations"].get(
        "retention_until"
    )
    requested_end = requested_at + timedelta(seconds=requested_lease)
    if retention_until_raw and requested_end > parse_datetime(
        retention_until_raw
    ):
        errors.append(
            "requested_lease_seconds: extends beyond resource retention"
        )

    envelope_expires_raw = envelope.get("expires_at")
    if envelope_expires_raw and requested_end > parse_datetime(
        envelope_expires_raw
    ):
        errors.append(
            "requested_lease_seconds: extends beyond resource envelope expiry"
        )

    derivative_scopes = {"derive", "redistribute", "commercialize"}
    if requested_scopes & derivative_scopes:
        if (
            field["reuse_policy"]["derived_resource_return_required"]
            and not document["intended_return_kinds"]
        ):
            errors.append(
                "intended_return_kinds: required for derivative reuse"
            )

    if document["status"] != "pending":
        errors.append(
            "status: only pending requests may be authorized"
        )

    return errors


def validate_field_resource_reuse_authorization(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    request, request_errors = get_record(
        registry,
        "field-resource-reuse-request",
        document["reuse_request_id"],
        "reuse_request_id",
    )
    errors.extend(request_errors)
    if request is None:
        return errors

    field = registry["shared-field-profile"].get(request["field_id"])
    binding = registry["field-participant-binding"].get(
        request["requester_binding_id"]
    )
    resource_receipt = find_field_resource_receipt(
        registry,
        request["field_resource_id"],
    )
    if field is None or binding is None or resource_receipt is None:
        errors.append(
            "reuse_request_id: referenced dependencies are incomplete"
        )
        return errors

    envelope = registry["shared-resource-envelope"].get(
        resource_receipt["envelope_id"]
    )
    if envelope is None:
        errors.append(
            "reuse_request_id: admitted resource envelope is unavailable"
        )
        return errors

    for key in ["field_id", "field_resource_id", "requester_binding_id"]:
        if document[key] != request[key]:
            errors.append(f"{key}: does not match reuse request")

    authorized_at = parse_datetime(document["authorized_at"])
    requested_at = parse_datetime(request["requested_at"])
    if authorized_at < requested_at:
        errors.append(
            "authorized_at: must not be earlier than requested_at"
        )

    decision = document["decision"]
    granted = set(document["granted_scopes"])
    lease_seconds = document["lease_seconds"]
    conditions = document["conditions"]

    if decision == "authorized":
        if request["status"] != "pending":
            errors.append(
                "decision: only a pending reuse request may be authorized"
            )
        if not granted:
            errors.append(
                "granted_scopes: authorized reuse requires at least one scope"
            )

        requested_scopes = set(request["requested_scopes"])
        excess_requested = sorted(granted - requested_scopes)
        if excess_requested:
            errors.append(
                "granted_scopes: scopes were not requested: "
                f"{excess_requested}"
            )

        for label, permitted in [
            ("requester binding", set(binding["granted_access_scopes"])),
            ("field reuse policy", set(field["reuse_policy"]["allowed_reuse_scopes"])),
            ("resource rights", set(envelope["rights"]["permitted_scopes"])),
        ]:
            excess = sorted(granted - permitted)
            if excess:
                errors.append(
                    f"granted_scopes: scopes exceed {label}: {excess}"
                )

        max_lease = min(
            request["requested_lease_seconds"],
            field["reuse_policy"]["max_lease_seconds"],
            binding["conditions"].get(
                "max_lease_seconds",
                field["reuse_policy"]["max_lease_seconds"],
            ),
        )
        if lease_seconds < 1 or lease_seconds > max_lease:
            errors.append(
                "lease_seconds: must be positive and within all lease limits"
            )

        derivative_scopes = {"derive", "redistribute", "commercialize"}
        derivative_use = bool(granted & derivative_scopes)
        expected_derivative = (
            derivative_use
            and field["permeability_policy"]["outbound"][
                "derivative_trace_required"
            ]
        )
        expected_return = (
            derivative_use
            and field["reuse_policy"]["derived_resource_return_required"]
        )
        expected_royalty = (
            derivative_use
            and field["permeability_policy"]["outbound"][
                "royalty_settlement_required"
            ]
        )
        expected_revocation = resource_receipt["obligations"][
            "revocation_propagation_required"
        ]

        expectations = {
            "derivative_trace_required": expected_derivative,
            "return_record_required": expected_return,
            "royalty_settlement_required": expected_royalty,
            "revocation_propagation_required": expected_revocation,
        }
        for key, expected in expectations.items():
            if conditions[key] != expected:
                errors.append(
                    f"conditions.{key}: expected {expected!r} from policy"
                )

        expected_policy = None
        if expected_royalty:
            expected_policy = (
                envelope["rights"].get("royalty_policy_ref")
                or binding["conditions"].get("royalty_policy_ref")
            )
        if conditions.get("royalty_policy_ref") != expected_policy:
            errors.append(
                "conditions.royalty_policy_ref: does not match resource or "
                "binding royalty policy"
            )

        retention_until_raw = resource_receipt["obligations"].get(
            "retention_until"
        )
        if retention_until_raw:
            authorization_end = authorized_at + timedelta(
                seconds=lease_seconds
            )
            if authorization_end > parse_datetime(retention_until_raw):
                errors.append(
                    "lease_seconds: authorization extends beyond resource "
                    "retention"
                )

    else:
        if granted:
            errors.append(
                "granted_scopes: denied or review-required decisions grant "
                "no scopes"
            )
        if lease_seconds != 0:
            errors.append(
                "lease_seconds: denied or review-required decisions use zero"
            )

    return errors


def validate_field_resource_lease(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    authorization, lookup_errors = get_record(
        registry,
        "field-resource-reuse-authorization",
        document["reuse_authorization_id"],
        "reuse_authorization_id",
    )
    errors.extend(lookup_errors)
    if authorization is None:
        return errors

    if authorization["decision"] != "authorized":
        errors.append(
            "reuse_authorization_id: only authorized decisions may issue a lease"
        )

    mappings = {
        "field_id": "field_id",
        "field_resource_id": "field_resource_id",
        "lessee_binding_id": "requester_binding_id",
    }
    for lease_key, auth_key in mappings.items():
        if document[lease_key] != authorization[auth_key]:
            errors.append(
                f"{lease_key}: does not match reuse authorization"
            )

    if set(document["granted_scopes"]) != set(
        authorization["granted_scopes"]
    ):
        errors.append(
            "granted_scopes: must exactly match reuse authorization"
        )

    authorized_at = parse_datetime(authorization["authorized_at"])
    issued_at = parse_datetime(document["issued_at"])
    starts_at = parse_datetime(document["starts_at"])
    expires_at = parse_datetime(document["expires_at"])
    return_due_at = parse_datetime(document["return_due_at"])

    if issued_at < authorized_at:
        errors.append(
            "issued_at: must not be earlier than authorization"
        )
    if starts_at < issued_at:
        errors.append(
            "starts_at: must not be earlier than lease issuance"
        )

    expected_expiry = starts_at + timedelta(
        seconds=authorization["lease_seconds"]
    )
    if expires_at != expected_expiry:
        errors.append(
            "expires_at: must equal starts_at plus authorized lease_seconds"
        )
    if return_due_at != expires_at:
        errors.append(
            "return_due_at: must equal lease expires_at"
        )

    resource_receipt = find_field_resource_receipt(
        registry,
        document["field_resource_id"],
    )
    if resource_receipt is None:
        errors.append(
            "field_resource_id: no admitted resource exists"
        )
    else:
        retention_until_raw = resource_receipt["obligations"].get(
            "retention_until"
        )
        if retention_until_raw and expires_at > parse_datetime(
            retention_until_raw
        ):
            errors.append(
                "expires_at: lease exceeds resource retention"
            )

    if document["lease_status"] == "active" and expires_at <= starts_at:
        errors.append(
            "lease_status: active lease requires a positive time window"
        )

    return errors


def validate_field_circulation_receipt(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    lease, lease_errors = get_record(
        registry,
        "field-resource-lease",
        document["lease_id"],
        "lease_id",
    )
    authorization, auth_errors = get_record(
        registry,
        "field-resource-reuse-authorization",
        document["reuse_authorization_id"],
        "reuse_authorization_id",
    )
    request, request_errors = get_record(
        registry,
        "field-resource-reuse-request",
        document["reuse_request_id"],
        "reuse_request_id",
    )
    errors.extend(lease_errors)
    errors.extend(auth_errors)
    errors.extend(request_errors)
    if lease is None or authorization is None or request is None:
        return errors

    if lease["reuse_authorization_id"] != document["reuse_authorization_id"]:
        errors.append(
            "reuse_authorization_id: does not match lease"
        )
    if authorization["reuse_request_id"] != document["reuse_request_id"]:
        errors.append(
            "reuse_request_id: does not match authorization"
        )

    mappings = {
        "field_id": lease["field_id"],
        "field_resource_id": lease["field_resource_id"],
        "lessee_binding_id": lease["lessee_binding_id"],
    }
    for key, expected in mappings.items():
        if document[key] != expected:
            errors.append(f"{key}: does not match lease")

    usage = document["usage"]
    actual_scopes = set(usage["actual_scopes"])
    excess_scopes = sorted(actual_scopes - set(lease["granted_scopes"]))
    if excess_scopes:
        errors.append(
            "usage.actual_scopes: scopes exceed lease: "
            f"{excess_scopes}"
        )

    starts_at = parse_datetime(lease["starts_at"])
    expires_at = parse_datetime(lease["expires_at"])
    used_from = parse_datetime(usage["started_at"])
    used_until = parse_datetime(usage["ended_at"])

    if used_from < starts_at:
        errors.append(
            "usage.started_at: must not be earlier than lease starts_at"
        )
    if used_until < used_from:
        errors.append(
            "usage.ended_at: must not be earlier than usage.started_at"
        )
    if usage["status"] == "expired":
        if used_until < expires_at:
            errors.append(
                "usage.ended_at: expired usage must reach lease expiry"
            )
    elif used_until > expires_at:
        errors.append(
            "usage.ended_at: use continued after lease expiry"
        )

    completed_at = parse_datetime(document["completed_at"])
    issued_at = parse_datetime(document["issued_at"])
    if completed_at < used_until:
        errors.append(
            "completed_at: must not be earlier than usage.ended_at"
        )
    if issued_at < completed_at:
        errors.append(
            "issued_at: must not be earlier than completed_at"
        )

    conditions = authorization["conditions"]
    obligations = document["obligations"]
    derivative_scopes = {"derive", "redistribute", "commercialize"}
    derivative_use = bool(actual_scopes & derivative_scopes)

    if conditions["derivative_trace_required"] and derivative_use:
        if not obligations["derivative_trace_ids"]:
            errors.append(
                "obligations.derivative_trace_ids: required for derivative use"
            )

    if conditions["return_record_required"] and derivative_use:
        if not document["return_records"]:
            errors.append(
                "return_records: derivative use must return a resource or "
                "failure record"
            )

    for index, returned in enumerate(document["return_records"]):
        prefix = f"return_records.{index}"
        envelope = registry["shared-resource-envelope"].get(
            returned["envelope_id"]
        )
        contribution_request = registry["field-contribution-request"].get(
            returned["contribution_request_id"]
        )
        if envelope is None:
            errors.append(
                f"{prefix}.envelope_id: unknown shared-resource-envelope"
            )
            continue
        if contribution_request is None:
            errors.append(
                f"{prefix}.contribution_request_id: unknown contribution request"
            )
            continue

        if envelope["field_id"] != document["field_id"]:
            errors.append(
                f"{prefix}.envelope_id: returned resource targets another field"
            )
        if envelope["contributor_binding_id"] != document[
            "lessee_binding_id"
        ]:
            errors.append(
                f"{prefix}.envelope_id: return contributor is not the lessee"
            )
        if contribution_request["envelope_id"] != returned["envelope_id"]:
            errors.append(
                f"{prefix}.contribution_request_id: request references another envelope"
            )
        if contribution_request["contributor_binding_id"] != document[
            "lessee_binding_id"
        ]:
            errors.append(
                f"{prefix}.contribution_request_id: request contributor is not the lessee"
            )
        if document["field_resource_id"] not in envelope["origin"][
            "derivative_of"
        ]:
            errors.append(
                f"{prefix}.envelope_id: origin.derivative_of must include "
                "the leased field resource"
            )

        return_status = returned["return_status"]
        receipt_id = returned.get("contribution_receipt_id")
        if return_status == "submitted":
            if receipt_id is not None:
                errors.append(
                    f"{prefix}.contribution_receipt_id: forbidden while submitted"
                )
            if contribution_request["status"] != "pending":
                errors.append(
                    f"{prefix}.return_status: submitted requires a pending request"
                )
        else:
            if receipt_id is None:
                errors.append(
                    f"{prefix}.contribution_receipt_id: required for terminal return status"
                )
            else:
                receipt = registry["field-contribution-receipt"].get(
                    receipt_id
                )
                if receipt is None:
                    errors.append(
                        f"{prefix}.contribution_receipt_id: unknown contribution receipt"
                    )
                else:
                    if receipt["request_id"] != returned[
                        "contribution_request_id"
                    ]:
                        errors.append(
                            f"{prefix}.contribution_receipt_id: receipt belongs to another request"
                        )
                    if receipt["outcome"] != return_status:
                        errors.append(
                            f"{prefix}.return_status: does not match contribution receipt"
                        )

    if conditions["royalty_settlement_required"] and derivative_use:
        if obligations["royalty_status"] == "not-required":
            errors.append(
                "obligations.royalty_status: royalty remains required"
            )
    elif obligations["royalty_status"] != "not-required":
        errors.append(
            "obligations.royalty_status: must be not-required when no "
            "royalty obligation exists"
        )

    if obligations["royalty_status"] == "settled" and not obligations.get(
        "royalty_settlement_ref"
    ):
        errors.append(
            "obligations.royalty_settlement_ref: required when settled"
        )

    if (
        conditions["revocation_propagation_required"]
        and not obligations["revocation_acknowledged"]
    ):
        errors.append(
            "obligations.revocation_acknowledged: must be true"
        )

    if usage["status"] in {"completed", "failed", "cancelled", "expired"}:
        if not obligations["lease_closed"]:
            errors.append(
                "obligations.lease_closed: terminal use must close the lease"
            )

    return errors


def resolve_immune_subject(
    registry: Registry,
    field_id: str,
    subject_type: str,
    subject_id: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    record: dict[str, Any] | None = None

    if subject_type == "field-resource":
        record = find_field_resource_receipt(registry, subject_id)
    elif subject_type == "shared-resource-envelope":
        record = registry["shared-resource-envelope"].get(subject_id)
    elif subject_type == "lease":
        record = registry["field-resource-lease"].get(subject_id)
    elif subject_type == "circulation-receipt":
        record = registry["field-circulation-receipt"].get(subject_id)

    if record is None:
        errors.append(
            f"subject.subject_id: unknown {subject_type} {subject_id!r}"
        )
    elif record.get("field_id") != field_id:
        errors.append(
            "subject.subject_id: subject belongs to a different field"
        )

    return record, errors


def validate_field_anomaly_evidence(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, lookup_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    errors.extend(lookup_errors)
    if field is None:
        return errors

    _, subject_errors = resolve_immune_subject(
        registry,
        document["field_id"],
        document["subject"]["subject_type"],
        document["subject"]["subject_id"],
    )
    errors.extend(subject_errors)

    observed_at = parse_datetime(document["observed_at"])
    recorded_at = parse_datetime(document["recorded_at"])
    if recorded_at < observed_at:
        errors.append("recorded_at: must not be earlier than observed_at")

    if (
        document["status"] == "confirmed"
        and document["severity"] in {"high", "critical"}
        and document["confidence"] < 0.7
    ):
        errors.append(
            "confidence: confirmed high or critical evidence requires "
            "confidence >= 0.7"
        )

    return errors


def validate_field_residual_assessment(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, lookup_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    errors.extend(lookup_errors)
    if field is None:
        return errors

    subject = document["subject"]
    receipt = find_field_resource_receipt(
        registry,
        subject["field_resource_id"],
    )
    if receipt is None:
        errors.append(
            "subject.field_resource_id: unknown admitted field resource"
        )
    elif receipt["field_id"] != document["field_id"]:
        errors.append(
            "subject.field_resource_id: resource belongs to another field"
        )

    if subject["source_type"] == "circulation-return":
        required = (
            "circulation_receipt_id",
            "envelope_id",
            "return_role",
        )
        for key in required:
            if key not in subject:
                errors.append(
                    f"subject.{key}: required for circulation-return"
                )

        if all(key in subject for key in required):
            circulation = registry["field-circulation-receipt"].get(
                subject["circulation_receipt_id"]
            )
            if circulation is None:
                errors.append(
                    "subject.circulation_receipt_id: unknown circulation receipt"
                )
            else:
                if circulation["field_id"] != document["field_id"]:
                    errors.append(
                        "subject.circulation_receipt_id: receipt belongs "
                        "to another field"
                    )
                if circulation["field_resource_id"] != subject[
                    "field_resource_id"
                ]:
                    errors.append(
                        "subject.field_resource_id: does not match "
                        "circulation receipt"
                    )
                matched = any(
                    item["envelope_id"] == subject["envelope_id"]
                    and item["return_role"] == subject["return_role"]
                    for item in circulation["return_records"]
                )
                if not matched:
                    errors.append(
                        "subject.envelope_id: not found with declared "
                        "return_role in circulation receipt"
                    )
    else:
        for key in (
            "circulation_receipt_id",
            "envelope_id",
            "return_role",
        ):
            if key in subject:
                errors.append(
                    f"subject.{key}: forbidden for field-resource source"
                )

    evidence_records: list[dict[str, Any]] = []
    assessed_at = parse_datetime(document["assessed_at"])
    for evidence_id in document["anomaly_evidence_ids"]:
        evidence = registry["field-anomaly-evidence"].get(evidence_id)
        if evidence is None:
            errors.append(
                f"anomaly_evidence_ids: unknown evidence {evidence_id!r}"
            )
            continue
        evidence_records.append(evidence)
        if parse_datetime(evidence["observed_at"]) > assessed_at:
            errors.append(
                "anomaly_evidence_ids: evidence was observed after assessment"
            )

    classification = document["classification"]
    expected_dispositions = {
        "recoverable": "re-enter-through-boundary",
        "dormant": "hold-dormant",
        "hazardous": "quarantine-and-revoke",
        "exhausted": "tombstone",
    }
    expected = expected_dispositions[classification]
    if document["disposition"] != expected:
        errors.append(
            f"disposition: must be {expected!r} for classification "
            f"{classification!r}"
        )

    checks = document["checks"]
    if classification == "recoverable":
        if (
            checks["utility"] != "pass"
            or checks["safety"] == "fail"
            or checks["integrity"] == "fail"
        ):
            errors.append(
                "checks: recoverable requires utility pass without "
                "safety or integrity failure"
            )

    if classification == "hazardous":
        if checks["safety"] != "fail" and checks["integrity"] != "fail":
            errors.append(
                "checks: hazardous requires safety or integrity failure"
            )
        if "hazardous" in field["immune_policy"][
            "anomaly_evidence_required_for"
        ]:
            confirmed = [
                item
                for item in evidence_records
                if item["status"] == "confirmed"
                and item["severity"] in {"high", "critical"}
            ]
            if not confirmed:
                errors.append(
                    "anomaly_evidence_ids: hazardous classification "
                    "requires confirmed high or critical evidence"
                )

    if classification == "dormant":
        due_raw = document.get("reassessment_due_at")
        if due_raw is None:
            errors.append(
                "reassessment_due_at: required for dormant classification"
            )
        elif parse_datetime(due_raw) <= assessed_at:
            errors.append(
                "reassessment_due_at: must be later than assessed_at"
            )
    elif "reassessment_due_at" in document:
        errors.append(
            "reassessment_due_at: allowed only for dormant classification"
        )

    if classification == "exhausted" and checks["utility"] != "fail":
        errors.append(
            "checks.utility: exhausted classification requires fail"
        )

    return errors


def validate_field_hazard_quarantine_record(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, field_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    assessment, assessment_errors = get_record(
        registry,
        "field-residual-assessment",
        document["residual_assessment_id"],
        "residual_assessment_id",
    )
    errors.extend(field_errors)
    errors.extend(assessment_errors)
    if field is None or assessment is None:
        return errors

    if assessment["field_id"] != document["field_id"]:
        errors.append(
            "residual_assessment_id: assessment belongs to another field"
        )
    if (
        assessment["classification"] != "hazardous"
        or assessment["disposition"] != "quarantine-and-revoke"
    ):
        errors.append(
            "residual_assessment_id: quarantine requires a hazardous "
            "quarantine-and-revoke assessment"
        )

    if assessment["subject"]["source_type"] == "field-resource":
        expected_type = "field-resource"
        expected_id = assessment["subject"]["field_resource_id"]
    else:
        expected_type = "shared-resource-envelope"
        expected_id = assessment["subject"].get("envelope_id")

    if (
        document["subject"]["subject_type"] != expected_type
        or document["subject"]["subject_id"] != expected_id
    ):
        errors.append("subject: does not match residual assessment subject")

    containment = document["containment"]
    if not all(
        containment[key]
        for key in (
            "access_blocked",
            "reuse_blocked",
            "propagation_blocked",
        )
    ):
        errors.append(
            "containment: quarantine must block access, reuse, and propagation"
        )

    if (
        document["subject"]["subject_type"] == "field-resource"
        and containment["active_lease_action"] == "none"
    ):
        leases = [
            lease
            for lease in registry["field-resource-lease"].values()
            if lease["field_resource_id"]
            == document["subject"]["subject_id"]
        ]
        if leases:
            errors.append(
                "containment.active_lease_action: field resource with leases "
                "cannot use none"
            )

    if document["release_policy"]["mode"] != field["immune_policy"][
        "quarantine_release_mode"
    ]:
        errors.append(
            "release_policy.mode: does not match field immune policy"
        )

    status = document["status"]
    if status == "released":
        if "released_at" not in document:
            errors.append("released_at: required when status is released")
        if (
            document["release_policy"]["review_authorization_required"]
            and not document.get("release_authorization_id")
        ):
            errors.append(
                "release_authorization_id: required for quarantine release"
            )
    elif (
        "released_at" in document
        or "release_authorization_id" in document
    ):
        errors.append(
            "release fields: allowed only when status is released"
        )

    if (
        status == "destroyed"
        and not document.get("destruction_evidence_ref")
    ):
        errors.append(
            "destruction_evidence_ref: required when status is destroyed"
        )

    if parse_datetime(document["issued_at"]) < parse_datetime(
        containment["isolated_at"]
    ):
        errors.append(
            "issued_at: must not be earlier than containment.isolated_at"
        )

    return errors


def validate_field_revocation_propagation_record(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    field, field_errors = get_record(
        registry,
        "shared-field-profile",
        document["field_id"],
        "field_id",
    )
    quarantine, quarantine_errors = get_record(
        registry,
        "field-hazard-quarantine-record",
        document["source"]["quarantine_record_id"],
        "source.quarantine_record_id",
    )
    errors.extend(field_errors)
    errors.extend(quarantine_errors)
    if field is None or quarantine is None:
        return errors

    source_id = document["source"]["field_resource_id"]
    if quarantine["field_id"] != document["field_id"]:
        errors.append(
            "source.quarantine_record_id: quarantine belongs to another field"
        )
    if (
        quarantine["subject"]["subject_type"] != "field-resource"
        or quarantine["subject"]["subject_id"] != source_id
    ):
        errors.append(
            "source.field_resource_id: does not match quarantined resource"
        )

    if document["propagation_depth"] > field["immune_policy"][
        "max_propagation_depth"
    ]:
        errors.append(
            "propagation_depth: exceeds field immune policy"
        )

    revoked_at = parse_datetime(document["source"]["revoked_at"])
    counts = {"completed": 0, "pending": 0, "failed": 0}
    target_pairs: set[tuple[str, str]] = set()

    for index, target in enumerate(document["targets"]):
        prefix = f"targets.{index}"
        pair = (target["target_type"], target["target_id"])
        if pair in target_pairs:
            errors.append(f"{prefix}: duplicate target")
        target_pairs.add(pair)

        target_type = target["target_type"]
        target_id = target["target_id"]
        record: dict[str, Any] | None = None
        if target_type == "lease":
            record = registry["field-resource-lease"].get(target_id)
        elif target_type == "shared-resource-envelope":
            record = registry["shared-resource-envelope"].get(target_id)
        elif target_type == "contribution-request":
            record = registry["field-contribution-request"].get(target_id)
        elif target_type == "field-resource":
            record = find_field_resource_receipt(registry, target_id)

        if record is None:
            errors.append(f"{prefix}.target_id: unknown target")
            continue

        relationship = target["relationship"]
        if relationship == "active-lease":
            if (
                target_type != "lease"
                or record["field_resource_id"] != source_id
            ):
                errors.append(
                    f"{prefix}: active-lease target does not lease source"
                )
        elif relationship == "derivative":
            if (
                target_type != "shared-resource-envelope"
                or source_id not in record["origin"]["derivative_of"]
            ):
                errors.append(
                    f"{prefix}: derivative target does not derive from source"
                )
        elif relationship == "pending-return":
            if target_type != "contribution-request":
                errors.append(
                    f"{prefix}: pending-return must target a contribution request"
                )
            else:
                envelope = registry["shared-resource-envelope"].get(
                    record["envelope_id"]
                )
                if (
                    envelope is None
                    or source_id not in envelope["origin"]["derivative_of"]
                ):
                    errors.append(
                        f"{prefix}: pending return is not derived from source"
                    )

        action_status = target["action_status"]
        counts[action_status] += 1
        if action_status == "completed":
            if (
                not target.get("action_receipt_ref")
                or not target.get("acted_at")
            ):
                errors.append(
                    f"{prefix}: completed action requires receipt and acted_at"
                )
            elif parse_datetime(target["acted_at"]) < revoked_at:
                errors.append(
                    f"{prefix}.acted_at: must not precede revoked_at"
                )
        elif (
            target.get("action_receipt_ref")
            or target.get("acted_at")
        ):
            errors.append(
                f"{prefix}: incomplete action must not claim completion evidence"
            )

    summary = document["summary"]
    if summary["total"] != len(document["targets"]):
        errors.append("summary.total: does not match targets")
    for key, value in counts.items():
        if summary[key] != value:
            errors.append(
                f"summary.{key}: does not match target states"
            )

    if (
        document["status"] == "completed"
        and counts["pending"] + counts["failed"] > 0
    ):
        errors.append(
            "status: completed propagation cannot contain pending or failed targets"
        )
    if document["status"] == "in-progress" and counts["pending"] == 0:
        errors.append(
            "status: in-progress propagation requires a pending target"
        )
    if document["status"] == "failed" and counts["failed"] == 0:
        errors.append(
            "status: failed propagation requires a failed target"
        )

    if field["immune_policy"]["require_known_derivative_coverage"]:
        known_derivatives = {
            envelope["envelope_id"]
            for envelope in registry["shared-resource-envelope"].values()
            if source_id in envelope["origin"]["derivative_of"]
        }
        covered_derivatives = {
            target["target_id"]
            for target in document["targets"]
            if target["target_type"] == "shared-resource-envelope"
            and target["relationship"] == "derivative"
        }
        missing = sorted(known_derivatives - covered_derivatives)
        if missing:
            errors.append(
                f"targets: missing known derivative coverage: {missing}"
            )

    if parse_datetime(document["issued_at"]) < revoked_at:
        errors.append(
            "issued_at: must not be earlier than source.revoked_at"
        )

    return errors


TRUST_RANK = {"low": 0, "medium": 1, "high": 2}


def validate_field_federation_profile(
    document: dict[str, Any],
    _: Registry,
) -> list[str]:
    errors: list[str] = []
    governance = document["governance"]
    stewards = governance["steward_ids"]
    if governance["quorum"] > len(stewards):
        errors.append("governance.quorum: must not exceed steward count")
    if governance["governance_mode"] == "council" and len(stewards) < 2:
        errors.append("governance.steward_ids: council requires at least two stewards")
    settlement = document["settlement_policy"]
    reserved = (
        settlement["source_field_min_share"]
        + settlement["target_field_min_share"]
        + settlement["common_pool_share"]
    )
    if reserved > 1.0 + 1e-12:
        errors.append("settlement_policy: minimum and common-pool shares exceed 1.0")
    if document["updated_at"] and parse_datetime(document["updated_at"]) < parse_datetime(document["created_at"]):
        errors.append("updated_at: must not be earlier than created_at")
    return errors


def validate_field_federation_admission_record(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    federation, e = get_record(registry, "field-federation-profile", document["federation_id"], "federation_id")
    errors.extend(e)
    field, e = get_record(registry, "shared-field-profile", document["field_id"], "field_id")
    errors.extend(e)
    if federation is None or field is None:
        return errors
    if federation["status"] != "active":
        errors.append("federation_id: federation must be active")
    if document["applicant_steward_id"] not in field["governance"]["steward_ids"]:
        errors.append("applicant_steward_id: must be a steward of the applicant field")
    policy = federation["admission_policy"]
    if policy["active_field_required"] and field["status"] != "active":
        errors.append("field_id: admission policy requires an active field")
    req_domains = set(document["requested_resource_domains"])
    req_scopes = set(document["requested_scopes"])
    domain_limits = set(federation["routing_policy"]["allowed_resource_domains"]) & set(field["resource_domains"])
    scope_limits = set(federation["routing_policy"]["allowed_scopes"]) & set(field["reuse_policy"]["allowed_reuse_scopes"])
    excess_domains = sorted(req_domains - domain_limits)
    excess_scopes = sorted(req_scopes - scope_limits)
    if excess_domains:
        errors.append(f"requested_resource_domains: exceed federation or field policy: {excess_domains}")
    if excess_scopes:
        errors.append(f"requested_scopes: exceed federation or field policy: {excess_scopes}")
    approvals = document["approvals"]
    approver_ids = [a["approver_id"] for a in approvals]
    if len(approver_ids) != len(set(approver_ids)):
        errors.append("approvals: duplicate approver_id")
    invalid_approvers = sorted(set(approver_ids) - set(federation["governance"]["steward_ids"]))
    if invalid_approvers:
        errors.append(f"approvals: approvers are not federation stewards: {invalid_approvers}")
    approve_count = sum(1 for a in approvals if a["decision"] == "approve")
    decision = document["decision"]
    checks_pass = all(v == "pass" for v in document["compatibility_checks"].values())
    if decision == "admitted":
        if not checks_pass:
            errors.append("decision: admitted requires all compatibility checks to pass")
        if approve_count < federation["governance"]["quorum"]:
            errors.append("approvals: admitted field does not satisfy federation quorum")
        if policy["approval_mode"] == "unanimous" and approve_count != len(federation["governance"]["steward_ids"]):
            errors.append("approvals: unanimous admission requires every steward")
        if TRUST_RANK[document["trust_level"]] < TRUST_RANK[policy["minimum_trust_level"]]:
            errors.append("trust_level: below federation minimum")
        if not document["granted_resource_domains"] or not document["granted_scopes"]:
            errors.append("granted_resource_domains: admitted fields require non-empty grants")
        if document["lifecycle_status"] != "active":
            errors.append("lifecycle_status: admitted fields must be active")
    else:
        if document["granted_resource_domains"] or document["granted_scopes"]:
            errors.append("granted scopes and domains must be empty unless admitted")
        if document["lifecycle_status"] == "active":
            errors.append("lifecycle_status: non-admitted fields cannot be active")
    if not set(document["granted_resource_domains"]) <= req_domains:
        errors.append("granted_resource_domains: must be a subset of requested domains")
    if not set(document["granted_scopes"]) <= req_scopes:
        errors.append("granted_scopes: must be a subset of requested scopes")
    valid_from = parse_datetime(document["valid_from"])
    if parse_datetime(document["issued_at"]) > valid_from:
        errors.append("issued_at: must not be later than valid_from")
    if document.get("valid_until") and parse_datetime(document["valid_until"]) <= valid_from:
        errors.append("valid_until: must be later than valid_from")
    return errors


def _bounded_retention(field: dict[str, Any]) -> int | None:
    retention = field["retention_policy"]
    return retention.get("max_retention_seconds") if retention["mode"] == "bounded" else None


def validate_field_policy_negotiation_record(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    federation, e = get_record(registry, "field-federation-profile", document["federation_id"], "federation_id")
    errors.extend(e)
    source_adm, e = get_record(registry, "field-federation-admission-record", document["source_admission_id"], "source_admission_id")
    errors.extend(e)
    target_adm, e = get_record(registry, "field-federation-admission-record", document["target_admission_id"], "target_admission_id")
    errors.extend(e)
    if federation is None or source_adm is None or target_adm is None:
        return errors
    if source_adm["federation_id"] != document["federation_id"] or target_adm["federation_id"] != document["federation_id"]:
        errors.append("admission ids: both admissions must belong to the federation")
    if source_adm["decision"] != "admitted" or source_adm["lifecycle_status"] != "active" or target_adm["decision"] != "admitted" or target_adm["lifecycle_status"] != "active":
        errors.append("admission ids: source and target admissions must be active and admitted")
    if document["source_field_id"] != source_adm["field_id"] or document["target_field_id"] != target_adm["field_id"]:
        errors.append("source_field_id/target_field_id: do not match admissions")
    if document["source_field_id"] == document["target_field_id"]:
        errors.append("target_field_id: cross-field negotiation requires distinct fields")
    source = registry["shared-field-profile"].get(document["source_field_id"])
    target = registry["shared-field-profile"].get(document["target_field_id"])
    if source is None or target is None:
        errors.append("field ids: source or target field is unavailable")
        return errors
    domain = document["requested_resource_domain"]
    allowed_domains = set(source_adm["granted_resource_domains"]) & set(target_adm["granted_resource_domains"]) & set(federation["routing_policy"]["allowed_resource_domains"])
    if domain not in allowed_domains:
        errors.append("requested_resource_domain: not shared by source, target, and federation grants")
    scopes = set(document["requested_scopes"])
    allowed_scopes = set(source_adm["granted_scopes"]) & set(target_adm["granted_scopes"]) & set(federation["routing_policy"]["allowed_scopes"]) & set(source["reuse_policy"]["allowed_reuse_scopes"]) & set(target["reuse_policy"]["allowed_reuse_scopes"])
    excess = sorted(scopes - allowed_scopes)
    if excess:
        errors.append(f"requested_scopes: outside policy intersection: {excess}")
    terms = document["resolved_terms"]
    if not set(terms["accepted_classifications"]) <= set(target["permeability_policy"]["inbound"]["accepted_classifications"]):
        errors.append("resolved_terms.accepted_classifications: target field does not accept every class")
    if terms["max_lease_seconds"] > min(source["reuse_policy"]["max_lease_seconds"], target["reuse_policy"]["max_lease_seconds"]):
        errors.append("resolved_terms.max_lease_seconds: exceeds source or target field limit")
    retention_limits = [x for x in (_bounded_retention(source), _bounded_retention(target)) if x is not None]
    if retention_limits and terms["retention_seconds"] > min(retention_limits):
        errors.append("resolved_terms.retention_seconds: exceeds source or target retention")
    expected = {
        "audit_required": target["permeability_policy"]["inbound"]["audit_required"],
        "derivative_trace_required": source["permeability_policy"]["outbound"]["derivative_trace_required"] or target["permeability_policy"]["outbound"]["derivative_trace_required"],
        "royalty_settlement_required": federation["settlement_policy"]["settlement_required"] or source["permeability_policy"]["outbound"]["royalty_settlement_required"] or target["permeability_policy"]["outbound"]["royalty_settlement_required"],
        "revocation_propagation_required": federation["routing_policy"]["revocation_propagation_required"] or source["permeability_policy"]["outbound"]["revocation_propagation_required"] or target["permeability_policy"]["outbound"]["revocation_propagation_required"],
        "target_reassessment_required": federation["routing_policy"]["target_reassessment_required"],
    }
    for key, value in expected.items():
        if terms[key] != value:
            errors.append(f"resolved_terms.{key}: expected {value!r} from strict policy intersection")
    if terms["royalty_settlement_required"] and not terms.get("royalty_policy_ref"):
        errors.append("resolved_terms.royalty_policy_ref: required when settlement is required")
    if document["decision"] == "agreed" and document["unresolved_conflicts"]:
        errors.append("unresolved_conflicts: agreed negotiation must have none")
    if parse_datetime(document["expires_at"]) <= parse_datetime(document["negotiated_at"]):
        errors.append("expires_at: must be later than negotiated_at")
    if document["issued_by"] not in federation["governance"]["steward_ids"]:
        errors.append("issued_by: must be a federation steward")
    return errors


def validate_cross_field_route_authorization(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    negotiation, e = get_record(registry, "field-policy-negotiation-record", document["negotiation_id"], "negotiation_id")
    errors.extend(e)
    federation, e = get_record(registry, "field-federation-profile", document["federation_id"], "federation_id")
    errors.extend(e)
    if negotiation is None or federation is None:
        return errors
    if negotiation["decision"] != "agreed":
        errors.append("negotiation_id: route requires an agreed negotiation")
    for key in ["federation_id", "source_admission_id", "target_admission_id", "source_field_id", "target_field_id"]:
        if document[key] != negotiation[key]:
            errors.append(f"{key}: does not match negotiation")
    if document["permitted_resource_domain"] != negotiation["requested_resource_domain"]:
        errors.append("permitted_resource_domain: does not match negotiation")
    if not set(document["permitted_scopes"]) <= set(negotiation["requested_scopes"]):
        errors.append("permitted_scopes: exceed negotiated scopes")
    if document["max_hops"] > federation["routing_policy"]["max_hops"]:
        errors.append("max_hops: exceeds federation routing policy")
    if document["max_lease_seconds"] > negotiation["resolved_terms"]["max_lease_seconds"]:
        errors.append("max_lease_seconds: exceeds negotiated lease")
    expected = {
        "target_reassessment_required": negotiation["resolved_terms"]["target_reassessment_required"],
        "audit_required": negotiation["resolved_terms"]["audit_required"],
        "royalty_settlement_required": negotiation["resolved_terms"]["royalty_settlement_required"],
        "revocation_propagation_required": negotiation["resolved_terms"]["revocation_propagation_required"],
    }
    for key, value in expected.items():
        if document["conditions"][key] != value:
            errors.append(f"conditions.{key}: does not match negotiated term")
    source = registry["shared-field-profile"].get(document["source_field_id"])
    target = registry["shared-field-profile"].get(document["target_field_id"])
    expected_coverage = bool(source and target and source["immune_policy"]["require_known_derivative_coverage"] and target["immune_policy"]["require_known_derivative_coverage"])
    if document["conditions"]["known_derivative_coverage_required"] != expected_coverage:
        errors.append("conditions.known_derivative_coverage_required: does not match field immune policies")
    if document["authorized_by"] not in federation["governance"]["steward_ids"]:
        errors.append("authorized_by: must be a federation steward")
    if parse_datetime(document["valid_until"]) > parse_datetime(negotiation["expires_at"]):
        errors.append("valid_until: must not exceed negotiation expiry")
    if parse_datetime(document["valid_until"]) <= parse_datetime(document["authorized_at"]):
        errors.append("valid_until: must be later than authorized_at")
    return errors


def validate_cross_field_circulation_receipt(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    route, e = get_record(registry, "cross-field-route-authorization", document["route_authorization_id"], "route_authorization_id")
    errors.extend(e)
    target_env, e = get_record(registry, "shared-resource-envelope", document["target_envelope_id"], "target_envelope_id")
    errors.extend(e)
    target_req, e = get_record(registry, "field-contribution-request", document["target_contribution_request_id"], "target_contribution_request_id")
    errors.extend(e)
    target_receipt, e = get_record(registry, "field-contribution-receipt", document["target_contribution_receipt_id"], "target_contribution_receipt_id")
    errors.extend(e)
    if route is None or target_env is None or target_req is None or target_receipt is None:
        return errors
    if route["status"] != "active":
        errors.append("route_authorization_id: route must be active")
    for key in ["federation_id", "source_field_id", "target_field_id"]:
        if document[key] != route[key]:
            errors.append(f"{key}: does not match route authorization")
    source_receipt = find_field_resource_receipt(registry, document["source_field_resource_id"])
    if source_receipt is None:
        errors.append("source_field_resource_id: unknown admitted field resource")
        return errors
    if source_receipt["field_id"] != document["source_field_id"]:
        errors.append("source_field_resource_id: resource belongs to a different source field")
    if source_receipt["envelope_id"] != document["source_envelope_id"]:
        errors.append("source_envelope_id: does not match source resource receipt")
    source_env = registry["shared-resource-envelope"].get(document["source_envelope_id"])
    if source_env is None:
        errors.append("source_envelope_id: source envelope unavailable")
        return errors
    started = parse_datetime(document["started_at"])
    for quarantine in registry["field-hazard-quarantine-record"].values():
        if (
            quarantine["subject"]["subject_type"] == "field-resource"
            and quarantine["subject"]["subject_id"]
            == document["source_field_resource_id"]
            and quarantine["status"] == "active"
            and parse_datetime(quarantine["containment"]["isolated_at"])
            <= started
        ):
            errors.append(
                "source_field_resource_id: source was quarantined before transfer"
            )
    for propagation in registry[
        "field-revocation-propagation-record"
    ].values():
        if (
            propagation["source"]["field_resource_id"]
            == document["source_field_resource_id"]
            and parse_datetime(propagation["source"]["revoked_at"])
            <= started
        ):
            errors.append(
                "source_field_resource_id: source was revoked before transfer"
            )
    if target_env["field_id"] != document["target_field_id"]:
        errors.append("target_envelope_id: envelope belongs to a different target field")
    if document["source_field_resource_id"] not in target_env["origin"]["derivative_of"] and document["source_envelope_id"] not in target_env["origin"]["derivative_of"]:
        errors.append("target_envelope_id: derivative lineage does not reference source resource")
    if target_req["envelope_id"] != document["target_envelope_id"] or target_req["field_id"] != document["target_field_id"]:
        errors.append("target_contribution_request_id: does not match target envelope and field")
    if target_receipt["request_id"] != document["target_contribution_request_id"] or target_receipt["envelope_id"] != document["target_envelope_id"]:
        errors.append("target_contribution_receipt_id: does not close target request")
    if target_receipt["outcome"] != document["outcome"]:
        errors.append("outcome: does not match target contribution receipt")
    if document["transferred_resource_domain"] != route["permitted_resource_domain"] or document["transferred_resource_domain"] != source_env["resource_domain"] or document["transferred_resource_domain"] != target_env["resource_domain"]:
        errors.append("transferred_resource_domain: source, target, and route must agree")
    if not set(document["exercised_scopes"]) <= set(route["permitted_scopes"]):
        errors.append("exercised_scopes: exceed route authorization")
    if document["hop_count"] > route["max_hops"]:
        errors.append("hop_count: exceeds route authorization")
    if document["lineage"]["origin_trace_id"] != source_env["origin"].get("origin_trace_id"):
        errors.append("lineage.origin_trace_id: does not match source envelope")
    if document["lineage"]["derivative_trace_id"] != target_env["origin"].get("origin_trace_id"):
        errors.append("lineage.derivative_trace_id: does not match target envelope")
    expectations = {
        "royalty_settlement_required": route["conditions"]["royalty_settlement_required"],
        "revocation_propagation_required": route["conditions"]["revocation_propagation_required"],
    }
    for key, expected in expectations.items():
        if document["obligations"][key] != expected:
            errors.append(f"obligations.{key}: does not match route")
    if route["conditions"]["target_reassessment_required"] and target_receipt["outcome"] == "admitted" and not document["obligations"]["target_reassessment_completed"]:
        errors.append("obligations.target_reassessment_completed: required for admitted target outcome")
    if document["status"] == "completed" and document["outcome"] != "admitted":
        errors.append("status: completed requires admitted target outcome")
    if document["status"] == "blocked" and document["outcome"] == "admitted":
        errors.append("status: blocked cannot accompany admitted target outcome")
    completed = parse_datetime(document["completed_at"])
    if started < parse_datetime(route["authorized_at"]):
        errors.append("started_at: must not precede route authorization")
    if completed < started:
        errors.append("completed_at: must not precede started_at")
    if completed > parse_datetime(route["valid_until"]):
        errors.append("completed_at: exceeds route validity")
    return errors


def _rounded_share(amount: int, share: float, mode: str) -> int:
    raw = amount * share
    if mode == "floor":
        return math.floor(raw)
    if mode == "ceiling":
        return math.ceil(raw)
    return int(math.floor(raw + 0.5))


def validate_multi_field_royalty_settlement_record(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    federation, e = get_record(registry, "field-federation-profile", document["federation_id"], "federation_id")
    errors.extend(e)
    receipt, e = get_record(registry, "cross-field-circulation-receipt", document["cross_field_receipt_id"], "cross_field_receipt_id")
    errors.extend(e)
    if federation is None or receipt is None:
        return errors
    if receipt["federation_id"] != document["federation_id"]:
        errors.append("cross_field_receipt_id: receipt belongs to another federation")
    policy = federation["settlement_policy"]
    if document["unit"] != policy["unit"]:
        errors.append("unit: does not match federation settlement policy")
    if document["total_allocated"] != sum(item["amount"] for item in document["allocations"]):
        errors.append("total_allocated: does not equal allocation sum")
    if document["total_allocated"] != document["gross_amount"]:
        errors.append("total_allocated: must equal gross_amount")
    keys = [(a["beneficiary_type"], a["beneficiary_id"]) for a in document["allocations"]]
    if len(keys) != len(set(keys)):
        errors.append("allocations: duplicate beneficiary")
    by_type: dict[str, int] = defaultdict(int)
    for item in document["allocations"]:
        by_type[item["beneficiary_type"]] += item["amount"]
        if item["beneficiary_type"] == "source-field" and item.get("field_id") != receipt["source_field_id"]:
            errors.append("allocations: source-field allocation must name receipt source field")
        if item["beneficiary_type"] == "target-field" and item.get("field_id") != receipt["target_field_id"]:
            errors.append("allocations: target-field allocation must name receipt target field")
    gross = document["gross_amount"]
    if by_type["source-field"] < _rounded_share(gross, policy["source_field_min_share"], "ceiling"):
        errors.append("allocations: source-field share is below federation minimum")
    if by_type["target-field"] < _rounded_share(gross, policy["target_field_min_share"], "ceiling"):
        errors.append("allocations: target-field share is below federation minimum")
    expected_pool = _rounded_share(gross, policy["common_pool_share"], policy["rounding_mode"])
    if by_type["federation-pool"] != expected_pool:
        errors.append("allocations: federation-pool amount does not match policy")
    if document["status"] == "completed":
        if receipt["outcome"] != "admitted" or receipt["status"] != "completed":
            errors.append("status: completed settlement requires completed admitted circulation")
        if parse_datetime(document["settled_at"]) < parse_datetime(receipt["completed_at"]):
            errors.append("settled_at: must not precede cross-field completion")
        if not document.get("ledger_ref"):
            errors.append("ledger_ref: required for completed settlement")
    return errors


def validate_federation_circulation_health_report(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    federation, e = get_record(registry, "field-federation-profile", document["federation_id"], "federation_id")
    errors.extend(e)
    if federation is None:
        return errors
    metrics = document["metrics"]
    attempts = metrics["cross_field_attempts"]
    if metrics["completed_routes"] + metrics["failed_routes"] > attempts:
        errors.append("metrics: completed_routes plus failed_routes exceeds attempts")
    if metrics["quarantined_transfers"] > attempts:
        errors.append("metrics.quarantined_transfers: exceeds attempts")
    if metrics["settled_transfers"] > metrics["royalty_required_transfers"]:
        errors.append("metrics.settled_transfers: exceeds royalty-required transfers")
    expected_rates = {
        "failed_route_rate": metrics["failed_routes"] / attempts if attempts else 0.0,
        "quarantine_rate": metrics["quarantined_transfers"] / attempts if attempts else 0.0,
        "settlement_completion_rate": metrics["settled_transfers"] / metrics["royalty_required_transfers"] if metrics["royalty_required_transfers"] else 1.0,
    }
    for key, expected in expected_rates.items():
        if abs(document["derived_rates"][key] - expected) > 1e-9:
            errors.append(f"derived_rates.{key}: expected {expected:.12g} from metrics")
    policy = federation["health_policy"]
    breaches: list[str] = []
    if expected_rates["failed_route_rate"] > policy["max_failed_route_rate"]:
        breaches.append("FAILED_ROUTE_RATE")
    if expected_rates["quarantine_rate"] > policy["max_quarantine_rate"]:
        breaches.append("QUARANTINE_RATE")
    if expected_rates["settlement_completion_rate"] < policy["min_settlement_completion_rate"]:
        breaches.append("SETTLEMENT_COMPLETION_RATE")
    if metrics["max_observed_revocation_lag_seconds"] > policy["max_revocation_lag_seconds"]:
        breaches.append("REVOCATION_LAG")
    if set(document["threshold_breaches"]) != set(breaches):
        errors.append(f"threshold_breaches: expected {sorted(breaches)}")
    expected_status = "healthy" if not breaches else ("critical" if len(breaches) >= 2 or "REVOCATION_LAG" in breaches else "degraded")
    if document["status"] != expected_status:
        errors.append(f"status: expected {expected_status!r} from threshold breaches")
    start = parse_datetime(document["window_start"])
    end = parse_datetime(document["window_end"])
    if end <= start:
        errors.append("window_end: must be later than window_start")
    if parse_datetime(document["generated_at"]) < end:
        errors.append("generated_at: must not precede window_end")
    return errors

SEMANTIC_VALIDATORS: dict[
    str,
    Callable[[dict[str, Any], Registry], list[str]],
] = {
    "shared-field-profile": validate_shared_field_profile,
    "field-participant-binding": validate_field_participant_binding,
    "shared-resource-envelope": validate_shared_resource_envelope,
    "field-contribution-request": validate_field_contribution_request,
    "field-contribution-assessment": validate_field_contribution_assessment,
    "field-contribution-receipt": validate_field_contribution_receipt,
    "field-resource-reuse-request": validate_field_resource_reuse_request,
    "field-resource-reuse-authorization": (
        validate_field_resource_reuse_authorization
    ),
    "field-resource-lease": validate_field_resource_lease,
    "field-circulation-receipt": validate_field_circulation_receipt,
    "field-anomaly-evidence": validate_field_anomaly_evidence,
    "field-residual-assessment": validate_field_residual_assessment,
    "field-hazard-quarantine-record": validate_field_hazard_quarantine_record,
    "field-revocation-propagation-record": validate_field_revocation_propagation_record,
    "field-federation-profile": validate_field_federation_profile,
    "field-federation-admission-record": validate_field_federation_admission_record,
    "field-policy-negotiation-record": validate_field_policy_negotiation_record,
    "cross-field-route-authorization": validate_cross_field_route_authorization,
    "cross-field-circulation-receipt": validate_cross_field_circulation_receipt,
    "multi-field-royalty-settlement-record": validate_multi_field_royalty_settlement_record,
    "federation-circulation-health-report": validate_federation_circulation_health_report,
}


def semantic_errors(
    document: dict[str, Any],
    registry: Registry,
) -> list[str]:
    record_type = document["record_type"]
    validator = SEMANTIC_VALIDATORS.get(record_type)

    if validator is None:
        return [f"<root>: unsupported record_type {record_type!r}"]

    return validator(document, registry)


def build_pass_registry(
    validators: dict[str, Draft202012Validator],
) -> Registry:
    registry: Registry = defaultdict(dict)
    documents_by_type: dict[str, list[tuple[Path, dict[str, Any]]]] = (
        defaultdict(list)
    )

    for path in sorted(PASS_DIR.glob("*.yaml")):
        document = load_yaml(path)
        errors = schema_errors(document, validators)
        if errors:
            raise RuntimeError(
                f"pass example has schema errors: {path}: "
                + "; ".join(errors)
            )
        documents_by_type[document["record_type"]].append(
            (path, document)
        )

    for record_type in TYPE_ORDER:
        for path, document in documents_by_type.get(record_type, []):
            errors = semantic_errors(document, registry)
            if errors:
                raise RuntimeError(
                    f"pass example has semantic errors: {path}: "
                    + "; ".join(errors)
                )

            id_field = ID_FIELDS[record_type]
            record_id = document[id_field]
            if record_id in registry[record_type]:
                raise RuntimeError(
                    f"duplicate {id_field} in pass examples: {record_id}"
                )
            registry[record_type][record_id] = document

    for record_type in TYPE_ORDER:
        if not registry[record_type]:
            raise RuntimeError(
                f"at least one pass example is required for {record_type}"
            )

    return registry


def validate_expected_pass(
    path: Path,
    validators: dict[str, Draft202012Validator],
    registry: Registry,
) -> bool:
    print(f"[validate-pass] {path.relative_to(ROOT)}")

    try:
        document = load_yaml(path)
    except Exception as exc:
        print(f"[load-error] {exc}")
        print()
        return False

    errors = schema_errors(document, validators)
    if errors:
        print("[schema-error]")
        for error in errors:
            print(f"  - {error}")
        print()
        return False

    print("[schema-ok]")
    errors = semantic_errors(document, registry)
    if errors:
        print("[semantic-error]")
        for error in errors:
            print(f"  - {error}")
        print()
        return False

    print("[semantic-ok]")
    print()
    return True


def validate_expected_fail(
    path: Path,
    validators: dict[str, Draft202012Validator],
    registry: Registry,
) -> bool:
    print(f"[validate-fail] {path.relative_to(ROOT)}")

    try:
        document = load_yaml(path)
    except Exception as exc:
        print(f"[expected-load-error] {exc}")
        print()
        return True

    errors = schema_errors(document, validators)
    if errors:
        print("[expected-schema-error]")
        for error in errors:
            print(f"  - {error}")
        print()
        return True

    print("[schema-ok]")
    errors = semantic_errors(document, registry)
    if errors:
        print("[expected-semantic-error]")
        for error in errors:
            print(f"  - {error}")
        print()
        return True

    print("[unexpected-pass]")
    print()
    return False


def main() -> int:
    print("=== Agentic Shared Field Protocol v0.5 Validation ===")

    schemas = {
        record_type: load_json(path)
        for record_type, path in SCHEMA_FILES.items()
    }
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    print("[schema-meta-ok]")

    for example_path in sorted(PASS_DIR.glob("*.yaml")) + sorted(
        FAIL_DIR.glob("*.yaml")
    ):
        load_yaml(example_path)
    print("[yaml-load-ok]")
    print()

    validators = {
        record_type: Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )
        for record_type, schema in schemas.items()
    }

    for record_type, path in SCHEMA_FILES.items():
        print(
            f"schema [{record_type}]: {path.relative_to(ROOT)}"
        )
    print()

    try:
        registry = build_pass_registry(validators)
    except Exception as exc:
        print(f"[fatal] {exc}")
        return 1

    pass_files = sorted(PASS_DIR.glob("*.yaml"))
    fail_files = sorted(FAIL_DIR.glob("*.yaml"))

    if not pass_files:
        print("[fatal] no pass examples found")
        return 1
    if not fail_files:
        print("[fatal] no fail examples found")
        return 1

    success = True
    for path in pass_files:
        success = validate_expected_pass(
            path,
            validators,
            registry,
        ) and success

    for path in fail_files:
        success = validate_expected_fail(
            path,
            validators,
            registry,
        ) and success

    if success:
        print("Validation passed.")
        return 0

    print("Validation failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
