#!/usr/bin/env python3
"""Validate Agentic Shared Field Protocol v0.2 examples."""

from __future__ import annotations

import json
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
}

TYPE_ORDER = [
    "shared-field-profile",
    "field-participant-binding",
    "shared-resource-envelope",
    "field-contribution-request",
    "field-contribution-assessment",
    "field-contribution-receipt",
]

ID_FIELDS = {
    "shared-field-profile": "field_id",
    "field-participant-binding": "binding_id",
    "shared-resource-envelope": "envelope_id",
    "field-contribution-request": "request_id",
    "field-contribution-assessment": "assessment_id",
    "field-contribution-receipt": "receipt_id",
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
    print("=== Agentic Shared Field Protocol v0.2 Validation ===")

    schemas = {
        record_type: load_json(path)
        for record_type, path in SCHEMA_FILES.items()
    }
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

