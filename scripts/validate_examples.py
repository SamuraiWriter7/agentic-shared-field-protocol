#!/usr/bin/env python3
"""Validate Agentic Shared Field Protocol v0.1 examples."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

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
}

PARTICIPANT_PREFIXES = {
    "human": "human:",
    "agent": "agent:",
    "organization": "org:",
    "service": "service:",
}


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
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


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


def validate_shared_field_profile(
    document: dict[str, Any],
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

    if field_kind != "composite":
        if domains != {field_kind}:
            errors.append(
                "resource_domains: a non-composite field must contain "
                "exactly its declared field_kind "
                f"{field_kind!r}"
            )
    elif len(domains) < 2:
        errors.append(
            "resource_domains: "
            "a composite field requires at least two domains"
        )

    access = document["access_policy"]
    allowed_scopes = set(access["allowed_access_scopes"])
    default_scopes = set(access["default_access_scopes"])

    excess_defaults = sorted(default_scopes - allowed_scopes)

    if excess_defaults:
        errors.append(
            "access_policy.default_access_scopes: "
            "scopes not present in allowed_access_scopes: "
            f"{excess_defaults}"
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
            "permeability_policy.inbound: "
            "accepted_classifications and rejected_classifications "
            f"overlap: {overlap}"
        )

    retention = document["retention_policy"]
    has_maximum = "max_retention_seconds" in retention

    if retention["mode"] == "bounded" and not has_maximum:
        errors.append(
            "retention_policy.max_retention_seconds: "
            "required when mode is bounded"
        )

    if retention["mode"] != "bounded" and has_maximum:
        errors.append(
            "retention_policy.max_retention_seconds: "
            "allowed only when mode is bounded"
        )

    created_at = parse_datetime(document["created_at"])
    updated_at = parse_datetime(document["updated_at"])

    if updated_at < created_at:
        errors.append(
            "updated_at: must not be earlier than created_at"
        )

    origin_created_at = parse_datetime(
        document["origin"]["created_at"]
    )

    if origin_created_at > created_at:
        errors.append(
            "origin.created_at: "
            "must not be later than field created_at"
        )

    return errors


def validate_field_participant_binding(
    document: dict[str, Any],
    field_registry: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []

    field_id = document["field_id"]
    field = field_registry.get(field_id)

    if field is None:
        return [
            f"field_id: unknown shared field {field_id!r}"
        ]

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
            "participant.participant_type: "
            "type is not admitted by the field"
        )

    decision = document["decision"]
    scopes = set(document["granted_access_scopes"])
    domains = set(document["allowed_resource_domains"])
    lifecycle = document["lifecycle_status"]

    if decision == "admitted":
        if not scopes:
            errors.append(
                "granted_access_scopes: "
                "admitted participants need at least one scope"
            )

        if not domains:
            errors.append(
                "allowed_resource_domains: "
                "admitted participants need at least one domain"
            )
    else:
        if scopes:
            errors.append(
                "granted_access_scopes: "
                "denied or suspended participants "
                "must have no scopes"
            )

        if domains:
            errors.append(
                "allowed_resource_domains: "
                "denied or suspended participants "
                "must have no domains"
            )

    if decision == "denied" and lifecycle != "inactive":
        errors.append(
            "lifecycle_status: denied bindings must be inactive"
        )

    if decision == "suspended" and lifecycle != "inactive":
        errors.append(
            "lifecycle_status: suspended bindings must be inactive"
        )

    allowed_scopes = set(access["allowed_access_scopes"])
    excess_scopes = sorted(scopes - allowed_scopes)

    if excess_scopes:
        errors.append(
            "granted_access_scopes: scopes exceed field policy: "
            f"{excess_scopes}"
        )

    field_domains = set(field["resource_domains"])
    excess_domains = sorted(domains - field_domains)

    if excess_domains:
        errors.append(
            "allowed_resource_domains: "
            "domains exceed field profile: "
            f"{excess_domains}"
        )

    if (
        "administer" in scopes
        and participant_id
        not in field["governance"]["steward_ids"]
    ):
        errors.append(
            "granted_access_scopes: administer may be granted "
            "only to a field steward"
        )

    if (
        decision == "admitted"
        and access["authorization_required"]
        and not document.get("authorization_receipt_id")
    ):
        errors.append(
            "authorization_receipt_id: "
            "required for admission to this field"
        )

    if (
        decision == "admitted"
        and lifecycle == "active"
        and field["status"] != "active"
    ):
        errors.append(
            "lifecycle_status: "
            "an active binding cannot target a non-active field"
        )

    valid_from = parse_datetime(document["valid_from"])
    valid_until_raw = document.get("valid_until")

    if valid_until_raw is not None:
        valid_until = parse_datetime(valid_until_raw)

        if valid_until <= valid_from:
            errors.append(
                "valid_until: must be later than valid_from"
            )

    issued_at = parse_datetime(document["issued_at"])

    if issued_at > valid_from:
        errors.append(
            "issued_at: must not be later than valid_from"
        )

    conditions = document["conditions"]
    outbound = field["permeability_policy"]["outbound"]
    inbound = field["permeability_policy"]["inbound"]

    derivative_scopes = {
        "derive",
        "redistribute",
        "commercialize",
    }

    if scopes & derivative_scopes:
        if (
            outbound["derivative_trace_required"]
            and not conditions["derivative_trace_required"]
        ):
            errors.append(
                "conditions.derivative_trace_required: "
                "must be true for derivative scopes"
            )

        if (
            outbound["royalty_settlement_required"]
            and not conditions.get("royalty_policy_ref")
        ):
            errors.append(
                "conditions.royalty_policy_ref: "
                "required for derivative scopes"
            )

    if (
        "contribute" in scopes
        and inbound["audit_required"]
        and not conditions["contribution_audit_required"]
    ):
        errors.append(
            "conditions.contribution_audit_required: "
            "must be true for contributors"
        )

    return errors


def semantic_errors(
    document: dict[str, Any],
    field_registry: dict[str, dict[str, Any]],
) -> list[str]:
    record_type = document["record_type"]

    if record_type == "shared-field-profile":
        return validate_shared_field_profile(document)

    if record_type == "field-participant-binding":
        return validate_field_participant_binding(
            document,
            field_registry,
        )

    return [
        f"<root>: unsupported record_type {record_type!r}"
    ]


def build_field_registry(
    validators: dict[str, Draft202012Validator],
) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}

    for path in sorted(PASS_DIR.glob("*.yaml")):
        document = load_yaml(path)

        if (
            document.get("record_type")
            != "shared-field-profile"
        ):
            continue

        errors = schema_errors(document, validators)
        errors.extend(
            validate_shared_field_profile(document)
        )

        if errors:
            joined = "; ".join(errors)

            raise RuntimeError(
                "cannot register invalid shared field profile "
                f"{path}: {joined}"
            )

        field_id = document["field_id"]

        if field_id in registry:
            raise RuntimeError(
                "duplicate field_id in pass examples: "
                f"{field_id}"
            )

        registry[field_id] = document

    if not registry:
        raise RuntimeError(
            "at least one valid shared-field-profile "
            "pass example is required"
        )

    return registry


def validate_expected_pass(
    path: Path,
    validators: dict[str, Draft202012Validator],
    field_registry: dict[str, dict[str, Any]],
) -> bool:
    print(f"[validate-pass] {path.relative_to(ROOT)}")

    try:
        document = load_yaml(path)
    except Exception as exc:
        print(f"[load-error] {exc}")
        return False

    errors = schema_errors(document, validators)

    if errors:
        print("[schema-error]")

        for error in errors:
            print(f"  - {error}")

        return False

    print("[schema-ok]")

    errors = semantic_errors(document, field_registry)

    if errors:
        print("[semantic-error]")

        for error in errors:
            print(f"  - {error}")

        return False

    print("[semantic-ok]")
    print()

    return True


def validate_expected_fail(
    path: Path,
    validators: dict[str, Draft202012Validator],
    field_registry: dict[str, dict[str, Any]],
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

    errors = semantic_errors(document, field_registry)

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
    print(
        "=== Agentic Shared Field Protocol "
        "v0.1 Validation ==="
    )

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
            f"schema [{record_type}]: "
            f"{path.relative_to(ROOT)}"
        )

    print()

    try:
        field_registry = build_field_registry(validators)
    except Exception as exc:
        print(f"[fatal] {exc}")
        return 1

    success = True

    pass_files = sorted(PASS_DIR.glob("*.yaml"))
    fail_files = sorted(FAIL_DIR.glob("*.yaml"))

    if not pass_files:
        print("[fatal] no pass examples found")
        return 1

    if not fail_files:
        print("[fatal] no fail examples found")
        return 1

    for path in pass_files:
        success = (
            validate_expected_pass(
                path,
                validators,
                field_registry,
            )
            and success
        )

    for path in fail_files:
        success = (
            validate_expected_fail(
                path,
                validators,
                field_registry,
            )
            and success
        )

    if success:
        print("Validation passed.")
        return 0

    print("Validation failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
