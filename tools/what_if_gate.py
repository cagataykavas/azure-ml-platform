"""Fail-closed policy gate for Azure Resource Manager What-If JSON."""

from __future__ import annotations

import argparse
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from numbers import Real
from pathlib import Path
from typing import Any


class WhatIfAuditError(ValueError):
    """Malformed or incomplete What-If evidence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class WhatIfPolicy:
    max_changed_resources: int = 20
    max_modified_resources: int = 10
    max_property_deletions: int = 0
    ignored_delete_path_prefixes: tuple[str, ...] = ()
    block_capacity_decrease: bool = True
    block_retention_decrease: bool = True


@dataclass(frozen=True)
class Violation:
    rule_id: str
    resource_id: str
    path: str | None
    message: str


@dataclass(frozen=True)
class WhatIfReport:
    accepted: bool
    resource_changes: int
    created_resources: int
    modified_resources: int
    deleted_resources: int
    ignored_resources: int
    property_deletions: tuple[str, ...]
    violations: tuple[Violation, ...]

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["property_deletions"] = list(self.property_deletions)
        payload["violations"] = list(payload["violations"])
        return payload


_RESOURCE_CHANGE_TYPES = {
    "Create",
    "Delete",
    "Ignore",
    "NoChange",
    "NoEffect",
    "Modify",
    "Deploy",
}
_PROPERTY_CHANGE_TYPES = {"Create", "Delete", "Modify", "Array", "NoEffect"}
_CAPACITY_PATHS = (
    "properties.template.scale.minreplicas",
    "properties.template.scale.maxreplicas",
)


def audit_what_if(
    document: Mapping[str, Any],
    *,
    policy: WhatIfPolicy | None = None,
) -> WhatIfReport:
    active_policy = policy or WhatIfPolicy()
    _validate_policy(active_policy)
    if not isinstance(document, Mapping):
        raise WhatIfAuditError("INVALID_DOCUMENT", "What-If document must be an object")
    if document.get("status") != "Succeeded":
        raise WhatIfAuditError("WHAT_IF_NOT_SUCCEEDED", "What-If status must be Succeeded")
    if document.get("error") not in (None, {}):
        raise WhatIfAuditError("WHAT_IF_ERROR", "What-If result contains an error")

    properties = document.get("properties")
    if not isinstance(properties, Mapping):
        raise WhatIfAuditError("INVALID_PROPERTIES", "What-If properties must be an object")
    changes = properties.get("changes")
    if not isinstance(changes, list):
        raise WhatIfAuditError("INVALID_CHANGES", "properties.changes must be an array")
    diagnostics = properties.get("diagnostics", [])
    potential_changes = properties.get("potentialChanges", [])
    if not isinstance(diagnostics, list) or not isinstance(potential_changes, list):
        raise WhatIfAuditError(
            "INVALID_PROPERTIES", "diagnostics and potentialChanges must be arrays"
        )

    violations: list[Violation] = []
    if diagnostics:
        violations.append(
            Violation(
                "WHAT_IF_DIAGNOSTICS_PRESENT",
                "<deployment>",
                None,
                "What-If returned diagnostics requiring review",
            )
        )
    if potential_changes:
        violations.append(
            Violation(
                "POTENTIAL_CHANGES_PRESENT",
                "<deployment>",
                None,
                "What-If returned unresolved potential changes",
            )
        )

    seen_resources: set[str] = set()
    counts = {kind: 0 for kind in _RESOURCE_CHANGE_TYPES}
    property_deletions: list[str] = []
    changed_resources = 0

    for index, change in enumerate(changes):
        resource_id, change_type = _validate_resource_change(change, index)
        if resource_id in seen_resources:
            raise WhatIfAuditError("DUPLICATE_RESOURCE_ID", f"duplicate resourceId: {resource_id}")
        seen_resources.add(resource_id)
        counts[change_type] += 1
        if change_type in {"Create", "Delete", "Modify", "Deploy"}:
            changed_resources += 1

        if change_type == "Delete":
            violations.append(
                Violation(
                    "RESOURCE_DELETE",
                    resource_id,
                    None,
                    "deployment would delete a resource",
                )
            )
        elif change_type == "Ignore":
            violations.append(
                Violation(
                    "INCOMPLETE_CHANGE_ANALYSIS",
                    resource_id,
                    None,
                    "resource was ignored by What-If",
                )
            )
        elif change_type == "Deploy":
            violations.append(
                Violation(
                    "RESOURCE_ID_ONLY_RESULT",
                    resource_id,
                    None,
                    "resource lacks FullResourcePayloads change evidence",
                )
            )
        elif change_type == "Modify":
            delta = change.get("delta")
            if not isinstance(delta, list) or not delta:
                violations.append(
                    Violation(
                        "MISSING_MODIFY_DELTA",
                        resource_id,
                        None,
                        "modified resource has no property delta",
                    )
                )
                continue
            for property_change in _flatten_property_changes(delta, resource_id):
                _inspect_property_change(
                    property_change,
                    resource_id,
                    active_policy,
                    property_deletions,
                    violations,
                )

    if changed_resources > active_policy.max_changed_resources:
        violations.append(
            Violation(
                "CHANGE_BLAST_RADIUS_EXCEEDED",
                "<deployment>",
                None,
                f"{changed_resources} changed resources exceed policy maximum",
            )
        )
    if counts["Modify"] > active_policy.max_modified_resources:
        violations.append(
            Violation(
                "MODIFY_BUDGET_EXCEEDED",
                "<deployment>",
                None,
                f"{counts['Modify']} modified resources exceed policy maximum",
            )
        )
    if len(property_deletions) > active_policy.max_property_deletions:
        violations.append(
            Violation(
                "PROPERTY_DELETE_BUDGET_EXCEEDED",
                "<deployment>",
                None,
                f"{len(property_deletions)} property deletions exceed policy maximum",
            )
        )

    ordered_violations = tuple(
        sorted(
            violations,
            key=lambda item: (item.rule_id, item.resource_id, item.path or ""),
        )
    )
    return WhatIfReport(
        accepted=not ordered_violations,
        resource_changes=len(changes),
        created_resources=counts["Create"],
        modified_resources=counts["Modify"],
        deleted_resources=counts["Delete"],
        ignored_resources=counts["Ignore"],
        property_deletions=tuple(sorted(property_deletions)),
        violations=ordered_violations,
    )


def _validate_policy(policy: WhatIfPolicy) -> None:
    for field in (
        "max_changed_resources",
        "max_modified_resources",
        "max_property_deletions",
    ):
        value = getattr(policy, field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise WhatIfAuditError("INVALID_POLICY", f"{field} must be a non-negative integer")
    if not all(
        isinstance(prefix, str) and prefix.strip() for prefix in policy.ignored_delete_path_prefixes
    ):
        raise WhatIfAuditError(
            "INVALID_POLICY", "ignored delete prefixes must be non-empty strings"
        )
    if not isinstance(policy.block_capacity_decrease, bool) or not isinstance(
        policy.block_retention_decrease, bool
    ):
        raise WhatIfAuditError("INVALID_POLICY", "policy switches must be boolean")


def _validate_resource_change(change: Any, index: int) -> tuple[str, str]:
    if not isinstance(change, Mapping):
        raise WhatIfAuditError("INVALID_RESOURCE_CHANGE", f"change {index} must be an object")
    resource_id = change.get("resourceId")
    change_type = change.get("changeType")
    if not isinstance(resource_id, str) or not resource_id.startswith("/"):
        raise WhatIfAuditError("INVALID_RESOURCE_ID", f"change {index} has an invalid resourceId")
    if change_type not in _RESOURCE_CHANGE_TYPES:
        raise WhatIfAuditError("INVALID_CHANGE_TYPE", f"change {index} has an unknown changeType")
    return resource_id, change_type


def _flatten_property_changes(
    changes: Sequence[Any], resource_id: str
) -> tuple[Mapping[str, Any], ...]:
    flattened: list[Mapping[str, Any]] = []
    for item in changes:
        if not isinstance(item, Mapping):
            raise WhatIfAuditError(
                "INVALID_PROPERTY_CHANGE",
                f"property delta for {resource_id} must contain objects",
            )
        change_type = item.get("propertyChangeType")
        path = item.get("path")
        if change_type not in _PROPERTY_CHANGE_TYPES:
            raise WhatIfAuditError(
                "INVALID_PROPERTY_CHANGE_TYPE",
                f"property delta for {resource_id} has an unknown type",
            )
        if not isinstance(path, str) or not path.strip():
            raise WhatIfAuditError(
                "INVALID_PROPERTY_PATH",
                f"property delta for {resource_id} has an invalid path",
            )
        flattened.append(item)
        children = item.get("children", [])
        if children is None:
            children = []
        if not isinstance(children, list):
            raise WhatIfAuditError(
                "INVALID_PROPERTY_CHILDREN",
                f"property delta for {resource_id} has invalid children",
            )
        flattened.extend(_flatten_property_changes(children, resource_id))
    return tuple(flattened)


def _inspect_property_change(
    change: Mapping[str, Any],
    resource_id: str,
    policy: WhatIfPolicy,
    property_deletions: list[str],
    violations: list[Violation],
) -> None:
    path = str(change["path"])
    normalized_path = path.lower()
    change_type = change["propertyChangeType"]
    if change_type == "Delete" and not any(
        normalized_path.startswith(prefix.lower()) for prefix in policy.ignored_delete_path_prefixes
    ):
        property_deletions.append(f"{resource_id}::{path}")

    if (
        policy.block_capacity_decrease
        and normalized_path.endswith(_CAPACITY_PATHS)
        and _numeric_decrease(change, resource_id, path)
    ):
        violations.append(
            Violation(
                "SCALE_CAPACITY_DECREASE",
                resource_id,
                path,
                "deployment would reduce configured replica capacity",
            )
        )
    if (
        policy.block_retention_decrease
        and normalized_path.endswith("retentionpolicy.days")
        and _numeric_decrease(change, resource_id, path)
    ):
        violations.append(
            Violation(
                "RETENTION_DECREASE",
                resource_id,
                path,
                "deployment would reduce configured retention",
            )
        )


def _numeric_decrease(change: Mapping[str, Any], resource_id: str, path: str) -> bool:
    before = change.get("before")
    after = change.get("after")
    for value in (before, after):
        if (
            not isinstance(value, Real)
            or isinstance(value, bool)
            or not math.isfinite(float(value))
        ):
            raise WhatIfAuditError(
                "INVALID_NUMERIC_DELTA",
                f"{resource_id} property {path} requires finite numeric values",
            )
    return float(after) < float(before)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Azure Resource Manager What-If JSON")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-changed-resources", type=int, default=20)
    parser.add_argument("--max-modified-resources", type=int, default=10)
    parser.add_argument("--max-property-deletions", type=int, default=0)
    parser.add_argument("--ignore-delete-prefix", action="append", default=[])
    args = parser.parse_args(argv)

    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
        report = audit_what_if(
            document,
            policy=WhatIfPolicy(
                max_changed_resources=args.max_changed_resources,
                max_modified_resources=args.max_modified_resources,
                max_property_deletions=args.max_property_deletions,
                ignored_delete_path_prefixes=tuple(args.ignore_delete_prefix),
            ),
        )
    except (OSError, json.JSONDecodeError, WhatIfAuditError) as exc:
        code = exc.code if isinstance(exc, WhatIfAuditError) else "INVALID_INPUT"
        payload = {"accepted": False, "error": {"code": code, "message": str(exc)}}
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 3

    rendered = json.dumps(report.as_dict(), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
