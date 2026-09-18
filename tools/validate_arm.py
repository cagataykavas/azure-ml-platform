"""Fail-closed policy checks for the compiled Azure ARM template."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Violation:
    rule: str
    resource: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "resource": self.resource, "message": self.message}


def _resources(template: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in template.get("resources", [])
        if resource.get("type", "").casefold() == resource_type.casefold()
    ]


def _one(template: dict[str, Any], resource_type: str, violations: list[Violation]) -> dict[str, Any]:
    matches = _resources(template, resource_type)
    if len(matches) != 1:
        violations.append(
            Violation(
                "resource.cardinality",
                resource_type,
                f"expected exactly one resource, found {len(matches)}",
            )
        )
        return {}
    return matches[0]


def evaluate_template(template: dict[str, Any]) -> list[Violation]:
    """Return every production-policy violation in a compiled ARM template."""
    violations: list[Violation] = []
    if template.get("$schema") is None or not isinstance(template.get("resources"), list):
        return [Violation("template.shape", "template", "not a compiled ARM deployment template")]

    storage = _one(template, "Microsoft.Storage/storageAccounts", violations)
    storage_props = storage.get("properties", {})
    required_storage = {
        "allowBlobPublicAccess": False,
        "allowSharedKeyAccess": False,
        "defaultToOAuthAuthentication": True,
        "minimumTlsVersion": "TLS1_2",
        "supportsHttpsTrafficOnly": True,
    }
    for key, expected in required_storage.items():
        if storage_props.get(key) != expected:
            violations.append(
                Violation(
                    f"storage.{key}",
                    str(storage.get("name", "storage")),
                    f"expected {key}={expected!r}",
                )
            )

    containers = _resources(template, "Microsoft.Storage/storageAccounts/blobServices/containers")
    if not containers:
        violations.append(
            Violation("storage.private_container", "models", "no blob container was compiled")
        )
    for container in containers:
        if container.get("properties", {}).get("publicAccess") != "None":
            violations.append(
                Violation(
                    "storage.private_container",
                    str(container.get("name", "container")),
                    "blob containers must explicitly disable public access",
                )
            )

    app = _one(template, "Microsoft.App/containerApps", violations)
    if app.get("identity", {}).get("type") != "SystemAssigned":
        violations.append(
            Violation(
                "app.managed_identity",
                str(app.get("name", "container-app")),
                "system-assigned managed identity is required",
            )
        )

    scale = app.get("properties", {}).get("template", {}).get("scale", {})
    min_replicas = scale.get("minReplicas")
    max_replicas = scale.get("maxReplicas")
    if not isinstance(min_replicas, int) or min_replicas < 0:
        violations.append(
            Violation("app.scale_min", str(app.get("name", "container-app")), "invalid minReplicas")
        )
    if not isinstance(max_replicas, int) or max_replicas < 1 or max_replicas > 50:
        violations.append(
            Violation(
                "app.scale_max",
                str(app.get("name", "container-app")),
                "maxReplicas must be between 1 and 50",
            )
        )
    if isinstance(min_replicas, int) and isinstance(max_replicas, int):
        if min_replicas > max_replicas:
            violations.append(
                Violation(
                    "app.scale_order",
                    str(app.get("name", "container-app")),
                    "minReplicas cannot exceed maxReplicas",
                )
            )

    role_assignments = _resources(template, "Microsoft.Authorization/roleAssignments")
    if not role_assignments:
        violations.append(
            Violation(
                "iam.runtime_role",
                "roleAssignments",
                "runtime managed identity has no compiled role assignment",
            )
        )
    else:
        for assignment in role_assignments:
            if assignment.get("properties", {}).get("principalType") != "ServicePrincipal":
                violations.append(
                    Violation(
                        "iam.principal_type",
                        str(assignment.get("name", "role-assignment")),
                        "role assignment principalType must be ServicePrincipal",
                    )
                )

    diagnostics = _resources(template, "Microsoft.Insights/diagnosticSettings")
    if len(diagnostics) != 1:
        violations.append(
            Violation(
                "observability.diagnostics",
                "diagnosticSettings",
                f"expected one diagnostic setting, found {len(diagnostics)}",
            )
        )
    else:
        properties = diagnostics[0].get("properties", {})
        enabled = {
            item.get("category")
            for item in properties.get("logs", [])
            if item.get("enabled") is True
        }
        required = {"ContainerAppConsoleLogs", "ContainerAppSystemLogs"}
        missing = sorted(required - enabled)
        if missing or not properties.get("workspaceId"):
            violations.append(
                Violation(
                    "observability.diagnostics",
                    str(diagnostics[0].get("name", "diagnostics")),
                    f"missing workspace or log categories: {missing}",
                )
            )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    try:
        template = json.loads(args.template.read_text(encoding="utf-8"))
        violations = evaluate_template(template)
    except (OSError, json.JSONDecodeError) as exc:
        violations = [Violation("template.read", str(args.template), str(exc))]

    payload = {
        "passed": not violations,
        "violation_count": len(violations),
        "violations": [item.to_dict() for item in violations],
    }
    if args.as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("ARM policy gate: PASS" if not violations else "ARM policy gate: FAIL")
        for item in violations:
            print(f"- [{item.rule}] {item.resource}: {item.message}")
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
