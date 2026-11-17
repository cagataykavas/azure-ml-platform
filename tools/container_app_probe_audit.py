from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "azure-container-app-probes/v1"
MAX_TEMPLATE_BYTES = 4 * 1024 * 1024
PROBE_POLICY = {
    "Startup": {
        "path": "/startup",
        "initialDelaySeconds": 1,
        "periodSeconds": 10,
        "timeoutSeconds": 3,
        "failureThreshold": 10,
        "successThreshold": 1,
    },
    "Liveness": {
        "path": "/live",
        "initialDelaySeconds": 10,
        "periodSeconds": 10,
        "timeoutSeconds": 3,
        "failureThreshold": 3,
        "successThreshold": 1,
    },
    "Readiness": {
        "path": "/ready",
        "initialDelaySeconds": 1,
        "periodSeconds": 5,
        "timeoutSeconds": 2,
        "failureThreshold": 3,
        "successThreshold": 1,
    },
}


class ProbeAuditError(ValueError):
    """Raised when compiled template evidence cannot be safely interpreted."""


@dataclass(frozen=True)
class ProbeAuditResult:
    schema_version: str
    accepted: bool
    template_sha256: str
    policy_sha256: str
    findings: tuple[str, ...]
    evidence_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def audit_template(template: dict[str, Any]) -> ProbeAuditResult:
    """Verify the reviewed probe contract in one compiled ARM template."""

    if not isinstance(template, dict):
        raise ProbeAuditError("template root must be an object")
    resources = template.get("resources")
    if not isinstance(resources, list):
        raise ProbeAuditError("template resources must be an array")
    if len(resources) > 10_000:
        raise ProbeAuditError("template resource budget exceeded")
    if any(not isinstance(resource, dict) for resource in resources):
        raise ProbeAuditError("template resources must contain only objects")

    findings: list[str] = []
    apps = [
        resource
        for resource in resources
        if isinstance(resource, dict)
        and resource.get("type") == "Microsoft.App/containerApps"
    ]
    if len(apps) != 1:
        findings.append("CONTAINER_APP_COUNT_MISMATCH")
    else:
        _audit_container_app(apps[0], findings)

    template_sha256 = _digest(template)
    policy_sha256 = _digest(PROBE_POLICY)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "accepted": not findings,
        "template_sha256": template_sha256,
        "policy_sha256": policy_sha256,
        "findings": tuple(findings),
    }
    return ProbeAuditResult(**payload, evidence_sha256=_digest(payload))


def load_template(
    path: str | Path, *, max_bytes: int = MAX_TEMPLATE_BYTES
) -> dict[str, Any]:
    """Read a bounded regular JSON file without following its final symlink."""

    template_path = Path(path)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ProbeAuditError("max_bytes must be a positive integer")
    try:
        before = template_path.lstat()
    except OSError as exc:
        raise ProbeAuditError("template cannot be inspected") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ProbeAuditError("template must be a regular non-symlink file")
    if not 0 < before.st_size <= max_bytes:
        raise ProbeAuditError("template size is outside the permitted range")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(template_path, flags)
    except OSError as exc:
        raise ProbeAuditError("template cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ProbeAuditError("template descriptor is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if len(raw) > max_bytes or len(raw) != opened.st_size:
        raise ProbeAuditError("template size changed or exceeded the budget")
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_opened or identity_opened != identity_after:
        raise ProbeAuditError("template changed while it was being read")
    try:
        decoded = raw.decode("utf-8")
        template = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeAuditError("template must be strict UTF-8 JSON") from exc
    if not isinstance(template, dict):
        raise ProbeAuditError("template root must be an object")
    return template


def _audit_container_app(app: dict[str, Any], findings: list[str]) -> None:
    properties = app.get("properties")
    if not isinstance(properties, dict):
        findings.append("CONTAINER_APP_PROPERTIES_MISSING")
        return
    configuration = properties.get("configuration")
    ingress = configuration.get("ingress") if isinstance(configuration, dict) else None
    target_port = ingress.get("targetPort") if isinstance(ingress, dict) else None
    if not _is_exact_int(target_port) or not 1 <= target_port <= 65_535:
        findings.append("INGRESS_TARGET_PORT_INVALID")
        return

    revision = properties.get("template")
    containers = revision.get("containers") if isinstance(revision, dict) else None
    if not isinstance(containers, list):
        findings.append("CONTAINER_LIST_MISSING")
        return
    api_containers = [
        container
        for container in containers
        if isinstance(container, dict) and container.get("name") == "api"
    ]
    if len(api_containers) != 1:
        findings.append("API_CONTAINER_COUNT_MISMATCH")
        return
    probes = api_containers[0].get("probes")
    if not isinstance(probes, list):
        findings.append("PROBE_LIST_MISSING")
        return
    if any(
        not isinstance(probe, dict) or not isinstance(probe.get("type"), str)
        for probe in probes
    ):
        findings.append("PROBE_TYPE_SET_MISMATCH")
        return
    probe_types = [probe["type"] for probe in probes]
    if len(probes) != len(PROBE_POLICY) or sorted(probe_types) != sorted(PROBE_POLICY):
        findings.append("PROBE_TYPE_SET_MISMATCH")
        return
    for probe in probes:
        probe_type = probe["type"]
        if not _probe_matches(probe, probe_type, target_port):
            findings.append(f"{probe_type.upper()}_PROBE_POLICY_MISMATCH")


def _probe_matches(probe: dict[str, Any], probe_type: str, target_port: int) -> bool:
    expected = PROBE_POLICY[probe_type]
    expected_keys = {
        "type",
        "httpGet",
        "initialDelaySeconds",
        "periodSeconds",
        "timeoutSeconds",
        "failureThreshold",
        "successThreshold",
    }
    if set(probe) != expected_keys:
        return False
    http_get = probe.get("httpGet")
    if not isinstance(http_get, dict) or set(http_get) != {"path", "port", "scheme"}:
        return False
    if http_get != {"path": expected["path"], "port": target_port, "scheme": "HTTP"}:
        return False
    return all(
        _is_exact_int(probe.get(field)) and probe[field] == expected[field]
        for field in (
            "initialDelaySeconds",
            "periodSeconds",
            "timeoutSeconds",
            "failureThreshold",
            "successThreshold",
        )
    )


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeAuditError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ProbeAuditError(f"non-finite JSON constant is forbidden: {value}")


def _digest(value: Any) -> str:
    try:
        rendered = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise ProbeAuditError("evidence must be canonical finite JSON") from exc
    return hashlib.sha256(rendered.encode()).hexdigest()


def _write_result(path: Path, result: ProbeAuditResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Container Apps health probes")
    parser.add_argument("template", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = audit_template(load_template(args.template))
    except ProbeAuditError as exc:
        print(
            json.dumps({"error": str(exc), "schema_version": SCHEMA_VERSION}),
            file=sys.stderr,
        )
        return 3
    if args.output is not None:
        _write_result(args.output, result)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.accepted else 2


if __name__ == "__main__":
    raise SystemExit(main())
