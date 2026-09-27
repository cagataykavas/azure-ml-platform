"""Fail-closed Azure Container Apps staged-rollout health audit.

The module deliberately consumes a normalized evidence artifact instead of calling
Azure APIs.  Collection credentials, Azure Monitor query provenance, and signing
belong in the deployment environment; this policy core stays deterministic and
credential-free so the same artifact can be re-evaluated in CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "azure-container-app-rollout/v1"
EXIT_ACCEPTED = 0
EXIT_POLICY_REJECTED = 2
EXIT_MALFORMED = 3

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESOURCE_ID_RE = re.compile(
    r"^/subscriptions/[A-Za-z0-9-]{1,64}/resourceGroups/[A-Za-z0-9._()-]{1,90}"
    r"/providers/Microsoft\.App/containerApps/[A-Za-z0-9-]{1,32}$",
    re.IGNORECASE,
)
_ROOT_FIELDS = {
    "schema_version",
    "audit_id",
    "app_resource_id",
    "candidate_revision",
    "baseline_revision",
    "image_digest",
    "created_at",
    "stages",
}
_STAGE_FIELDS = {
    "stage_id",
    "started_at",
    "ended_at",
    "candidate_traffic_percent",
    "baseline_traffic_percent",
    "candidate_requests",
    "candidate_5xx",
    "baseline_requests",
    "baseline_5xx",
    "candidate_p95_ms",
    "baseline_p95_ms",
    "candidate_ready_replicas",
    "candidate_total_replicas",
    "candidate_restart_count",
    "health_probe_failures",
    "telemetry_complete",
}


class MalformedEvidence(ValueError):
    """Raised when an artifact cannot safely be evaluated."""


@dataclass(frozen=True)
class RolloutPolicy:
    min_stages: int = 2
    max_stages: int = 16
    min_stage_duration_seconds: float = 300.0
    max_stage_gap_seconds: float = 120.0
    min_candidate_requests_per_stage: int = 200
    min_baseline_requests_for_comparison: int = 200
    min_final_candidate_traffic_percent: float = 25.0
    max_candidate_5xx_rate: float = 0.01
    max_5xx_rate_delta: float = 0.005
    max_candidate_p95_ms: float = 1000.0
    max_p95_ratio: float = 1.5
    max_unready_fraction: float = 0.0
    max_restart_count_per_stage: int = 0
    max_health_probe_failures_per_stage: int = 0
    max_evidence_age_seconds: float = 3600.0
    max_future_skew_seconds: float = 60.0
    max_artifact_bytes: int = 262_144
    max_findings: int = 128

    def validate(self) -> None:
        integer_fields = {
            "min_stages": self.min_stages,
            "max_stages": self.max_stages,
            "min_candidate_requests_per_stage": self.min_candidate_requests_per_stage,
            "min_baseline_requests_for_comparison": self.min_baseline_requests_for_comparison,
            "max_restart_count_per_stage": self.max_restart_count_per_stage,
            "max_health_probe_failures_per_stage": self.max_health_probe_failures_per_stage,
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_findings": self.max_findings,
        }
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in integer_fields.values()
        ):
            raise ValueError("policy integer fields must be integers")
        if self.min_stages < 1 or self.max_stages < self.min_stages:
            raise ValueError("invalid stage-count policy")
        if self.max_stages > 10_000:
            raise ValueError("max_stages exceeds the evaluator budget")
        if self.min_candidate_requests_per_stage < 1:
            raise ValueError("candidate request minimum must be positive")
        if self.min_baseline_requests_for_comparison < 1:
            raise ValueError("baseline request minimum must be positive")
        if (
            self.max_restart_count_per_stage < 0
            or self.max_health_probe_failures_per_stage < 0
        ):
            raise ValueError("failure budgets cannot be negative")
        if self.max_artifact_bytes < 1 or self.max_artifact_bytes > 8_388_608:
            raise ValueError("invalid artifact byte budget")
        if self.max_findings < 1 or self.max_findings > 10_000:
            raise ValueError("invalid finding budget")

        finite_nonnegative = {
            "min_stage_duration_seconds": self.min_stage_duration_seconds,
            "max_stage_gap_seconds": self.max_stage_gap_seconds,
            "max_candidate_5xx_rate": self.max_candidate_5xx_rate,
            "max_5xx_rate_delta": self.max_5xx_rate_delta,
            "max_candidate_p95_ms": self.max_candidate_p95_ms,
            "max_p95_ratio": self.max_p95_ratio,
            "max_unready_fraction": self.max_unready_fraction,
            "max_evidence_age_seconds": self.max_evidence_age_seconds,
            "max_future_skew_seconds": self.max_future_skew_seconds,
        }
        for name, value in finite_nonnegative.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if not math.isfinite(float(value)) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
        if not 0 < self.min_final_candidate_traffic_percent <= 100:
            raise ValueError("final candidate traffic must be in (0, 100]")
        if (
            not 0 <= self.max_candidate_5xx_rate <= 1
            or not 0 <= self.max_5xx_rate_delta <= 1
        ):
            raise ValueError("error-rate thresholds must be in [0, 1]")
        if self.max_candidate_p95_ms <= 0 or self.max_p95_ratio < 1:
            raise ValueError("latency thresholds must be positive")
        if not 0 <= self.max_unready_fraction <= 1:
            raise ValueError("unready fraction must be in [0, 1]")


@dataclass(frozen=True)
class Stage:
    stage_id: str
    started_at: datetime
    ended_at: datetime
    candidate_traffic_percent: float
    baseline_traffic_percent: float
    candidate_requests: int
    candidate_5xx: int
    baseline_requests: int
    baseline_5xx: int
    candidate_p95_ms: float
    baseline_p95_ms: float
    candidate_ready_replicas: int
    candidate_total_replicas: int
    candidate_restart_count: int
    health_probe_failures: int
    telemetry_complete: bool


@dataclass(frozen=True)
class Artifact:
    audit_id: str
    app_resource_id: str
    candidate_revision: str
    baseline_revision: str
    image_digest: str
    created_at: datetime
    stages: tuple[Stage, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MalformedEvidence(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json_strict(raw: bytes, *, max_bytes: int) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise MalformedEvidence("artifact exceeds byte budget")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedEvidence("artifact is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise MalformedEvidence("artifact is not valid bounded JSON") from exc
    if not isinstance(value, dict):
        raise MalformedEvidence("artifact root must be an object")
    return value


def _reject_constant(value: str) -> None:
    raise MalformedEvidence(f"non-finite JSON number: {value}")


def _exact_fields(value: dict[str, Any], expected: set[str], *, location: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise MalformedEvidence(
            f"{location} fields mismatch; missing={missing}, unknown={unknown}"
        )


def _identifier(value: Any, *, name: str, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise MalformedEvidence(f"{name} must be a non-empty bounded string")
    if not _IDENTIFIER_RE.fullmatch(value):
        raise MalformedEvidence(f"{name} contains unsupported characters")
    return value


def _resource_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not _RESOURCE_ID_RE.fullmatch(value)
    ):
        raise MalformedEvidence("app_resource_id must identify one Azure Container App")
    return value


def _timestamp(value: Any, *, name: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise MalformedEvidence(f"{name} must be a bounded RFC3339 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise MalformedEvidence(f"{name} is not a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MalformedEvidence(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _integer(value: Any, *, name: str, maximum: int = 1_000_000_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedEvidence(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise MalformedEvidence(f"{name} is outside the supported range")
    return value


def _number(value: Any, *, name: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedEvidence(f"{name} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0 or numeric > maximum:
        raise MalformedEvidence(f"{name} is outside the supported range")
    return numeric


def parse_artifact(value: dict[str, Any], *, policy: RolloutPolicy) -> Artifact:
    _exact_fields(value, _ROOT_FIELDS, location="root")
    if value["schema_version"] != SCHEMA_VERSION:
        raise MalformedEvidence("unsupported schema_version")

    audit_id = _identifier(value["audit_id"], name="audit_id")
    app_resource_id = _resource_id(value["app_resource_id"])
    candidate_revision = _identifier(
        value["candidate_revision"], name="candidate_revision"
    )
    baseline_revision = _identifier(
        value["baseline_revision"], name="baseline_revision"
    )
    if candidate_revision == baseline_revision:
        raise MalformedEvidence("candidate and baseline revisions must differ")
    image_digest = value["image_digest"]
    if not isinstance(image_digest, str) or not _IMAGE_DIGEST_RE.fullmatch(
        image_digest
    ):
        raise MalformedEvidence("image_digest must be a lowercase sha256 digest")
    created_at = _timestamp(value["created_at"], name="created_at")

    raw_stages = value["stages"]
    if not isinstance(raw_stages, list):
        raise MalformedEvidence("stages must be an array")
    if not 1 <= len(raw_stages) <= policy.max_stages:
        raise MalformedEvidence("stage count is outside the evaluator budget")

    stages: list[Stage] = []
    seen_ids: set[str] = set()
    previous_end: datetime | None = None
    previous_traffic = -1.0
    for index, raw_stage in enumerate(raw_stages):
        location = f"stages[{index}]"
        if not isinstance(raw_stage, dict):
            raise MalformedEvidence(f"{location} must be an object")
        _exact_fields(raw_stage, _STAGE_FIELDS, location=location)
        stage_id = _identifier(raw_stage["stage_id"], name=f"{location}.stage_id")
        if stage_id in seen_ids:
            raise MalformedEvidence("stage_id values must be unique")
        seen_ids.add(stage_id)
        started_at = _timestamp(raw_stage["started_at"], name=f"{location}.started_at")
        ended_at = _timestamp(raw_stage["ended_at"], name=f"{location}.ended_at")
        if ended_at <= started_at:
            raise MalformedEvidence("each rollout stage must have positive duration")
        if ended_at > created_at:
            raise MalformedEvidence("stage evidence cannot end after artifact creation")
        if previous_end is not None and started_at < previous_end:
            raise MalformedEvidence(
                "rollout stages must be ordered and non-overlapping"
            )
        previous_end = ended_at

        candidate_traffic = _number(
            raw_stage["candidate_traffic_percent"],
            name=f"{location}.candidate_traffic_percent",
            maximum=100,
        )
        baseline_traffic = _number(
            raw_stage["baseline_traffic_percent"],
            name=f"{location}.baseline_traffic_percent",
            maximum=100,
        )
        if not math.isclose(candidate_traffic + baseline_traffic, 100.0, abs_tol=1e-6):
            raise MalformedEvidence(
                "candidate and baseline traffic must sum to 100 percent"
            )
        if candidate_traffic <= 0:
            raise MalformedEvidence(
                "candidate traffic must be positive in every audited stage"
            )
        if candidate_traffic <= previous_traffic:
            raise MalformedEvidence(
                "candidate traffic must increase strictly across stages"
            )
        previous_traffic = candidate_traffic

        candidate_requests = _integer(
            raw_stage["candidate_requests"], name=f"{location}.candidate_requests"
        )
        candidate_5xx = _integer(
            raw_stage["candidate_5xx"], name=f"{location}.candidate_5xx"
        )
        baseline_requests = _integer(
            raw_stage["baseline_requests"], name=f"{location}.baseline_requests"
        )
        baseline_5xx = _integer(
            raw_stage["baseline_5xx"], name=f"{location}.baseline_5xx"
        )
        if candidate_5xx > candidate_requests or baseline_5xx > baseline_requests:
            raise MalformedEvidence("5xx count cannot exceed request count")

        candidate_total = _integer(
            raw_stage["candidate_total_replicas"],
            name=f"{location}.candidate_total_replicas",
            maximum=1_000_000,
        )
        candidate_ready = _integer(
            raw_stage["candidate_ready_replicas"],
            name=f"{location}.candidate_ready_replicas",
            maximum=1_000_000,
        )
        if candidate_ready > candidate_total:
            raise MalformedEvidence("candidate replica counts are inconsistent")
        telemetry_complete = raw_stage["telemetry_complete"]
        if not isinstance(telemetry_complete, bool):
            raise MalformedEvidence("telemetry_complete must be boolean")

        stages.append(
            Stage(
                stage_id=stage_id,
                started_at=started_at,
                ended_at=ended_at,
                candidate_traffic_percent=candidate_traffic,
                baseline_traffic_percent=baseline_traffic,
                candidate_requests=candidate_requests,
                candidate_5xx=candidate_5xx,
                baseline_requests=baseline_requests,
                baseline_5xx=baseline_5xx,
                candidate_p95_ms=_number(
                    raw_stage["candidate_p95_ms"],
                    name=f"{location}.candidate_p95_ms",
                    maximum=86_400_000,
                ),
                baseline_p95_ms=_number(
                    raw_stage["baseline_p95_ms"],
                    name=f"{location}.baseline_p95_ms",
                    maximum=86_400_000,
                ),
                candidate_ready_replicas=candidate_ready,
                candidate_total_replicas=candidate_total,
                candidate_restart_count=_integer(
                    raw_stage["candidate_restart_count"],
                    name=f"{location}.candidate_restart_count",
                ),
                health_probe_failures=_integer(
                    raw_stage["health_probe_failures"],
                    name=f"{location}.health_probe_failures",
                ),
                telemetry_complete=telemetry_complete,
            )
        )
    return Artifact(
        audit_id=audit_id,
        app_resource_id=app_resource_id,
        candidate_revision=candidate_revision,
        baseline_revision=baseline_revision,
        image_digest=image_digest,
        created_at=created_at,
        stages=tuple(stages),
    )


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical_artifact(artifact: Artifact) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "audit_id": artifact.audit_id,
        "app_resource_id": artifact.app_resource_id,
        "candidate_revision": artifact.candidate_revision,
        "baseline_revision": artifact.baseline_revision,
        "image_digest": artifact.image_digest,
        "created_at": _iso(artifact.created_at),
        "stages": [
            {
                **asdict(stage),
                "started_at": _iso(stage.started_at),
                "ended_at": _iso(stage.ended_at),
            }
            for stage in artifact.stages
        ],
    }


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _private_ref(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def evaluate(
    artifact: Artifact, *, policy: RolloutPolicy, now: datetime
) -> dict[str, Any]:
    policy.validate()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must include a timezone")
    now_utc = now.astimezone(UTC)
    findings: list[dict[str, Any]] = []

    def finding(code: str, stage: Stage | None, **details: Any) -> None:
        item: dict[str, Any] = {"code": code}
        if stage is not None:
            item["stage_ref"] = _private_ref(stage.stage_id)
        item.update(details)
        findings.append(item)

    age_seconds = (now_utc - artifact.created_at).total_seconds()
    if age_seconds < -policy.max_future_skew_seconds:
        finding("EVIDENCE_FROM_FUTURE", None)
    elif age_seconds > policy.max_evidence_age_seconds:
        finding("EVIDENCE_STALE", None, age_seconds=round(age_seconds, 6))
    observation_age_seconds = (now_utc - artifact.stages[-1].ended_at).total_seconds()
    if observation_age_seconds > policy.max_evidence_age_seconds:
        finding(
            "OBSERVATION_WINDOW_STALE",
            None,
            age_seconds=round(observation_age_seconds, 6),
        )
    if len(artifact.stages) < policy.min_stages:
        finding(
            "STAGE_COUNT_BELOW_MINIMUM",
            None,
            observed=len(artifact.stages),
            minimum=policy.min_stages,
        )

    max_error_rate = 0.0
    max_error_delta = 0.0
    max_candidate_p95 = 0.0
    max_p95_ratio = 0.0
    max_unready_fraction = 0.0
    total_candidate_requests = 0

    for index, stage in enumerate(artifact.stages):
        duration = (stage.ended_at - stage.started_at).total_seconds()
        if duration < policy.min_stage_duration_seconds:
            finding(
                "STAGE_DURATION_TOO_SHORT",
                stage,
                observed_seconds=round(duration, 6),
                minimum_seconds=policy.min_stage_duration_seconds,
            )
        if index:
            gap = (
                stage.started_at - artifact.stages[index - 1].ended_at
            ).total_seconds()
            if gap > policy.max_stage_gap_seconds:
                finding(
                    "TELEMETRY_GAP_EXCEEDED",
                    stage,
                    observed_seconds=round(gap, 6),
                    maximum_seconds=policy.max_stage_gap_seconds,
                )
        if not stage.telemetry_complete:
            finding("TELEMETRY_INCOMPLETE", stage)
        if stage.candidate_requests < policy.min_candidate_requests_per_stage:
            finding(
                "CANDIDATE_SAMPLE_TOO_SMALL",
                stage,
                observed=stage.candidate_requests,
                minimum=policy.min_candidate_requests_per_stage,
            )

        total_candidate_requests += stage.candidate_requests
        candidate_error_rate = (
            stage.candidate_5xx / stage.candidate_requests
            if stage.candidate_requests
            else 0.0
        )
        max_error_rate = max(max_error_rate, candidate_error_rate)
        if candidate_error_rate > policy.max_candidate_5xx_rate:
            finding(
                "CANDIDATE_5XX_RATE_EXCEEDED",
                stage,
                observed=round(candidate_error_rate, 12),
                maximum=policy.max_candidate_5xx_rate,
            )

        if stage.baseline_traffic_percent > 0:
            if stage.baseline_requests < policy.min_baseline_requests_for_comparison:
                finding(
                    "BASELINE_SAMPLE_TOO_SMALL",
                    stage,
                    observed=stage.baseline_requests,
                    minimum=policy.min_baseline_requests_for_comparison,
                )
            else:
                baseline_error_rate = stage.baseline_5xx / stage.baseline_requests
                error_delta = candidate_error_rate - baseline_error_rate
                max_error_delta = max(max_error_delta, error_delta)
                if error_delta > policy.max_5xx_rate_delta:
                    finding(
                        "CANDIDATE_5XX_DELTA_EXCEEDED",
                        stage,
                        observed=round(error_delta, 12),
                        maximum=policy.max_5xx_rate_delta,
                    )
                if stage.baseline_p95_ms <= 0:
                    finding("BASELINE_LATENCY_UNAVAILABLE", stage)
                else:
                    p95_ratio = stage.candidate_p95_ms / stage.baseline_p95_ms
                    max_p95_ratio = max(max_p95_ratio, p95_ratio)
                    if p95_ratio > policy.max_p95_ratio:
                        finding(
                            "CANDIDATE_P95_RATIO_EXCEEDED",
                            stage,
                            observed=round(p95_ratio, 12),
                            maximum=policy.max_p95_ratio,
                        )

        max_candidate_p95 = max(max_candidate_p95, stage.candidate_p95_ms)
        if stage.candidate_p95_ms > policy.max_candidate_p95_ms:
            finding(
                "CANDIDATE_P95_ABSOLUTE_EXCEEDED",
                stage,
                observed_ms=stage.candidate_p95_ms,
                maximum_ms=policy.max_candidate_p95_ms,
            )
        unready_fraction = (
            1.0
            if stage.candidate_total_replicas == 0
            else 1.0 - stage.candidate_ready_replicas / stage.candidate_total_replicas
        )
        max_unready_fraction = max(max_unready_fraction, unready_fraction)
        if unready_fraction > policy.max_unready_fraction:
            finding(
                "CANDIDATE_REPLICAS_UNREADY",
                stage,
                observed=round(unready_fraction, 12),
                maximum=policy.max_unready_fraction,
            )
        if stage.candidate_restart_count > policy.max_restart_count_per_stage:
            finding(
                "CANDIDATE_RESTART_BUDGET_EXCEEDED",
                stage,
                observed=stage.candidate_restart_count,
                maximum=policy.max_restart_count_per_stage,
            )
        if stage.health_probe_failures > policy.max_health_probe_failures_per_stage:
            finding(
                "HEALTH_PROBE_FAILURE_BUDGET_EXCEEDED",
                stage,
                observed=stage.health_probe_failures,
                maximum=policy.max_health_probe_failures_per_stage,
            )

    final_traffic = artifact.stages[-1].candidate_traffic_percent
    if final_traffic < policy.min_final_candidate_traffic_percent:
        finding(
            "FINAL_TRAFFIC_BELOW_AUDIT_TARGET",
            artifact.stages[-1],
            observed=final_traffic,
            minimum=policy.min_final_candidate_traffic_percent,
        )

    bounded_findings = findings[: policy.max_findings]
    canonical = _canonical_artifact(artifact)
    return {
        "schema_version": SCHEMA_VERSION,
        "accepted": not findings,
        "artifact_sha256": _digest(canonical),
        "policy_sha256": _digest(asdict(policy)),
        "audit_ref": _private_ref(artifact.audit_id),
        "app_resource_ref": _private_ref(artifact.app_resource_id),
        "candidate_revision_ref": _private_ref(artifact.candidate_revision),
        "baseline_revision_ref": _private_ref(artifact.baseline_revision),
        "image_digest": artifact.image_digest,
        "finding_count": len(findings),
        "findings_truncated": len(findings) > len(bounded_findings),
        "reason_codes": sorted({item["code"] for item in findings}),
        "findings": bounded_findings,
        "summary": {
            "stage_count": len(artifact.stages),
            "evidence_duration_seconds": round(
                (
                    artifact.stages[-1].ended_at - artifact.stages[0].started_at
                ).total_seconds(),
                6,
            ),
            "final_candidate_traffic_percent": final_traffic,
            "total_candidate_requests": total_candidate_requests,
            "max_candidate_5xx_rate": round(max_error_rate, 12),
            "max_candidate_5xx_delta": round(max_error_delta, 12),
            "max_candidate_p95_ms": max_candidate_p95,
            "max_candidate_p95_ratio": round(max_p95_ratio, 12),
            "max_candidate_unready_fraction": round(max_unready_fraction, 12),
        },
    }


def audit_bytes(raw: bytes, *, policy: RolloutPolicy, now: datetime) -> dict[str, Any]:
    policy.validate()
    decoded = load_json_strict(raw, max_bytes=policy.max_artifact_bytes)
    artifact = parse_artifact(decoded, policy=policy)
    return evaluate(artifact, policy=policy, now=now)


def _atomic_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--now", help="RFC3339 evaluation time; defaults to current UTC"
    )
    parser.add_argument("--min-final-traffic", type=float, default=25.0)
    parser.add_argument("--min-stage-seconds", type=float, default=300.0)
    parser.add_argument("--min-candidate-requests", type=int, default=200)
    parser.add_argument("--max-5xx-rate", type=float, default=0.01)
    parser.add_argument("--max-5xx-delta", type=float, default=0.005)
    parser.add_argument("--max-p95-ms", type=float, default=1000.0)
    parser.add_argument("--max-p95-ratio", type=float, default=1.5)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = RolloutPolicy(
            min_final_candidate_traffic_percent=args.min_final_traffic,
            min_stage_duration_seconds=args.min_stage_seconds,
            min_candidate_requests_per_stage=args.min_candidate_requests,
            max_candidate_5xx_rate=args.max_5xx_rate,
            max_5xx_rate_delta=args.max_5xx_delta,
            max_candidate_p95_ms=args.max_p95_ms,
            max_p95_ratio=args.max_p95_ratio,
        )
        now = _timestamp(args.now, name="now") if args.now else datetime.now(UTC)
        report = audit_bytes(args.artifact.read_bytes(), policy=policy, now=now)
    except (OSError, MalformedEvidence, TypeError, ValueError) as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "accepted": False,
            "malformed": True,
            "reason_codes": ["MALFORMED_EVIDENCE"],
            "message": str(exc),
        }
        exit_code = EXIT_MALFORMED
    else:
        exit_code = EXIT_ACCEPTED if report["accepted"] else EXIT_POLICY_REJECTED

    if args.output:
        _atomic_write(args.output, report)
    else:
        print(json.dumps(report, sort_keys=True, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
