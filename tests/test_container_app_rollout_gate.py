from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from tools.container_app_rollout_gate import (
    EXIT_ACCEPTED,
    EXIT_MALFORMED,
    EXIT_POLICY_REJECTED,
    MalformedEvidence,
    RolloutPolicy,
    audit_bytes,
    main,
)

NOW = datetime(2026, 9, 27, 4, 30, tzinfo=UTC)


def valid_artifact() -> dict[str, object]:
    def stage(
        stage_id: str,
        start: str,
        end: str,
        candidate_traffic: float,
        baseline_traffic: float,
    ) -> dict[str, object]:
        return {
            "stage_id": stage_id,
            "started_at": start,
            "ended_at": end,
            "candidate_traffic_percent": candidate_traffic,
            "baseline_traffic_percent": baseline_traffic,
            "candidate_requests": 1000,
            "candidate_5xx": 2,
            "baseline_requests": 1000,
            "baseline_5xx": 1,
            "candidate_p95_ms": 100.0,
            "baseline_p95_ms": 90.0,
            "candidate_ready_replicas": 2,
            "candidate_total_replicas": 2,
            "candidate_restart_count": 0,
            "health_probe_failures": 0,
            "telemetry_complete": True,
        }

    return {
        "schema_version": "azure-container-app-rollout/v1",
        "audit_id": "rollout-20260927-001",
        "app_resource_id": "/subscriptions/000/resourceGroups/ml/providers/Microsoft.App/containerApps/api",
        "candidate_revision": "ml-inference--sha-abc123",
        "baseline_revision": "ml-inference--sha-def456",
        "image_digest": "sha256:" + "a" * 64,
        "created_at": "2026-09-27T04:20:00Z",
        "stages": [
            stage(
                "canary-05", "2026-09-27T04:00:00Z", "2026-09-27T04:05:00Z", 5.0, 95.0
            ),
            stage(
                "canary-25", "2026-09-27T04:06:00Z", "2026-09-27T04:11:00Z", 25.0, 75.0
            ),
        ],
    }


def encoded(artifact: dict[str, object]) -> bytes:
    return json.dumps(artifact, separators=(",", ":")).encode()


def audit(
    artifact: dict[str, object],
    *,
    policy: RolloutPolicy | None = None,
    now: datetime = NOW,
) -> dict[str, object]:
    return audit_bytes(encoded(artifact), policy=policy or RolloutPolicy(), now=now)


class AcceptedAuditTests(unittest.TestCase):
    def test_accepts_healthy_staged_rollout(self) -> None:
        report = audit(valid_artifact())

        self.assertTrue(report["accepted"])
        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["reason_codes"], [])
        self.assertEqual(report["summary"]["stage_count"], 2)
        self.assertEqual(report["summary"]["final_candidate_traffic_percent"], 25.0)
        self.assertEqual(report["summary"]["total_candidate_requests"], 2000)

    def test_key_order_does_not_change_artifact_digest(self) -> None:
        first = valid_artifact()
        second = dict(reversed(list(copy.deepcopy(first).items())))

        self.assertEqual(
            audit(first)["artifact_sha256"], audit(second)["artifact_sha256"]
        )

    def test_timezone_representation_does_not_change_artifact_digest(self) -> None:
        first = valid_artifact()
        second = copy.deepcopy(first)
        second["created_at"] = "2026-09-27T07:20:00+03:00"
        second["stages"][0]["started_at"] = "2026-09-27T07:00:00+03:00"
        second["stages"][0]["ended_at"] = "2026-09-27T07:05:00+03:00"
        second["stages"][1]["started_at"] = "2026-09-27T07:06:00+03:00"
        second["stages"][1]["ended_at"] = "2026-09-27T07:11:00+03:00"

        self.assertEqual(
            audit(first)["artifact_sha256"], audit(second)["artifact_sha256"]
        )

    def test_report_does_not_expose_raw_identifiers(self) -> None:
        artifact = valid_artifact()
        rendered = json.dumps(audit(artifact))

        self.assertNotIn(artifact["audit_id"], rendered)
        self.assertNotIn(artifact["app_resource_id"], rendered)
        self.assertNotIn(artifact["candidate_revision"], rendered)
        self.assertIn(artifact["image_digest"], rendered)

    def test_allows_full_cutover_without_baseline_requests(self) -> None:
        artifact = valid_artifact()
        final = artifact["stages"][-1]
        final["candidate_traffic_percent"] = 100.0
        final["baseline_traffic_percent"] = 0.0
        final["baseline_requests"] = 0
        final["baseline_5xx"] = 0
        final["baseline_p95_ms"] = 0.0

        self.assertTrue(audit(artifact)["accepted"])


class PolicyFindingTests(unittest.TestCase):
    def assert_reason(
        self,
        artifact: dict[str, object],
        code: str,
        policy: RolloutPolicy | None = None,
    ) -> None:
        report = audit(artifact, policy=policy)
        self.assertFalse(report["accepted"])
        self.assertIn(code, report["reason_codes"])

    def test_rejects_stale_evidence(self) -> None:
        self.assert_reason(
            valid_artifact(),
            "EVIDENCE_STALE",
            RolloutPolicy(max_evidence_age_seconds=60),
        )

    def test_rejects_stale_observation_window_even_with_fresh_artifact(self) -> None:
        artifact = valid_artifact()
        artifact["created_at"] = "2026-09-27T04:29:30Z"
        self.assert_reason(
            artifact,
            "OBSERVATION_WINDOW_STALE",
            RolloutPolicy(max_evidence_age_seconds=600),
        )

    def test_rejects_evidence_too_far_in_future(self) -> None:
        artifact = valid_artifact()
        artifact["created_at"] = "2026-09-27T04:32:00Z"
        self.assert_reason(
            artifact, "EVIDENCE_FROM_FUTURE", RolloutPolicy(max_future_skew_seconds=30)
        )

    def test_rejects_short_stage(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["ended_at"] = "2026-09-27T04:04:59Z"
        self.assert_reason(artifact, "STAGE_DURATION_TOO_SHORT")

    def test_rejects_telemetry_gap(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][1]["started_at"] = "2026-09-27T04:08:00Z"
        artifact["stages"][1]["ended_at"] = "2026-09-27T04:13:00Z"
        self.assert_reason(artifact, "TELEMETRY_GAP_EXCEEDED")

    def test_rejects_incomplete_telemetry(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["telemetry_complete"] = False
        self.assert_reason(artifact, "TELEMETRY_INCOMPLETE")

    def test_rejects_small_candidate_sample(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_requests"] = 199
        artifact["stages"][0]["candidate_5xx"] = 0
        self.assert_reason(artifact, "CANDIDATE_SAMPLE_TOO_SMALL")

    def test_rejects_absolute_candidate_error_rate(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_5xx"] = 11
        self.assert_reason(artifact, "CANDIDATE_5XX_RATE_EXCEEDED")

    def test_rejects_candidate_error_delta(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_5xx"] = 7
        artifact["stages"][0]["baseline_5xx"] = 1
        policy = RolloutPolicy(max_candidate_5xx_rate=0.02, max_5xx_rate_delta=0.005)
        self.assert_reason(artifact, "CANDIDATE_5XX_DELTA_EXCEEDED", policy)

    def test_rejects_small_baseline_sample_when_traffic_is_present(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["baseline_requests"] = 199
        artifact["stages"][0]["baseline_5xx"] = 0
        self.assert_reason(artifact, "BASELINE_SAMPLE_TOO_SMALL")

    def test_rejects_missing_baseline_latency(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["baseline_p95_ms"] = 0.0
        self.assert_reason(artifact, "BASELINE_LATENCY_UNAVAILABLE")

    def test_rejects_absolute_candidate_latency(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_p95_ms"] = 1001.0
        artifact["stages"][0]["baseline_p95_ms"] = 1000.0
        self.assert_reason(artifact, "CANDIDATE_P95_ABSOLUTE_EXCEEDED")

    def test_rejects_relative_candidate_latency(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_p95_ms"] = 151.0
        artifact["stages"][0]["baseline_p95_ms"] = 100.0
        self.assert_reason(artifact, "CANDIDATE_P95_RATIO_EXCEEDED")

    def test_rejects_unready_candidate_replicas(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_ready_replicas"] = 1
        self.assert_reason(artifact, "CANDIDATE_REPLICAS_UNREADY")

    def test_rejects_restart_budget(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_restart_count"] = 1
        self.assert_reason(artifact, "CANDIDATE_RESTART_BUDGET_EXCEEDED")

    def test_rejects_health_probe_failures(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["health_probe_failures"] = 1
        self.assert_reason(artifact, "HEALTH_PROBE_FAILURE_BUDGET_EXCEEDED")

    def test_rejects_final_traffic_below_target(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][1]["candidate_traffic_percent"] = 20.0
        artifact["stages"][1]["baseline_traffic_percent"] = 80.0
        self.assert_reason(artifact, "FINAL_TRAFFIC_BELOW_AUDIT_TARGET")

    def test_rejects_too_few_stages_as_policy_evidence(self) -> None:
        artifact = valid_artifact()
        artifact["stages"] = artifact["stages"][:1]
        self.assert_reason(artifact, "STAGE_COUNT_BELOW_MINIMUM")

    def test_bounds_reported_findings_and_marks_truncation(self) -> None:
        artifact = valid_artifact()
        for stage in artifact["stages"]:
            stage["candidate_requests"] = 1
            stage["candidate_5xx"] = 1
            stage["candidate_p95_ms"] = 2000.0
            stage["candidate_ready_replicas"] = 0
            stage["candidate_restart_count"] = 3
            stage["health_probe_failures"] = 4
            stage["telemetry_complete"] = False
        report = audit(artifact, policy=RolloutPolicy(max_findings=3))

        self.assertGreater(report["finding_count"], 3)
        self.assertEqual(len(report["findings"]), 3)
        self.assertTrue(report["findings_truncated"])


class MalformedArtifactTests(unittest.TestCase):
    def assert_malformed(
        self, artifact: dict[str, object], policy: RolloutPolicy | None = None
    ) -> None:
        with self.assertRaises(MalformedEvidence):
            audit(artifact, policy=policy)

    def test_rejects_duplicate_json_fields(self) -> None:
        raw = encoded(valid_artifact()).replace(
            b'"audit_id":"rollout-20260927-001",',
            b'"audit_id":"rollout-20260927-001","audit_id":"other",',
        )
        with self.assertRaises(MalformedEvidence):
            audit_bytes(raw, policy=RolloutPolicy(), now=NOW)

    def test_rejects_nonfinite_json_numbers(self) -> None:
        raw = encoded(valid_artifact()).replace(
            b'"candidate_p95_ms":100.0', b'"candidate_p95_ms":NaN', 1
        )
        with self.assertRaises(MalformedEvidence):
            audit_bytes(raw, policy=RolloutPolicy(), now=NOW)

    def test_rejects_artifact_over_byte_budget(self) -> None:
        with self.assertRaises(MalformedEvidence):
            audit_bytes(
                encoded(valid_artifact()),
                policy=RolloutPolicy(max_artifact_bytes=10),
                now=NOW,
            )

    def test_rejects_unknown_root_field(self) -> None:
        artifact = valid_artifact()
        artifact["unexpected"] = True
        self.assert_malformed(artifact)

    def test_rejects_unknown_stage_field(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["cpu"] = 0.5
        self.assert_malformed(artifact)

    def test_rejects_naive_timestamp(self) -> None:
        artifact = valid_artifact()
        artifact["created_at"] = "2026-09-27T04:20:00"
        self.assert_malformed(artifact)

    def test_rejects_overlapping_stages(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][1]["started_at"] = "2026-09-27T04:04:00Z"
        self.assert_malformed(artifact)

    def test_rejects_stage_ending_after_creation(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][1]["ended_at"] = "2026-09-27T04:21:00Z"
        self.assert_malformed(artifact)

    def test_rejects_nonincreasing_candidate_traffic(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][1]["candidate_traffic_percent"] = 5.0
        artifact["stages"][1]["baseline_traffic_percent"] = 95.0
        self.assert_malformed(artifact)

    def test_rejects_zero_candidate_traffic_stage(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_traffic_percent"] = 0.0
        artifact["stages"][0]["baseline_traffic_percent"] = 100.0
        self.assert_malformed(artifact)

    def test_rejects_traffic_not_summing_to_100(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["baseline_traffic_percent"] = 90.0
        self.assert_malformed(artifact)

    def test_rejects_more_errors_than_requests(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_5xx"] = 1001
        self.assert_malformed(artifact)

    def test_rejects_same_candidate_and_baseline_revision(self) -> None:
        artifact = valid_artifact()
        artifact["baseline_revision"] = artifact["candidate_revision"]
        self.assert_malformed(artifact)

    def test_rejects_mutable_image_reference(self) -> None:
        artifact = valid_artifact()
        artifact["image_digest"] = "registry.example/api:latest"
        self.assert_malformed(artifact)

    def test_zero_candidate_replicas_is_a_policy_rejection(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_total_replicas"] = 0
        artifact["stages"][0]["candidate_ready_replicas"] = 0
        report = audit(artifact)
        self.assertIn("CANDIDATE_REPLICAS_UNREADY", report["reason_codes"])

    def test_rejects_boolean_count(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["candidate_requests"] = True
        self.assert_malformed(artifact)

    def test_rejects_empty_stages(self) -> None:
        artifact = valid_artifact()
        artifact["stages"] = []
        self.assert_malformed(artifact)

    def test_rejects_duplicate_stage_id(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][1]["stage_id"] = artifact["stages"][0]["stage_id"]
        self.assert_malformed(artifact)


class PolicyValidationTests(unittest.TestCase):
    def test_rejects_nonfinite_policy(self) -> None:
        with self.assertRaises(ValueError):
            RolloutPolicy(max_candidate_p95_ms=float("inf")).validate()

    def test_rejects_boolean_integer_policy(self) -> None:
        with self.assertRaises(ValueError):
            RolloutPolicy(max_stages=True).validate()

    def test_rejects_invalid_error_rate_policy(self) -> None:
        with self.assertRaises(ValueError):
            RolloutPolicy(max_candidate_5xx_rate=1.1).validate()


class CliTests(unittest.TestCase):
    def run_cli(
        self, artifact: dict[str, object] | bytes
    ) -> tuple[int, dict[str, object]]:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "artifact.json"
            output = Path(temporary) / "report.json"
            source.write_bytes(
                artifact if isinstance(artifact, bytes) else encoded(artifact)
            )
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        str(source),
                        "--output",
                        str(output),
                        "--now",
                        "2026-09-27T04:30:00Z",
                    ]
                )
            return exit_code, json.loads(output.read_text(encoding="utf-8"))

    def test_cli_returns_zero_for_accepted_artifact(self) -> None:
        exit_code, report = self.run_cli(valid_artifact())
        self.assertEqual(exit_code, EXIT_ACCEPTED)
        self.assertTrue(report["accepted"])

    def test_cli_returns_two_for_policy_rejection(self) -> None:
        artifact = valid_artifact()
        artifact["stages"][0]["health_probe_failures"] = 1
        exit_code, report = self.run_cli(artifact)
        self.assertEqual(exit_code, EXIT_POLICY_REJECTED)
        self.assertFalse(report["accepted"])
        self.assertNotIn("malformed", report)

    def test_cli_returns_three_for_malformed_artifact(self) -> None:
        exit_code, report = self.run_cli(b"not-json")
        self.assertEqual(exit_code, EXIT_MALFORMED)
        self.assertTrue(report["malformed"])
        self.assertEqual(report["reason_codes"], ["MALFORMED_EVIDENCE"])


if __name__ == "__main__":
    unittest.main()
