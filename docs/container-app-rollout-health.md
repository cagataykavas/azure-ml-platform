# Azure Container Apps rollout health gate

`tools/container_app_rollout_gate.py` is a credential-free policy core for staged
Azure Container Apps revision rollouts. It evaluates normalized evidence collected
after a candidate revision receives traffic and before the next traffic increase.

This closes a different failure window from template compilation or ARM What-If:
a deployment can be structurally safe and still produce 5xx errors, latency
regression, replica instability, or probe failures after it starts serving.

## Evidence contract

The v1 artifact binds the audit to:

- the Container App resource ID;
- distinct candidate and baseline revisions;
- an immutable `sha256:` container image digest;
- an evidence creation time; and
- an ordered set of strictly increasing traffic stages.

Each stage contains its UTC-aware interval, candidate/baseline traffic weights,
request and 5xx counts, p95 latency, candidate replica readiness, restart count,
health-probe failures, and an explicit telemetry-completeness flag. Traffic weights
must total 100%. Stages must be non-overlapping and the candidate weight must
increase strictly.

The input is intentionally normalized. A protected deployment job should collect
revision/traffic state from Azure Resource Manager and aggregate request/latency
signals from Azure Monitor or Application Insights. The collector should retain the
raw query result separately; this repository does not need Azure credentials.

## Default admission policy

The gate requires:

- at least two stages, each at least five minutes long;
- no telemetry gap longer than two minutes;
- complete telemetry and at least 200 candidate requests per stage;
- at least 200 baseline requests whenever baseline traffic is non-zero;
- final candidate traffic of at least 25%;
- candidate 5xx rate at most 1%;
- candidate-minus-baseline 5xx rate at most 0.5 percentage points;
- candidate p95 at most 1,000 ms and 1.5× baseline;
- all candidate replicas ready;
- zero restarts and zero health-probe failures; and
- evidence no more than one hour old, with at most 60 seconds of future skew.

Thresholds are explicit policy, not universal SLOs. A production pipeline should
calibrate them per endpoint and rollout stage while preserving the fail-closed
behavior for missing comparison evidence.

## CLI

```bash
python tools/container_app_rollout_gate.py rollout.json \
  --now 2026-09-27T04:30:00Z \
  --output rollout-report.json
```

Exit codes are stable for automation:

| Code | Meaning |
| ---: | --- |
| `0` | evidence is well formed and policy accepted the rollout |
| `2` | evidence is well formed but the rollout violates policy |
| `3` | evidence or policy is malformed and cannot be evaluated safely |

The report contains canonical artifact and policy SHA-256 identities, hashed
resource/revision references, bounded findings, deterministic reason codes, and
aggregate metrics. It does not copy raw resource IDs, revision names, stage IDs,
timestamps, request rows, or logs. The immutable image digest remains visible so a
promotion controller can bind the decision to the exact deployable image.

## Deployment integration

A safe traffic step is:

1. deploy a new inactive revision pinned by digest;
2. assign the first canary traffic weight;
3. collect a complete stage interval from ARM and Azure Monitor;
4. increase traffic only after the audit returns `0`;
5. stop and roll traffic back on exit `2` or `3`; and
6. retain the raw evidence and JSON report under the deployment/change record.

The final promotion job should compare the report's artifact digest, image digest,
policy digest, and candidate revision reference with the values it is about to
promote. Merely running the gate without binding its decision to the traffic update
would leave a time-of-check/time-of-use gap.

## Failure behavior and resource limits

The evaluator rejects duplicate JSON fields, unknown fields, non-finite values,
naive timestamps, invalid count relationships, mutable image references, duplicate
stages, overlapping chronology, non-monotonic traffic, and inconsistent replica
counts. Artifact bytes, stage count, numeric ranges, and reported findings are
bounded before or during evaluation.

Output is written atomically when `--output` is supplied. A policy rejection still
produces a complete report; malformed evidence produces a minimal error report and
never falls back to acceptance.

## Limits and next step

This gate trusts its evidence producer. It does not authenticate Azure Monitor
queries, prove that request cohorts were routed to the claimed revision, detect
within-window spikes hidden by aggregates, or issue a rollback itself. Low-volume
services also need longer stages or a statistically appropriate policy rather than
lowering sample requirements without justification.

The next production increment is a least-privilege collector that signs the raw ARM
and Azure Monitor evidence, followed by a deployment controller that transactionally
binds an accepted report digest to the exact traffic-weight update.
