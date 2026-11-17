from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from tools.container_app_probe_audit import (
    PROBE_POLICY,
    ProbeAuditError,
    audit_template,
    load_template,
    main,
)


def valid_template() -> dict[str, object]:
    probes = []
    for probe_type, policy in PROBE_POLICY.items():
        probes.append(
            {
                "type": probe_type,
                "httpGet": {
                    "path": policy["path"],
                    "port": 8000,
                    "scheme": "HTTP",
                },
                "initialDelaySeconds": policy["initialDelaySeconds"],
                "periodSeconds": policy["periodSeconds"],
                "timeoutSeconds": policy["timeoutSeconds"],
                "failureThreshold": policy["failureThreshold"],
                "successThreshold": policy["successThreshold"],
            }
        )
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [
            {
                "type": "Microsoft.App/containerApps",
                "name": "ml-inference",
                "properties": {
                    "configuration": {"ingress": {"targetPort": 8000}},
                    "template": {"containers": [{"name": "api", "probes": probes}]},
                },
            }
        ],
    }


class ProbeAuditTests(unittest.TestCase):
    def test_reviewed_probe_contract_is_accepted(self) -> None:
        result = audit_template(valid_template())

        self.assertTrue(result.accepted)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.template_sha256), 64)
        self.assertEqual(len(result.evidence_sha256), 64)

    def test_missing_probe_type_is_rejected(self) -> None:
        template = valid_template()
        template["resources"][0]["properties"]["template"]["containers"][0][
            "probes"
        ].pop()

        result = audit_template(template)

        self.assertFalse(result.accepted)
        self.assertEqual(result.findings, ("PROBE_TYPE_SET_MISMATCH",))

    def test_probe_port_must_match_ingress(self) -> None:
        template = valid_template()
        template["resources"][0]["properties"]["template"]["containers"][0]["probes"][
            0
        ]["httpGet"]["port"] = 9000

        result = audit_template(template)

        self.assertFalse(result.accepted)
        self.assertEqual(result.findings, ("STARTUP_PROBE_POLICY_MISMATCH",))

    def test_probe_path_and_timing_are_governed(self) -> None:
        template = valid_template()
        readiness = template["resources"][0]["properties"]["template"]["containers"][0][
            "probes"
        ][2]
        readiness["httpGet"]["path"] = "/health"
        readiness["failureThreshold"] = 4

        result = audit_template(template)

        self.assertEqual(result.findings, ("READINESS_PROBE_POLICY_MISMATCH",))

    def test_probe_transport_cannot_be_ambiguous(self) -> None:
        template = valid_template()
        template["resources"][0]["properties"]["template"]["containers"][0]["probes"][
            0
        ]["tcpSocket"] = {"port": 8000}

        result = audit_template(template)

        self.assertEqual(result.findings, ("STARTUP_PROBE_POLICY_MISMATCH",))

    def test_malformed_probe_entry_fails_closed(self) -> None:
        template = valid_template()
        template["resources"][0]["properties"]["template"]["containers"][0]["probes"][
            0
        ] = {"httpGet": {"port": 8000}}

        result = audit_template(template)

        self.assertEqual(result.findings, ("PROBE_TYPE_SET_MISMATCH",))

    def test_boolean_port_is_not_an_integer_port(self) -> None:
        template = valid_template()
        template["resources"][0]["properties"]["configuration"]["ingress"][
            "targetPort"
        ] = True

        result = audit_template(template)

        self.assertEqual(result.findings, ("INGRESS_TARGET_PORT_INVALID",))

    def test_evidence_is_deterministic_and_binds_template(self) -> None:
        template = valid_template()
        first = audit_template(template)
        repeated = audit_template(copy.deepcopy(template))
        changed = copy.deepcopy(template)
        changed["metadata"] = {"revision": "two"}

        self.assertEqual(first, repeated)
        self.assertNotEqual(
            first.template_sha256, audit_template(changed).template_sha256
        )
        self.assertNotEqual(
            first.evidence_sha256, audit_template(changed).evidence_sha256
        )

    def test_multiple_container_apps_are_rejected(self) -> None:
        template = valid_template()
        template["resources"].append(copy.deepcopy(template["resources"][0]))

        result = audit_template(template)

        self.assertEqual(result.findings, ("CONTAINER_APP_COUNT_MISMATCH",))

    def test_duplicate_json_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text('{"resources": [], "resources": []}', encoding="utf-8")

            with self.assertRaisesRegex(ProbeAuditError, "duplicate"):
                load_template(path)

    def test_non_finite_json_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text('{"resources": [], "value": NaN}', encoding="utf-8")

            with self.assertRaisesRegex(ProbeAuditError, "non-finite"):
                load_template(path)

    def test_symlink_template_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_text(json.dumps(valid_template()), encoding="utf-8")
            link = Path(directory) / "template.json"
            link.symlink_to(target)

            with self.assertRaisesRegex(ProbeAuditError, "non-symlink"):
                load_template(link)

    def test_size_budget_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text(json.dumps(valid_template()), encoding="utf-8")

            with self.assertRaisesRegex(ProbeAuditError, "size"):
                load_template(path, max_bytes=10)

    def test_cli_returns_distinct_policy_and_malformed_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            accepted_path = Path(directory) / "accepted.json"
            rejected_path = Path(directory) / "rejected.json"
            malformed_path = Path(directory) / "malformed.json"
            accepted_path.write_text(json.dumps(valid_template()), encoding="utf-8")
            rejected = valid_template()
            rejected["resources"][0]["properties"]["template"]["containers"][0][
                "probes"
            ] = []
            rejected_path.write_text(json.dumps(rejected), encoding="utf-8")
            malformed_path.write_text("not-json", encoding="utf-8")

            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main([str(accepted_path)]), 0)
                self.assertEqual(main([str(rejected_path)]), 2)
                self.assertEqual(main([str(malformed_path)]), 3)


if __name__ == "__main__":
    unittest.main()
