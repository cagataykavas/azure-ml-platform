from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.audit_private_storage import (
    MAX_TEMPLATE_BYTES,
    MalformedTemplate,
    audit_template,
    load_template,
    main,
)


def valid_template() -> dict:
    storage_id = "[resourceId('Microsoft.Storage/storageAccounts', 'artifacts')]"
    vnet_id = "[resourceId('Microsoft.Network/virtualNetworks', 'ml-platform-vnet')]"
    zone_id = "[resourceId('Microsoft.Network/privateDnsZones', variables('blobZone'))]"
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "variables": {"blobZone": "privatelink.blob.core.windows.net"},
        "resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "name": "artifacts",
                "properties": {
                    "allowBlobPublicAccess": False,
                    "allowSharedKeyAccess": False,
                    "defaultToOAuthAuthentication": True,
                    "networkAcls": {"bypass": "None", "defaultAction": "Deny"},
                    "publicNetworkAccess": "Disabled",
                },
            },
            {
                "type": "Microsoft.Network/virtualNetworks/subnets",
                "name": "ml-platform-vnet/container-apps",
                "properties": {"addressPrefix": "10.42.0.0/23"},
            },
            {
                "type": "Microsoft.Network/virtualNetworks/subnets",
                "name": "ml-platform-vnet/private-endpoints",
                "properties": {
                    "addressPrefix": "10.42.2.0/24",
                    "privateEndpointNetworkPolicies": "Disabled",
                },
            },
            {
                "type": "Microsoft.App/managedEnvironments",
                "name": "environment",
                "properties": {
                    "vnetConfiguration": {
                        "infrastructureSubnetId": "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'ml-platform-vnet', 'container-apps')]"
                    }
                },
            },
            {
                "type": "Microsoft.Network/privateEndpoints",
                "name": "blob-endpoint",
                "properties": {
                    "subnet": {
                        "id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'ml-platform-vnet', 'private-endpoints')]"
                    },
                    "privateLinkServiceConnections": [
                        {
                            "name": "blob",
                            "properties": {
                                "groupIds": ["blob"],
                                "privateLinkServiceId": storage_id,
                            },
                        }
                    ],
                },
            },
            {
                "type": "Microsoft.Network/privateDnsZones",
                "name": "[variables('blobZone')]",
                "properties": {},
            },
            {
                "type": "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
                "name": "blob/link",
                "properties": {
                    "registrationEnabled": False,
                    "virtualNetwork": {"id": vnet_id},
                },
            },
            {
                "type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
                "name": "blob-endpoint/default",
                "properties": {
                    "privateDnsZoneConfigs": [
                        {"name": "blob", "properties": {"privateDnsZoneId": zone_id}}
                    ]
                },
            },
            {
                "type": "Microsoft.Network/virtualNetworks",
                "name": "ml-platform-vnet",
                "properties": {"addressSpace": {"addressPrefixes": ["10.42.0.0/16"]}},
            },
        ],
    }


class AuditTests(unittest.TestCase):
    def test_accepts_complete_private_storage_boundary(self) -> None:
        report = audit_template(valid_template())
        self.assertTrue(report["accepted"])
        self.assertEqual([], report["reason_codes"])
        self.assertEqual(64, len(report["evidence_sha256"]))

    def test_report_is_deterministic(self) -> None:
        self.assertEqual(audit_template(valid_template()), audit_template(valid_template()))

    def test_rejects_public_storage_and_firewall_bypass(self) -> None:
        template = valid_template()
        storage = template["resources"][0]
        storage["properties"]["publicNetworkAccess"] = "Enabled"
        storage["properties"]["networkAcls"] = {
            "bypass": "AzureServices",
            "defaultAction": "Allow",
        }
        report = audit_template(template)
        self.assertFalse(report["accepted"])
        self.assertEqual(
            [
                "STORAGE_FIREWALL_BYPASS_PRESENT",
                "STORAGE_FIREWALL_DEFAULT_ALLOW",
                "STORAGE_PUBLIC_NETWORK_ENABLED",
            ],
            report["reason_codes"],
        )

    def test_rejects_shared_key_or_anonymous_blob_access(self) -> None:
        template = valid_template()
        storage = template["resources"][0]["properties"]
        storage["allowBlobPublicAccess"] = True
        storage["allowSharedKeyAccess"] = True
        report = audit_template(template)
        self.assertIn("ANONYMOUS_BLOB_ACCESS_ALLOWED", report["reason_codes"])
        self.assertIn("STORAGE_SHARED_KEY_ALLOWED", report["reason_codes"])

    def test_rejects_wrong_private_link_group_and_target(self) -> None:
        template = valid_template()
        connection = template["resources"][4]["properties"]["privateLinkServiceConnections"][0][
            "properties"
        ]
        connection["groupIds"] = ["file"]
        connection["privateLinkServiceId"] = "[resourceId('Microsoft.KeyVault/vaults', 'x')]"
        report = audit_template(template)
        self.assertIn("PRIVATE_LINK_GROUP_NOT_BLOB", report["reason_codes"])
        self.assertIn("PRIVATE_LINK_TARGET_NOT_STORAGE", report["reason_codes"])

    def test_rejects_endpoint_on_workload_subnet(self) -> None:
        template = valid_template()
        template["resources"][4]["properties"]["subnet"]["id"] = "container-apps"
        self.assertIn("PRIVATE_ENDPOINT_SUBNET_NOT_BOUND", audit_template(template)["reason_codes"])

    def test_rejects_missing_container_apps_vnet_integration(self) -> None:
        template = valid_template()
        template["resources"][3]["properties"] = {}
        self.assertIn(
            "CONTAINER_APPS_VNET_INTEGRATION_MISSING", audit_template(template)["reason_codes"]
        )

    def test_rejects_enabled_endpoint_network_policies(self) -> None:
        template = valid_template()
        template["resources"][2]["properties"]["privateEndpointNetworkPolicies"] = "Enabled"
        self.assertIn(
            "PRIVATE_ENDPOINT_NETWORK_POLICIES_ENABLED", audit_template(template)["reason_codes"]
        )

    def test_rejects_wrong_private_dns_zone(self) -> None:
        template = valid_template()
        template["variables"]["blobZone"] = "blob.core.windows.net"
        self.assertIn("BLOB_PRIVATE_DNS_ZONE_INVALID", audit_template(template)["reason_codes"])

    def test_rejects_unbound_dns_zone_group(self) -> None:
        template = valid_template()
        configs = template["resources"][7]["properties"]["privateDnsZoneConfigs"]
        configs[0]["properties"]["privateDnsZoneId"] = "not-a-zone"
        self.assertIn(
            "PRIVATE_ENDPOINT_DNS_ZONE_NOT_BOUND", audit_template(template)["reason_codes"]
        )

    def test_rejects_dns_auto_registration(self) -> None:
        template = valid_template()
        template["resources"][6]["properties"]["registrationEnabled"] = True
        self.assertIn(
            "PRIVATE_DNS_AUTO_REGISTRATION_ENABLED", audit_template(template)["reason_codes"]
        )

    def test_rejects_missing_or_ambiguous_resources(self) -> None:
        template = valid_template()
        template["resources"] = [
            resource
            for resource in template["resources"]
            if resource["type"] != "Microsoft.Network/privateEndpoints"
        ]
        template["resources"].append(copy.deepcopy(template["resources"][0]))
        reasons = audit_template(template)["reason_codes"]
        self.assertIn("BLOB_PRIVATE_ENDPOINT_MISSING", reasons)
        self.assertIn("STORAGE_ACCOUNT_MISSING_AMBIGUOUS", reasons)

    def test_rejects_non_resource_objects_and_budget_breach(self) -> None:
        with self.assertRaisesRegex(MalformedTemplate, "every resource"):
            audit_template({"resources": ["bad"]})
        with self.assertRaisesRegex(MalformedTemplate, "resource count"):
            audit_template(
                {"resources": [{"type": f"Example.Provider/type{i}"} for i in range(257)]}
            )
        template = valid_template()
        template["resources"][4]["properties"] = "invalid"
        with self.assertRaisesRegex(MalformedTemplate, "private endpoint properties"):
            audit_template(template)


class LoadingAndCliTests(unittest.TestCase):
    def test_loader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text('{"resources":[],"resources":[]}', encoding="utf-8")
            with self.assertRaisesRegex(MalformedTemplate, "duplicate"):
                load_template(path)

    def test_loader_rejects_oversized_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_bytes(b" " * (MAX_TEMPLATE_BYTES + 1))
            with self.assertRaisesRegex(MalformedTemplate, "byte budget"):
                load_template(path)

    def test_cli_exit_codes_distinguish_policy_and_malformed_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            accepted = Path(directory) / "accepted.json"
            rejected = Path(directory) / "rejected.json"
            malformed = Path(directory) / "malformed.json"
            accepted.write_text(json.dumps(valid_template()), encoding="utf-8")
            rejected_template = valid_template()
            rejected_template["resources"][0]["properties"]["publicNetworkAccess"] = "Enabled"
            rejected.write_text(json.dumps(rejected_template), encoding="utf-8")
            malformed.write_text("{", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([str(accepted)]))
                self.assertEqual(2, main([str(rejected)]))
                self.assertEqual(3, main([str(malformed)]))


if __name__ == "__main__":
    unittest.main()
