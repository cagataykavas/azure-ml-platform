import copy
import unittest

from tools.validate_arm import evaluate_template


def valid_template():
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "name": "artifacts",
                "properties": {
                    "allowBlobPublicAccess": False,
                    "allowSharedKeyAccess": False,
                    "defaultToOAuthAuthentication": True,
                    "minimumTlsVersion": "TLS1_2",
                    "supportsHttpsTrafficOnly": True,
                },
            },
            {
                "type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                "name": "artifacts/default/models",
                "properties": {"publicAccess": "None"},
            },
            {
                "type": "Microsoft.App/containerApps",
                "name": "inference",
                "identity": {"type": "SystemAssigned"},
                "properties": {"template": {"scale": {"minReplicas": 0, "maxReplicas": 10}}},
            },
            {
                "type": "Microsoft.Authorization/roleAssignments",
                "name": "runtime-reader",
                "properties": {"principalType": "ServicePrincipal"},
            },
            {
                "type": "Microsoft.Insights/diagnosticSettings",
                "name": "diagnostics",
                "properties": {
                    "workspaceId": "workspace-resource-id",
                    "logs": [
                        {"category": "ContainerAppConsoleLogs", "enabled": True},
                        {"category": "ContainerAppSystemLogs", "enabled": True},
                    ],
                },
            },
        ],
    }


class PolicyTests(unittest.TestCase):
    def test_secure_template_passes(self):
        self.assertEqual(evaluate_template(valid_template()), [])

    def test_storage_regressions_are_reported_together(self):
        template = valid_template()
        storage = template["resources"][0]
        storage["properties"]["allowSharedKeyAccess"] = True
        storage["properties"]["minimumTlsVersion"] = "TLS1_0"
        container = template["resources"][1]
        container["properties"]["publicAccess"] = "Blob"

        rules = {item.rule for item in evaluate_template(template)}
        self.assertIn("storage.allowSharedKeyAccess", rules)
        self.assertIn("storage.minimumTlsVersion", rules)
        self.assertIn("storage.private_container", rules)

    def test_identity_scaling_and_observability_fail_closed(self):
        template = valid_template()
        template["resources"][2]["identity"] = {"type": "None"}
        template["resources"][2]["properties"]["template"]["scale"] = {
            "minReplicas": 12,
            "maxReplicas": 5,
        }
        template["resources"][-1]["properties"]["logs"][1]["enabled"] = False

        rules = {item.rule for item in evaluate_template(template)}
        self.assertEqual(
            rules,
            {
                "app.managed_identity",
                "app.scale_order",
                "observability.diagnostics",
            },
        )

    def test_missing_critical_resources_fail(self):
        template = copy.deepcopy(valid_template())
        template["resources"] = []
        rules = {item.rule for item in evaluate_template(template)}
        self.assertIn("resource.cardinality", rules)
        self.assertIn("iam.runtime_role", rules)
        self.assertIn("observability.diagnostics", rules)

    def test_rejects_source_or_arbitrary_json(self):
        self.assertEqual(evaluate_template({})[0].rule, "template.shape")


if __name__ == "__main__":
    unittest.main()
