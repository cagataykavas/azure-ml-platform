"""Fail-closed audit for the compiled Azure private-storage network contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
MAX_RESOURCES = 256


class MalformedTemplate(ValueError):
    """The ARM artifact cannot be evaluated safely."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MalformedTemplate("duplicate JSON object key")
        result[key] = value
    return result


def load_template(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise MalformedTemplate("template is not readable") from exc
    if size > MAX_TEMPLATE_BYTES:
        raise MalformedTemplate("template exceeds byte budget")

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MalformedTemplate("template is not valid UTF-8 JSON") from exc

    if not isinstance(document, dict):
        raise MalformedTemplate("template root must be an object")
    return document


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _contains(value: Any, fragment: str) -> bool:
    return fragment.lower() in _canonical(value).lower()


def _index_resources(template: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    resources = template.get("resources")
    if not isinstance(resources, list):
        raise MalformedTemplate("resources must be an array")
    if len(resources) > MAX_RESOURCES:
        raise MalformedTemplate("resource count exceeds budget")

    indexed: dict[str, list[dict[str, Any]]] = {}
    for resource in resources:
        if not isinstance(resource, dict):
            raise MalformedTemplate("every resource must be an object")
        resource_type = resource.get("type")
        if not isinstance(resource_type, str) or not resource_type:
            raise MalformedTemplate("every resource must have a type")
        indexed.setdefault(resource_type.lower(), []).append(resource)
    return indexed


def _one(
    indexed: dict[str, list[dict[str, Any]]],
    resource_type: str,
    missing_code: str,
    reasons: set[str],
) -> dict[str, Any] | None:
    matches = indexed.get(resource_type.lower(), [])
    if len(matches) != 1:
        reasons.add(missing_code if not matches else f"{missing_code}_AMBIGUOUS")
        return None
    return matches[0]


def _properties(resource: dict[str, Any], resource_label: str) -> dict[str, Any]:
    properties = resource.get("properties")
    if not isinstance(properties, dict):
        raise MalformedTemplate(f"{resource_label} properties must be an object")
    return properties


def audit_template(template: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic report without copying resource names or addresses."""

    indexed = _index_resources(template)
    reasons: set[str] = set()

    storage = _one(
        indexed,
        "Microsoft.Storage/storageAccounts",
        "STORAGE_ACCOUNT_MISSING",
        reasons,
    )
    _one(
        indexed,
        "Microsoft.Network/virtualNetworks",
        "VIRTUAL_NETWORK_MISSING",
        reasons,
    )
    environment = _one(
        indexed,
        "Microsoft.App/managedEnvironments",
        "CONTAINER_APPS_ENVIRONMENT_MISSING",
        reasons,
    )
    endpoint = _one(
        indexed,
        "Microsoft.Network/privateEndpoints",
        "BLOB_PRIVATE_ENDPOINT_MISSING",
        reasons,
    )
    dns_zone = _one(
        indexed,
        "Microsoft.Network/privateDnsZones",
        "BLOB_PRIVATE_DNS_ZONE_MISSING",
        reasons,
    )
    dns_link = _one(
        indexed,
        "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
        "PRIVATE_DNS_VNET_LINK_MISSING",
        reasons,
    )
    dns_group = _one(
        indexed,
        "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
        "PRIVATE_ENDPOINT_DNS_GROUP_MISSING",
        reasons,
    )

    subnets = indexed.get("microsoft.network/virtualnetworks/subnets", [])
    app_subnets = [
        resource for resource in subnets if _contains(resource.get("name"), "container-apps")
    ]
    endpoint_subnets = [
        resource for resource in subnets if _contains(resource.get("name"), "private-endpoints")
    ]
    if len(app_subnets) != 1:
        reasons.add("CONTAINER_APPS_SUBNET_MISSING")
    if len(endpoint_subnets) != 1:
        reasons.add("PRIVATE_ENDPOINT_SUBNET_MISSING")
    elif (
        _properties(endpoint_subnets[0], "private endpoint subnet").get(
            "privateEndpointNetworkPolicies"
        )
        != "Disabled"
    ):
        reasons.add("PRIVATE_ENDPOINT_NETWORK_POLICIES_ENABLED")

    if storage is not None:
        properties = _properties(storage, "storage")
        if properties.get("publicNetworkAccess") != "Disabled":
            reasons.add("STORAGE_PUBLIC_NETWORK_ENABLED")
        network_acls = properties.get("networkAcls")
        if not isinstance(network_acls, dict):
            reasons.add("STORAGE_FIREWALL_MISSING")
        else:
            if network_acls.get("defaultAction") != "Deny":
                reasons.add("STORAGE_FIREWALL_DEFAULT_ALLOW")
            if network_acls.get("bypass") != "None":
                reasons.add("STORAGE_FIREWALL_BYPASS_PRESENT")
        if properties.get("allowBlobPublicAccess") is not False:
            reasons.add("ANONYMOUS_BLOB_ACCESS_ALLOWED")
        if properties.get("allowSharedKeyAccess") is not False:
            reasons.add("STORAGE_SHARED_KEY_ALLOWED")
        if properties.get("defaultToOAuthAuthentication") is not True:
            reasons.add("OAUTH_NOT_DEFAULT")

    if environment is not None:
        vnet_configuration = _properties(environment, "Container Apps environment").get(
            "vnetConfiguration"
        )
        if not isinstance(vnet_configuration, dict) or not _contains(
            vnet_configuration.get("infrastructureSubnetId"), "container-apps"
        ):
            reasons.add("CONTAINER_APPS_VNET_INTEGRATION_MISSING")

    if endpoint is not None:
        properties = _properties(endpoint, "private endpoint")
        if not _contains(properties.get("subnet", {}).get("id"), "private-endpoints"):
            reasons.add("PRIVATE_ENDPOINT_SUBNET_NOT_BOUND")
        connections = properties.get("privateLinkServiceConnections")
        if not isinstance(connections, list) or len(connections) != 1:
            reasons.add("BLOB_PRIVATE_LINK_CONNECTION_INVALID")
        else:
            connection_properties = connections[0].get("properties", {})
            if connection_properties.get("groupIds") != ["blob"]:
                reasons.add("PRIVATE_LINK_GROUP_NOT_BLOB")
            if not _contains(connection_properties.get("privateLinkServiceId"), "storageaccounts"):
                reasons.add("PRIVATE_LINK_TARGET_NOT_STORAGE")

    if dns_zone is not None:
        variables = template.get("variables", {})
        zone_contract = {"name": dns_zone.get("name"), "variables": variables}
        if not _contains(zone_contract, "privatelink.blob."):
            reasons.add("BLOB_PRIVATE_DNS_ZONE_INVALID")

    if dns_link is not None:
        properties = _properties(dns_link, "private DNS VNet link")
        if properties.get("registrationEnabled") is not False:
            reasons.add("PRIVATE_DNS_AUTO_REGISTRATION_ENABLED")
        if not _contains(properties.get("virtualNetwork", {}).get("id"), "virtualnetworks"):
            reasons.add("PRIVATE_DNS_VNET_NOT_BOUND")

    if dns_group is not None:
        configs = _properties(dns_group, "private endpoint DNS group").get("privateDnsZoneConfigs")
        if not isinstance(configs, list) or len(configs) != 1:
            reasons.add("PRIVATE_ENDPOINT_DNS_CONFIG_INVALID")
        elif not _contains(
            configs[0].get("properties", {}).get("privateDnsZoneId"), "privatednszones"
        ):
            reasons.add("PRIVATE_ENDPOINT_DNS_ZONE_NOT_BOUND")

    return {
        "accepted": not reasons,
        "evidence_sha256": hashlib.sha256(_canonical(template).encode("utf-8")).hexdigest(),
        "reason_codes": sorted(reasons),
        "resource_count": sum(len(resources) for resources in indexed.values()),
        "schema_version": 1,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path, help="Compiled ARM template JSON")
    arguments = parser.parse_args(argv)

    try:
        report = audit_template(load_template(arguments.template))
    except MalformedTemplate as exc:
        print(
            json.dumps(
                {"accepted": False, "error": "malformed_template", "message": str(exc)},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 3

    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["accepted"] else 2


if __name__ == "__main__":
    sys.exit(main())
