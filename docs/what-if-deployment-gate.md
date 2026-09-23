# Azure What-If deployment gate

Bicep compilation proves that a template is syntactically valid. It does not prove
that applying the template to an existing environment is operationally safe.
`tools/what_if_gate.py` evaluates the JSON returned by an authenticated Azure
Resource Manager What-If operation before deployment.

```bash
az deployment group what-if \
  --resource-group "$RESOURCE_GROUP" \
  --template-file infra/main.bicep \
  --result-format FullResourcePayloads \
  --no-pretty-print \
  --output json > what-if.json

python tools/what_if_gate.py what-if.json --output what-if-audit.json
```

Exit code `0` accepts the plan, `2` denotes a policy rejection, and `3` denotes
malformed or incomplete evidence.

## Enforced contract

The gate:

- requires a successful What-If result with a concrete `properties.changes` list;
- rejects resource deletions;
- rejects `Ignore`, `Deploy`, unresolved potential changes and diagnostics;
- requires property-level delta evidence for modified resources;
- bounds total changed resources and modified resources;
- budgets property deletions, with explicit prefixes for calibrated Azure noise;
- blocks Container Apps replica-capacity reductions; and
- blocks retention-period reductions.

Every result is deterministic and JSON-ready. Rejections contain stable rule IDs,
resource IDs and property paths. Invalid schemas, duplicate resources, unknown
change types, and non-finite numeric deltas fail closed.

Azure documents seven resource change types and notes that `Ignore` can appear
when nested-template expansion limits are reached. `Deploy` is returned for
`ResourceIdOnly` results when Azure lacks property-level certainty. This gate
therefore requires `FullResourcePayloads` evidence rather than treating incomplete
analysis as approval.

- [Azure ARM deployment What-If](https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-what-if)
- [What-If REST result schema](https://learn.microsoft.com/rest/api/resources/deployments/what-if-at-subscription-scope)

## Trust boundary and limitations

The repository's public CI cannot run an authenticated What-If against a real
subscription. It validates the policy engine with representative official-schema
fixtures; a deployment pipeline must generate the input using least-privilege
Azure credentials in its target environment.

Azure warns that service-default properties can appear as noisy deletions. Such
paths must be observed and explicitly allowlisted; broad wildcard suppression is
intentionally absent. This gate does not replace Azure Policy, provider semantic
validation, resource locks, approval workflows, or post-deployment health checks.

The next step is to retain the What-If input and audit output as signed deployment
evidence, then require an approval identity for narrowly scoped policy exceptions.
