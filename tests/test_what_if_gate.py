from __future__ import annotations

import json
import math

import pytest
from tools.what_if_gate import (
    WhatIfAuditError,
    WhatIfPolicy,
    audit_what_if,
    main,
)


def _document(*changes: dict[str, object]) -> dict[str, object]:
    return {"status": "Succeeded", "properties": {"changes": list(changes)}}


def _change(
    resource_id: str,
    change_type: str,
    *,
    delta: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "resourceId": resource_id,
        "changeType": change_type,
    }
    if delta is not None:
        result["delta"] = delta
    return result


def _property(
    path: str,
    change_type: str,
    *,
    before: object = None,
    after: object = None,
) -> dict[str, object]:
    return {
        "path": path,
        "propertyChangeType": change_type,
        "before": before,
        "after": after,
    }


def test_accepts_bounded_create_and_non_destructive_modify():
    report = audit_what_if(
        _document(
            _change("/subscriptions/s/resourceGroups/r/providers/Microsoft.X/new", "Create"),
            _change(
                "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/existing",
                "Modify",
                delta=[_property("tags.release", "Create", after="v2")],
            ),
        )
    )

    assert report.accepted
    assert report.created_resources == 1
    assert report.modified_resources == 1
    assert report.violations == ()


def test_rejects_resource_deletion():
    report = audit_what_if(
        _document(_change("/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x", "Delete"))
    )

    assert not report.accepted
    assert report.deleted_resources == 1
    assert report.violations[0].rule_id == "RESOURCE_DELETE"


@pytest.mark.parametrize(
    ("change_type", "rule_id"),
    [
        ("Ignore", "INCOMPLETE_CHANGE_ANALYSIS"),
        ("Deploy", "RESOURCE_ID_ONLY_RESULT"),
    ],
)
def test_rejects_incomplete_change_evidence(change_type: str, rule_id: str):
    report = audit_what_if(
        _document(
            _change(
                "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x",
                change_type,
            )
        )
    )

    assert [violation.rule_id for violation in report.violations] == [rule_id]


def test_rejects_potential_changes_and_diagnostics():
    document = _document()
    document["properties"]["potentialChanges"] = [{"changeType": "Modify"}]
    document["properties"]["diagnostics"] = [{"level": "Warning"}]

    report = audit_what_if(document)

    assert [violation.rule_id for violation in report.violations] == [
        "POTENTIAL_CHANGES_PRESENT",
        "WHAT_IF_DIAGNOSTICS_PRESENT",
    ]


def test_property_delete_budget_is_fail_closed():
    resource_id = "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x"
    report = audit_what_if(
        _document(
            _change(
                resource_id,
                "Modify",
                delta=[_property("properties.retentionPolicy", "Delete", before={})],
            )
        )
    )

    assert report.property_deletions == (f"{resource_id}::properties.retentionPolicy",)
    assert report.violations[0].rule_id == "PROPERTY_DELETE_BUDGET_EXCEEDED"


def test_known_noisy_property_delete_can_be_ignored_explicitly():
    report = audit_what_if(
        _document(
            _change(
                "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x",
                "Modify",
                delta=[_property("properties.serviceDefault", "Delete", before=True)],
            )
        ),
        policy=WhatIfPolicy(ignored_delete_path_prefixes=("properties.serviceDefault",)),
    )

    assert report.accepted
    assert report.property_deletions == ()


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        ("properties.template.scale.minReplicas", "SCALE_CAPACITY_DECREASE"),
        ("properties.template.scale.maxReplicas", "SCALE_CAPACITY_DECREASE"),
        ("properties.logs.retentionPolicy.days", "RETENTION_DECREASE"),
    ],
)
def test_rejects_capacity_or_retention_reduction(path: str, rule_id: str):
    report = audit_what_if(
        _document(
            _change(
                "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x",
                "Modify",
                delta=[_property(path, "Modify", before=10, after=2)],
            )
        )
    )

    assert rule_id in {violation.rule_id for violation in report.violations}


def test_capacity_increase_is_allowed():
    report = audit_what_if(
        _document(
            _change(
                "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x",
                "Modify",
                delta=[
                    _property(
                        "properties.template.scale.minReplicas",
                        "Modify",
                        before=1,
                        after=2,
                    )
                ],
            )
        )
    )

    assert report.accepted


def test_change_blast_radius_is_bounded():
    changes = [
        _change(f"/subscriptions/s/resourceGroups/r/providers/Microsoft.X/{index}", "Create")
        for index in range(3)
    ]

    report = audit_what_if(_document(*changes), policy=WhatIfPolicy(max_changed_resources=2))

    assert report.violations[0].rule_id == "CHANGE_BLAST_RADIUS_EXCEEDED"


@pytest.mark.parametrize(
    ("document", "code"),
    [
        ({"status": "Failed", "properties": {"changes": []}}, "WHAT_IF_NOT_SUCCEEDED"),
        ({"status": "Succeeded", "properties": {}}, "INVALID_CHANGES"),
        (
            _document(
                _change("/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x", "Unknown")
            ),
            "INVALID_CHANGE_TYPE",
        ),
        (
            _document(
                _change(
                    "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x",
                    "Modify",
                    delta=[
                        _property(
                            "properties.template.scale.minReplicas",
                            "Modify",
                            before=2,
                            after=math.nan,
                        )
                    ],
                )
            ),
            "INVALID_NUMERIC_DELTA",
        ),
    ],
)
def test_malformed_evidence_fails_closed(document: dict[str, object], code: str):
    with pytest.raises(WhatIfAuditError) as error:
        audit_what_if(document)

    assert error.value.code == code


def test_cli_distinguishes_accept_reject_and_invalid(tmp_path, capsys):
    accepted = tmp_path / "accepted.json"
    rejected = tmp_path / "rejected.json"
    malformed = tmp_path / "malformed.json"
    accepted.write_text(json.dumps(_document()), encoding="utf-8")
    rejected.write_text(
        json.dumps(
            _document(
                _change(
                    "/subscriptions/s/resourceGroups/r/providers/Microsoft.X/x",
                    "Delete",
                )
            )
        ),
        encoding="utf-8",
    )
    malformed.write_text("{", encoding="utf-8")

    assert main([str(accepted)]) == 0
    assert main([str(rejected)]) == 2
    assert main([str(malformed)]) == 3
    assert '"accepted": false' in capsys.readouterr().out
