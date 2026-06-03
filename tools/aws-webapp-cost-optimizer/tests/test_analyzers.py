from aws_webapp_cost_optimizer.analyzers import analyze_inventory
from aws_webapp_cost_optimizer.aws_collectors import RESOURCE_TYPES, sample_inventory


def test_sample_inventory_covers_required_resource_types():
    inventory = sample_inventory(regions=["us-east-1", "eu-west-1"])
    seen = {item["type"] for item in inventory["resources"]}
    assert set(RESOURCE_TYPES).issubset(seen)


def test_analyzer_emits_required_safety_categories():
    analysis = analyze_inventory(sample_inventory(regions=["us-east-1", "eu-west-1"]))
    categories = {finding["category"] for finding in analysis["findings"]}
    assert "unused deletion candidate" in categories
    assert "used but oversized" in categories
    assert "DR posture decision required" in categories
    assert "blocked by AWS valid-modification API" in categories
    assert "manual approval required" in categories


def test_rds_orderable_without_valid_modification_is_blocked():
    inventory = {
        "app_name": "test",
        "regions": ["us-east-1"],
        "resources": [
            {
                "id": "test-db",
                "region": "us-east-1",
                "service": "rds",
                "type": "rds_instance",
                "candidate_smaller_classes": ["db.t4g.small"],
                "valid_modification_classes": [],
            }
        ],
    }
    analysis = analyze_inventory(inventory)
    assert analysis["findings"][0]["category"] == "blocked by AWS valid-modification API"
