import pytest

from aws_webapp_cost_optimizer.safety import assert_readonly_operation, is_mutating_operation, is_readonly_operation


def test_readonly_operation_prefixes_are_allowed():
    assert is_readonly_operation("describe_instances")
    assert is_readonly_operation("list-tags-for-resource")
    assert is_readonly_operation("get_caller_identity")


def test_mutating_operation_prefixes_are_blocked():
    assert is_mutating_operation("delete_nat_gateway")
    assert is_mutating_operation("modify_db_instance")
    assert is_mutating_operation("release_address")


def test_assert_readonly_rejects_mutations():
    with pytest.raises(ValueError):
        assert_readonly_operation("terminate_instances")
