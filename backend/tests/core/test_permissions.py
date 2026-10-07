"""Tests for app.core.permissions — pure, no DB needed."""

from app.core.permissions import PERMISSIONS, ROLE_PERMISSIONS, is_authorized


def test_admin_has_every_permission() -> None:
    for name, _description in PERMISSIONS:
        assert is_authorized("ADMIN", name), f"ADMIN should have {name}"


def test_viewer_cannot_use_ai_copilot() -> None:
    assert not is_authorized("VIEWER", "ai_copilot:use")


def test_soc_analyst_can_use_ai_copilot_but_not_manage_rules() -> None:
    assert is_authorized("SOC_ANALYST", "ai_copilot:use")
    assert not is_authorized("SOC_ANALYST", "detection_rules:write")


def test_security_manager_can_manage_rules() -> None:
    assert is_authorized("SECURITY_MANAGER", "detection_rules:write")


def test_unknown_role_is_never_authorized() -> None:
    assert not is_authorized("NOT_A_REAL_ROLE", "incidents:read")


def test_every_role_in_role_permissions_has_at_least_read_access() -> None:
    for role, perms in ROLE_PERMISSIONS.items():
        assert "incidents:read" in perms, f"{role} should be able to at least read incidents"


if __name__ == "__main__":
    test_admin_has_every_permission()
    test_viewer_cannot_use_ai_copilot()
    test_soc_analyst_can_use_ai_copilot_but_not_manage_rules()
    test_security_manager_can_manage_rules()
    test_unknown_role_is_never_authorized()
    test_every_role_in_role_permissions_has_at_least_read_access()
    print("All permissions tests passed.")
