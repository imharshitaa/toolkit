"""
Tests for toolkit.security — the target-authorization guardrail used by every
active scan/simulate module.
"""
import pytest

from toolkit.security import UnauthorizedTargetError, require_authorized_target


class TestPrivateTargetsAllowed:
    """Private/loopback targets should always pass without allow_unsafe."""

    @pytest.mark.parametrize("target", [
        "127.0.0.1",
        "localhost",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "192.168.1.1:8080",
        "http://192.168.1.1:8000",
        "https://localhost:8443/path",
        "10.0.0.0/24",
    ])
    def test_private_target_passes(self, target):
        require_authorized_target(target)  # should not raise


class TestPublicTargetsBlocked:
    """Public targets must be rejected unless allow_unsafe is explicitly set."""

    def test_public_ip_rejected_by_default(self):
        with pytest.raises(UnauthorizedTargetError):
            require_authorized_target("8.8.8.8")

    def test_public_url_rejected_by_default(self):
        with pytest.raises(UnauthorizedTargetError):
            require_authorized_target("https://8.8.8.8/path")

    def test_public_ip_allowed_with_override(self):
        require_authorized_target("8.8.8.8", allow_unsafe=True)  # should not raise

    def test_override_logs_a_warning(self, caplog):
        import logging
        caplog.set_level(logging.WARNING)
        require_authorized_target("8.8.8.8", allow_unsafe=True)
        assert any("8.8.8.8" in record.message for record in caplog.records)


class TestMalformedTargets:
    def test_empty_target_raises(self):
        with pytest.raises(UnauthorizedTargetError):
            require_authorized_target("")
