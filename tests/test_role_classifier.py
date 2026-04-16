"""Tests for role classification, OS detection, and software signature matching."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.profiler.device_profiler import DeviceProfile
from src.profiler.role_classifier import classify_role, detect_os
from src.profiler.software_signatures import match_software


def _profile(**kwargs: object) -> DeviceProfile:
    """Build a DeviceProfile with defaults, overriding specified fields."""
    defaults: dict = {
        "ip": "10.0.0.1",
        "sensor": "hedgehog-test",
        "time_range": "now-7d",
    }
    defaults.update(kwargs)
    return DeviceProfile(**defaults)


# ---------------------------------------------------------------------------
# classify_role tests
# ---------------------------------------------------------------------------


class TestClassifyRole:
    def test_domain_controller(self) -> None:
        profile = _profile(
            inbound_services=[
                {"port": 53, "app_proto": "dns", "count": 669},
                {"port": 389, "app_proto": "ldap", "count": 222},
                {"port": 88, "app_proto": "krb", "count": 122},
                {"port": 445, "app_proto": "smb", "count": 83},
                {"port": 49666, "app_proto": "dce_rpc", "count": 127},
            ],
            dest_port_distribution={123: 10},
            dns_top_domains=[
                {"domain": "fe3.update.microsoft.com", "count": 5},
            ],
        )
        role, confidence = classify_role(profile)
        assert role == "domain_controller"
        assert confidence >= 0.60

    def test_workstation(self) -> None:
        profile = _profile(
            inbound_services=[],
            unique_dest_count=50,
            user_agents=["Mozilla/5.0 (Windows NT 10.0)"],
            dns_top_domains=[
                {"domain": "wpad.corp.local", "count": 2},
                {"domain": "fe3.update.microsoft.com", "count": 5},
            ],
            ja4_fingerprints=[
                {"hash": "a", "count": 1},
                {"hash": "b", "count": 1},
                {"hash": "c", "count": 1},
            ],
        )
        role, confidence = classify_role(profile)
        assert role == "workstation"
        assert confidence >= 0.60

    def test_linux_server(self) -> None:
        profile = _profile(
            ssh_inbound=True,
            ssh_server_versions=["SSH-2.0-OpenSSH_9.7"],
            inbound_services=[{"port": 22, "app_proto": "ssh", "count": 50}],
            dns_top_domains=[],
            user_agents=[],
        )
        role, confidence = classify_role(profile)
        assert role == "linux_server"
        assert confidence >= 0.60

    def test_unknown_empty_profile(self) -> None:
        profile = _profile()
        role, confidence = classify_role(profile)
        assert role == "unknown"
        assert confidence == 0.0

    def test_file_server(self) -> None:
        profile = _profile(
            inbound_services=[
                {"port": 445, "app_proto": "smb", "count": 200},
            ],
            smb_shares_hosted=["Data", "Backups"],
            unique_dest_count=5,
        )
        role, confidence = classify_role(profile)
        assert role == "file_server"
        assert confidence >= 0.60

    def test_print_server(self) -> None:
        profile = _profile(
            inbound_services=[
                {"port": 9100, "app_proto": "", "count": 30},
            ],
            unique_dest_count=3,
        )
        role, confidence = classify_role(profile)
        assert role == "print_server"
        assert confidence >= 0.40


# ---------------------------------------------------------------------------
# detect_os tests
# ---------------------------------------------------------------------------


class TestDetectOs:
    def test_windows_from_ua_os(self) -> None:
        profile = _profile(user_agent_os=["Windows 10"])
        assert detect_os(profile) == "windows"

    def test_macos_from_ua_os(self) -> None:
        profile = _profile(user_agent_os=["Mac OS X"])
        assert detect_os(profile) == "macos"

    def test_linux_from_dns(self) -> None:
        profile = _profile(
            dns_top_domains=[
                {"domain": "connectivity-check.ubuntu.com", "count": 5},
            ],
        )
        assert detect_os(profile) == "linux"

    def test_windows_from_dns(self) -> None:
        profile = _profile(
            dns_top_domains=[
                {"domain": "fe3.update.microsoft.com", "count": 5},
            ],
        )
        # *.update.microsoft.com doesn't match *.windowsupdate.com
        # but does match the _WINDOWS_DNS pattern
        assert detect_os(profile) == "windows"

    def test_linux_from_ssh_version(self) -> None:
        profile = _profile(
            ssh_server_versions=["SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"],
        )
        assert detect_os(profile) == "linux"

    def test_windows_from_putty(self) -> None:
        profile = _profile(
            ssh_client_versions=["SSH-2.0-PuTTY_Release_0.81"],
        )
        assert detect_os(profile) == "windows"

    def test_none_when_no_signals(self) -> None:
        profile = _profile()
        assert detect_os(profile) is None


# ---------------------------------------------------------------------------
# match_software tests
# ---------------------------------------------------------------------------


class TestMatchSoftware:
    def test_defender_from_dns(self) -> None:
        profile = _profile(
            dns_top_domains=[
                {"domain": "winatp-gw-usmv.microsoft.com", "count": 3},
            ],
        )
        result = match_software(profile)
        assert "Microsoft Defender for Endpoint" in result

    def test_ninjarmm_from_dns(self) -> None:
        profile = _profile(
            dns_top_domains=[
                {"domain": "app.ninjarmm.com", "count": 10},
            ],
        )
        result = match_software(profile)
        assert "NinjaRMM" in result

    def test_multiple_matches(self) -> None:
        profile = _profile(
            dns_top_domains=[
                {"domain": "app.ninjarmm.com", "count": 10},
                {"domain": "endpoint.ingress.rapid7.com", "count": 5},
                {"domain": "winatp-gw-usmv.microsoft.com", "count": 3},
            ],
        )
        result = match_software(profile)
        assert len(result) >= 3

    def test_no_matches(self) -> None:
        profile = _profile(
            dns_top_domains=[{"domain": "example.com", "count": 1}],
        )
        assert match_software(profile) == []

    def test_empty_profile(self) -> None:
        assert match_software(_profile()) == []

    def test_chrome_from_dns(self) -> None:
        profile = _profile(
            dns_top_domains=[
                {"domain": "update.googleapis.com", "count": 5},
            ],
        )
        result = match_software(profile)
        assert "Google Chrome" in result
