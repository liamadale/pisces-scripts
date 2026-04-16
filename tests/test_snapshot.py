"""Tests for profile snapshot save/load/diff."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.profiler.device_profiler import DeviceProfile
from src.profiler.snapshot import diff_profiles, load_snapshot, save_snapshot


def _profile(**kwargs: object) -> DeviceProfile:
    defaults: dict = {"ip": "10.0.0.1", "sensor": "hedgehog-test", "time_range": "now-7d"}
    defaults.update(kwargs)
    return DeviceProfile(**defaults)


class TestSaveLoadSnapshot:
    def test_round_trip(self, tmp_path: object, monkeypatch: object) -> None:
        monkeypatch.setattr("src.profiler.snapshot._PROFILES_DIR", tmp_path)
        profile = _profile(role="workstation", os_family="windows")
        path = save_snapshot(profile)
        assert path.exists()
        loaded = load_snapshot("10.0.0.1", "hedgehog-test")
        assert loaded is not None
        assert loaded["role"] == "workstation"
        assert loaded["os_family"] == "windows"

    def test_load_missing(self, tmp_path: object, monkeypatch: object) -> None:
        monkeypatch.setattr("src.profiler.snapshot._PROFILES_DIR", tmp_path)
        assert load_snapshot("10.0.0.99", "hedgehog-test") is None


class TestDiffProfiles:
    def test_no_changes(self) -> None:
        profile = _profile(role="workstation", os_family="windows")
        baseline = {"role": "workstation", "os_family": "windows"}
        assert diff_profiles(profile, baseline) == []

    def test_role_change(self) -> None:
        profile = _profile(role="file_server")
        baseline = {"role": "workstation"}
        changes = diff_profiles(profile, baseline)
        roles = [c for c in changes if c["category"] == "role"]
        assert len(roles) == 1
        assert "workstation" in roles[0]["detail"]
        assert "file_server" in roles[0]["detail"]

    def test_new_ja4(self) -> None:
        profile = _profile(
            ja4_fingerprints=[
                {"hash": "aaa", "count": 10},
                {"hash": "bbb", "count": 5},
            ],
        )
        baseline = {"ja4_fingerprints": [{"hash": "aaa", "count": 10}]}
        changes = diff_profiles(profile, baseline)
        added = [
            c for c in changes if c["category"] == "ja4_fingerprints" and c["change"] == "added"
        ]
        assert len(added) == 1
        assert added[0]["detail"] == "bbb"

    def test_removed_ja4(self) -> None:
        profile = _profile(ja4_fingerprints=[])
        baseline = {"ja4_fingerprints": [{"hash": "old", "count": 10}]}
        changes = diff_profiles(profile, baseline)
        removed = [c for c in changes if c["change"] == "removed"]
        assert any(c["detail"] == "old" for c in removed)

    def test_new_software(self) -> None:
        profile = _profile(software=["NinjaRMM", "Defender"])
        baseline = {"software": ["Defender"]}
        changes = diff_profiles(profile, baseline)
        added = [c for c in changes if c["category"] == "software" and c["change"] == "added"]
        assert len(added) == 1
        assert added[0]["detail"] == "NinjaRMM"

    def test_new_inbound_service(self) -> None:
        profile = _profile(
            inbound_services=[
                {"port": 22, "app_proto": "ssh", "count": 10},
                {"port": 445, "app_proto": "smb", "count": 50},
            ],
        )
        baseline = {"inbound_services": [{"port": 445, "app_proto": "smb", "count": 50}]}
        changes = diff_profiles(profile, baseline)
        added = [c for c in changes if c["category"] == "inbound_services"]
        assert any("22" in c["detail"] for c in added)

    def test_new_user(self) -> None:
        profile = _profile(users=["admin@CORP", "jsmith"])
        baseline = {"users": ["admin@CORP"]}
        changes = diff_profiles(profile, baseline)
        added = [c for c in changes if c["category"] == "users" and c["change"] == "added"]
        assert len(added) == 1
        assert added[0]["detail"] == "jsmith"

    def test_os_change(self) -> None:
        profile = _profile(os_family="linux")
        baseline = {"os_family": "windows"}
        changes = diff_profiles(profile, baseline)
        os_changes = [c for c in changes if c["category"] == "os_family"]
        assert len(os_changes) == 1
        assert "windows" in os_changes[0]["detail"]
        assert "linux" in os_changes[0]["detail"]
