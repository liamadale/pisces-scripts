"""Tests for fleet scanner — Jaccard similarity and JA4 clustering."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.profiler.fleet_scanner import (
    cluster_by_similarity,
    jaccard,
    scan_fleet,
)

# ---------------------------------------------------------------------------
# Jaccard similarity tests
# ---------------------------------------------------------------------------


class TestJaccard:
    def test_identical_sets(self) -> None:
        assert jaccard({"a", "b", "c"}, {"a", "b", "c"}) == 1.0

    def test_disjoint_sets(self) -> None:
        assert jaccard({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self) -> None:
        # intersection={a,b}, union={a,b,c,d} → 2/4 = 0.5
        assert jaccard({"a", "b", "c"}, {"a", "b", "d"}) == 0.5

    def test_empty_sets(self) -> None:
        assert jaccard(set(), set()) == 1.0

    def test_one_empty(self) -> None:
        assert jaccard({"a"}, set()) == 0.0

    def test_subset(self) -> None:
        # intersection={a}, union={a,b,c} → 1/3
        result = jaccard({"a"}, {"a", "b", "c"})
        assert abs(result - 1 / 3) < 0.01


# ---------------------------------------------------------------------------
# cluster_by_similarity tests
# ---------------------------------------------------------------------------


class TestClusterBySimilarity:
    def test_identical_fingerprints_cluster_together(self) -> None:
        ip_sets = {
            "10.0.0.1": {"ja4_a", "ja4_b"},
            "10.0.0.2": {"ja4_a", "ja4_b"},
            "10.0.0.3": {"ja4_a", "ja4_b"},
        }
        clusters = cluster_by_similarity(ip_sets, threshold=0.7)
        assert len(clusters) == 1
        assert len(clusters[0].ips) == 3

    def test_different_fingerprints_separate(self) -> None:
        ip_sets = {
            "10.0.0.1": {"ja4_a", "ja4_b"},
            "10.0.0.2": {"ja4_x", "ja4_y"},
        }
        clusters = cluster_by_similarity(ip_sets, threshold=0.7)
        assert len(clusters) == 2

    def test_partial_overlap_above_threshold(self) -> None:
        # {a,b,c} vs {a,b,d} → Jaccard = 2/4 = 0.5, below 0.7
        ip_sets = {
            "10.0.0.1": {"a", "b", "c"},
            "10.0.0.2": {"a", "b", "d"},
        }
        clusters = cluster_by_similarity(ip_sets, threshold=0.5)
        assert len(clusters) == 1

    def test_partial_overlap_below_threshold(self) -> None:
        ip_sets = {
            "10.0.0.1": {"a", "b", "c"},
            "10.0.0.2": {"a", "b", "d"},
        }
        clusters = cluster_by_similarity(ip_sets, threshold=0.7)
        assert len(clusters) == 2

    def test_sorted_by_size_descending(self) -> None:
        ip_sets = {
            "10.0.0.1": {"x"},
            "10.0.0.2": {"a", "b"},
            "10.0.0.3": {"a", "b"},
            "10.0.0.4": {"a", "b"},
        }
        clusters = cluster_by_similarity(ip_sets, threshold=0.7)
        assert len(clusters[0].ips) >= len(clusters[-1].ips)

    def test_empty_input(self) -> None:
        assert cluster_by_similarity({}) == []

    def test_single_ip(self) -> None:
        clusters = cluster_by_similarity({"10.0.0.1": {"a"}})
        assert len(clusters) == 1
        assert clusters[0].ips == ["10.0.0.1"]


# ---------------------------------------------------------------------------
# scan_fleet round-trip tests
# ---------------------------------------------------------------------------

MOCK_FLEET_RESPONSE = {
    "aggregations": {
        "per_ip": {
            "buckets": [
                {
                    "key": "10.0.0.1",
                    "doc_count": 500,
                    "ja4_set": {
                        "buckets": [
                            {"key": "t13d1516h2_abc", "doc_count": 300},
                            {"key": "t12d1809h2_def", "doc_count": 150},
                        ]
                    },
                },
                {
                    "key": "10.0.0.2",
                    "doc_count": 400,
                    "ja4_set": {
                        "buckets": [
                            {"key": "t13d1516h2_abc", "doc_count": 250},
                            {"key": "t12d1809h2_def", "doc_count": 100},
                        ]
                    },
                },
                {
                    "key": "10.0.0.3",
                    "doc_count": 100,
                    "ja4_set": {
                        "buckets": [
                            {"key": "t99z0000h0_xyz", "doc_count": 100},
                        ]
                    },
                },
                {
                    "key": "8.8.8.8",
                    "doc_count": 50,
                    "ja4_set": {
                        "buckets": [
                            {"key": "t13d1516h2_abc", "doc_count": 50},
                        ]
                    },
                },
            ]
        }
    }
}


class TestScanFleet:
    @patch("src.profiler.fleet_scanner.query_opensearch")
    def test_filters_public_ips(self, mock_qs: object) -> None:
        mock_qs.return_value = MOCK_FLEET_RESPONSE
        clusters = scan_fleet("hedgehog-test")
        all_ips = [ip for c in clusters for ip in c.ips]
        assert "8.8.8.8" not in all_ips

    @patch("src.profiler.fleet_scanner.query_opensearch")
    def test_clusters_similar_ips(self, mock_qs: object) -> None:
        mock_qs.return_value = MOCK_FLEET_RESPONSE
        clusters = scan_fleet("hedgehog-test")
        # 10.0.0.1 and 10.0.0.2 have identical JA4 sets → same cluster
        # 10.0.0.3 has different JA4 → separate cluster
        assert len(clusters) == 2
        big_cluster = clusters[0]
        assert len(big_cluster.ips) == 2
        assert "10.0.0.1" in big_cluster.ips
        assert "10.0.0.2" in big_cluster.ips

    @patch("src.profiler.fleet_scanner.query_opensearch")
    def test_null_response(self, mock_qs: object) -> None:
        mock_qs.return_value = None
        assert scan_fleet("hedgehog-test") == []

    @patch("src.profiler.fleet_scanner.query_opensearch")
    def test_query_has_sensor(self, mock_qs: object) -> None:
        mock_qs.return_value = {"aggregations": {"per_ip": {"buckets": []}}}
        scan_fleet("hedgehog-test", time_range="now-3d")
        body = mock_qs.call_args[0][0]
        must = body["query"]["bool"]["must"]
        sensors = [c["term"]["host.name"] for c in must if "term" in c and "host.name" in c["term"]]
        assert sensors == ["hedgehog-test"]
