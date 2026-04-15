"""Offline enrichment layer — zero-API-cost signals for the classifier.

Provides:
    OfflineEnrichment   — structured enrichment hints passed to classify_rules()
    OfflineEnrichmentProvider — aggregates per-IP offline signals for a ticket

Lookup hierarchy (all zero or free cost):
    1. Free bulk blocklists  (Spamhaus DROP/EDROP, Feodo Tracker, ThreatFox,
                              ET compromised-ips) — downloaded and cached locally
    2. Shodan InternetDB     (free, unmetered REST endpoint, 30-day cache)
    3. Offline ASN/BGP table (pyasn, optional; gracefully degrades to None)
    4. Local reputation prior from existing malicious_ips / false_positive_ips
    5. Paid API results      (GreyNoise, AbuseIPDB — populated by --enrich pass)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests
import yaml

from src.utils.cache import dump_json, load_json

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal console helper — prints to stderr so it doesn't pollute stdout
# ---------------------------------------------------------------------------


def _print(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Project-root-relative default paths
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_BLOCKLIST_DIR = os.path.join(_DATA_DIR, "blocklists")
_CACHE_PATH = os.path.join(_DATA_DIR, "enrichment_cache.json")
_MAL_PATH = os.path.join(_DATA_DIR, "tickets", "enriched", "malicious_ips.json")
_FP_PATH = os.path.join(_DATA_DIR, "tickets", "enriched", "false_positive_ips.json")
_ASN_REP_PATH = os.path.join(_DATA_DIR, "asn_reputation.yaml")

# Blocklist refresh interval: 24 hours
_BLOCKLIST_REFRESH_SECONDS = 86_400

# Enrichment cache TTL: 30 days
_CACHE_TTL_DAYS = 30

# MaxMind GeoLite2 database paths (relative to data/ directory).
# Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
_MAXMIND_CITY_DB = os.path.join(_DATA_DIR, "GeoLite2-City.mmdb")
_MAXMIND_ASN_DB = os.path.join(_DATA_DIR, "GeoLite2-ASN.mmdb")

# ---------------------------------------------------------------------------
# Blocklist source definitions
# ---------------------------------------------------------------------------

# Each entry: (source_name, url, format)
# Formats: "cidr_txt" (one CIDR/IP per line), "feodo_json", "threatfox_json",
#          "ip_txt" (one IP per line)
_BLOCKLIST_SOURCES: list[tuple[str, str, str]] = [
    (
        "spamhaus_drop",
        "https://www.spamhaus.org/drop/drop.txt",
        "cidr_txt",
    ),
    (
        "spamhaus_edrop",
        "https://www.spamhaus.org/drop/edrop.txt",
        "cidr_txt",
    ),
    (
        "feodo",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "feodo_json",
    ),
    (
        "threatfox",
        "https://threatfox.abuse.ch/export/json/recent/",
        "threatfox_json",
    ),
    (
        "et_compromised",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "ip_txt",
    ),
]


# ---------------------------------------------------------------------------
# OfflineEnrichment dataclass
# ---------------------------------------------------------------------------


@dataclass
class OfflineEnrichment:
    """Structured offline enrichment hints for a single ticket.

    Aggregated across all IPs in the ticket.  All fields default to empty /
    None so callers can safely check truthiness.

    Attributes:
        blocklist_hits: Blocklist source names for any IP in the ticket.
            e.g. ``["spamhaus_drop", "feodo", "threatfox"]``
        asn_tier: Reputation tier of the ASN hosting the IP.
            One of ``"bulletproof"``, ``"transit"``, ``"cloud"``,
            ``"residential"`` or ``None`` if unknown.
        local_prior: Disposition inferred from previous analyst verdicts in
            the local registries.  One of ``"malicious"``, ``"false_positive"``,
            ``"conflicted"`` or ``None`` if no prior data.
        greynoise_classification: GreyNoise classification from paid API cache.
            One of ``"benign"``, ``"malicious"``, ``"not_found"`` or ``None``
            if no cached result.
        abuseipdb_confidence: AbuseIPDB abuse confidence score 0–100 from paid
            API cache, or ``None`` if no cached result.
        ip_role: Role the primary IP played in the ticket — ``"source"``
            (attacker/originator), ``"dest"`` (victim/target), or ``None``
            when the role is unresolvable.  Supplied by the caller;
            influences reputation scoring in the classifier.
        country: ISO 3166-1 alpha-2 country code for the primary IP, sourced
            from the AbuseIPDB paid API cache.  ``None`` when no cached result
            is available.
    """

    blocklist_hits: list[str] = field(default_factory=list)
    asn_tier: str | None = None
    local_prior: str | None = None
    greynoise_classification: str | None = None
    abuseipdb_confidence: int | None = None
    ip_role: str | None = None
    country: str | None = None


# ---------------------------------------------------------------------------
# OfflineEnrichmentProvider
# ---------------------------------------------------------------------------


class OfflineEnrichmentProvider:
    """Aggregates offline enrichment signals for tickets before classification.

    Instantiate once per threat-model run.  Blocklist data and ASN tables are
    loaded at construction time so ``enrich_ticket()`` is a pure in-memory
    lookup on the hot path.

    Args:
        data_dir: Override for the ``data/`` directory.  Defaults to the
            project-root-relative ``data/`` directory.
    """

    def __init__(self, data_dir: str | None = None) -> None:
        if data_dir is not None:
            base = data_dir
            self._blocklist_dir = os.path.join(base, "blocklists")
            self._cache_path = os.path.join(base, "enrichment_cache.json")
            self._mal_path = os.path.join(
                base, "tickets", "enriched", "malicious_ips.json"
            )
            self._fp_path = os.path.join(
                base, "tickets", "enriched", "false_positive_ips.json"
            )
            self._asn_rep_path = os.path.join(base, "asn_reputation.yaml")
            self._maxmind_city_path = os.path.join(base, "GeoLite2-City.mmdb")
            self._maxmind_asn_path = os.path.join(base, "GeoLite2-ASN.mmdb")
        else:
            self._blocklist_dir = _BLOCKLIST_DIR
            self._cache_path = _CACHE_PATH
            self._mal_path = _MAL_PATH
            self._fp_path = _FP_PATH
            self._asn_rep_path = _ASN_REP_PATH
            self._maxmind_city_path = _MAXMIND_CITY_DB
            self._maxmind_asn_path = _MAXMIND_ASN_DB

        # Blocklist in-memory stores
        self._cidr_prefixes: dict[str, list[ipaddress.IPv4Network]] = {}
        self._ip_sets: dict[str, set[str]] = {}

        # Enrichment cache: ip → {fetched_at, greynoise, abuseipdb}
        self._ecache: dict[str, dict[str, Any]] = {}

        # Local registry stores
        self._mal_by_ip: dict[str, dict[str, Any]] = {}
        self._fp_by_ip: dict[str, dict[str, Any]] = {}

        # ASN reputation: ASN string (e.g. "AS174") → {name, tier}
        self._asn_rep: dict[str, dict[str, str]] = {}
        # pyasn database object (None if not installed / no BGP dump)
        self._asndb: Any = None

        # MaxMind GeoLite2 reader handles (None when not installed / DB absent)
        self._mmdb_city: Any = None
        self._mmdb_asn: Any = None

        self._load_blocklists()
        self._load_enrichment_cache()
        self._load_local_registries()
        self._load_asn_reputation()
        self._load_maxmind()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_ticket(
        self,
        ticket: dict,
        ip: str | None = None,
        ip_role: str | None = None,
    ) -> OfflineEnrichment:
        """Return aggregated offline enrichment for all IPs in *ticket*.

        Iterates ``ticket["ips"]``, calls each per-IP lookup, and unions the
        results.  The most severe ``local_prior`` (``"conflicted"`` >
        ``"malicious"`` > ``"false_positive"``) wins when multiple IPs have
        different priors.  The most-severe GreyNoise classification
        (``"malicious"`` > ``"not_found"`` > ``"benign"``) wins; highest
        AbuseIPDB confidence wins.

        Args:
            ticket: Raw ticket dict from tickets_index.json.
            ip: If provided, country resolution prefers this IP's cached API
                result over all others in the ticket.
            ip_role: Role the primary IP played in this ticket — ``"source"``,
                ``"dest"``, or ``None``.  Stored verbatim on the returned
                :class:`OfflineEnrichment` for use by the classifier.
        """
        blocklist_hits: set[str] = set()
        asn_tier: str | None = None
        local_prior: str | None = None
        greynoise_classification: str | None = None
        abuseipdb_confidence: int | None = None
        country: str | None = None
        target_country: str | None = None

        _prior_rank = {"conflicted": 2, "malicious": 1, "false_positive": 0}
        _gn_rank = {"malicious": 2, "not_found": 1, "benign": 0}

        for ip_addr in ticket.get("ips", []):
            blocklist_hits.update(self._lookup_blocklists(ip_addr))

            tier = self._lookup_asn_tier(ip_addr)
            if tier and asn_tier is None:
                asn_tier = tier

            prior = self._lookup_local_prior(ip_addr)
            if prior is not None:
                if local_prior is None:
                    local_prior = prior
                elif _prior_rank.get(prior, -1) > _prior_rank.get(local_prior, -1):
                    local_prior = prior

            # Paid API results from enrichment cache
            gn_class, abuse_conf, ip_country = self._lookup_api_cache(ip_addr)
            if gn_class is not None:
                if greynoise_classification is None:
                    greynoise_classification = gn_class
                elif _gn_rank.get(gn_class, -1) > _gn_rank.get(
                    greynoise_classification, -1
                ):
                    greynoise_classification = gn_class
            if abuse_conf is not None:
                if abuseipdb_confidence is None:
                    abuseipdb_confidence = abuse_conf
                elif abuse_conf > abuseipdb_confidence:
                    abuseipdb_confidence = abuse_conf

            # Country: prefer the caller-specified IP; fall back to first hit.
            if ip_country:
                if ip is not None and ip_addr == ip:
                    target_country = ip_country
                if country is None:
                    country = ip_country

        effective_country = target_country or country

        return OfflineEnrichment(
            blocklist_hits=sorted(blocklist_hits),
            asn_tier=asn_tier,
            local_prior=local_prior,
            greynoise_classification=greynoise_classification,
            abuseipdb_confidence=abuseipdb_confidence,
            ip_role=ip_role,
            country=effective_country,
        )

    def save_api_result(
        self,
        ip: str,
        *,
        greynoise: dict[str, Any] | None = None,
        abuseipdb: dict[str, Any] | None = None,
    ) -> None:
        """Store paid API results for *ip* in the enrichment cache.

        Called by the ``--enrich`` pass in ``mantis_threat_model.py`` after
        querying GreyNoise and AbuseIPDB.  The cache is flushed to disk after
        every call so partial runs are not lost.

        Args:
            ip: The IP address the results belong to.
            greynoise: Dict with at least a ``"classification"`` key, as
                returned by ``src.enricher.greynoise.check_ip()``.
            abuseipdb: Dict with at least a ``"score"`` key, as returned by
                ``src.enricher.abuseipdb.check_ip()``.
        """
        entry = self._ecache.setdefault(ip, {})
        entry["fetched_at"] = datetime.now(tz=timezone.utc).isoformat()
        if greynoise is not None:
            entry["greynoise"] = {
                "classification": greynoise.get("classification", "not_found")
            }
        if abuseipdb is not None and not abuseipdb.get("error"):
            entry["abuseipdb"] = {
                "confidence": abuseipdb.get("score", 0),
                "country": abuseipdb.get("country", "") or "",
            }
        self._flush_cache()

    def has_fresh_api_cache(self, ip: str) -> bool:
        """Return True if *ip* has a fresh (within TTL) paid API cache entry."""
        entry = self._ecache.get(ip)
        if not entry:
            return False
        if "greynoise" not in entry and "abuseipdb" not in entry:
            return False
        return self._is_cache_entry_fresh(entry)

    # ------------------------------------------------------------------
    # Loader helpers (called once at __init__)
    # ------------------------------------------------------------------

    def _load_blocklists(self) -> None:
        """Download stale/missing blocklists and load them into memory."""
        os.makedirs(self._blocklist_dir, exist_ok=True)

        _print(f"  Loading {len(_BLOCKLIST_SOURCES)} blocklists...")
        for source, url, fmt in _BLOCKLIST_SOURCES:
            path = os.path.join(self._blocklist_dir, f"{source}.cache")
            self._maybe_download(source, url, path)
            self._parse_blocklist(source, path, fmt)

        total_cidrs = sum(len(v) for v in self._cidr_prefixes.values())
        total_ips = sum(len(v) for v in self._ip_sets.values())
        _print(
            f"  Blocklists ready: {total_cidrs:,} CIDRs, {total_ips:,} IPs "
            f"across {len(self._cidr_prefixes) + len(self._ip_sets)} sources"
        )

    def _maybe_download(self, source: str, url: str, path: str) -> None:
        """Download blocklist file if missing or older than refresh interval."""
        if os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            if age < _BLOCKLIST_REFRESH_SECONDS:
                return

        _print(f"  Downloading {source}...")
        try:
            resp = requests.get(url, timeout=30, headers={"User-Agent": "pisces/1.0"})
            resp.raise_for_status()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(resp.text)
            size_kb = len(resp.content) // 1024
            _print(f"  Downloaded {source} ({size_kb} KB)")
            logger.info("Downloaded blocklist %s → %s", source, path)
        except Exception as exc:  # noqa: BLE001
            _print(f"  Warning: failed to download {source}: {exc}")
            logger.warning(
                "Failed to download blocklist %s from %s: %s", source, url, exc
            )

    def _parse_blocklist(self, source: str, path: str, fmt: str) -> None:
        """Parse a downloaded blocklist file into the in-memory stores."""
        if not os.path.exists(path):
            _print(f"  Skipping {source} (no local cache)")
            return

        try:
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            logger.warning("Cannot read blocklist %s: %s", path, exc)
            return

        if fmt == "cidr_txt":
            self._cidr_prefixes[source] = _parse_cidr_txt(content)
            _print(f"  {source}: {len(self._cidr_prefixes[source]):,} CIDRs")
        elif fmt == "ip_txt":
            self._ip_sets[source] = _parse_ip_txt(content)
            _print(f"  {source}: {len(self._ip_sets[source]):,} IPs")
        elif fmt == "feodo_json":
            self._ip_sets[source] = _parse_feodo_json(content)
            _print(f"  {source}: {len(self._ip_sets[source]):,} IPs")
        elif fmt == "threatfox_json":
            self._ip_sets[source] = _parse_threatfox_json(content)
            _print(f"  {source}: {len(self._ip_sets[source]):,} IPs")

    def _load_enrichment_cache(self) -> None:
        """Load enrichment cache from disk."""
        if not os.path.exists(self._cache_path):
            _print("  Enrichment cache: empty (first run)")
            return
        try:
            self._ecache = load_json(self._cache_path)  # type: ignore[assignment]
            _print(f"  Enrichment cache: {len(self._ecache):,} IPs cached")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("Cannot load enrichment cache %s: %s", self._cache_path, exc)
            self._ecache = {}

    def _load_local_registries(self) -> None:
        """Load malicious_ips.json and false_positive_ips.json for local priors."""
        for path, store in (
            (self._mal_path, "_mal_by_ip"),
            (self._fp_path, "_fp_by_ip"),
        ):
            if not os.path.exists(path):
                continue
            try:
                records: list[dict[str, Any]] = load_json(path)  # type: ignore[assignment]
                setattr(self, store, {r["ip"]: r for r in records if "ip" in r})
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                logger.warning("Cannot load registry %s: %s", path, exc)

        if self._mal_by_ip or self._fp_by_ip:
            _print(
                f"  Local priors: {len(self._mal_by_ip):,} malicious, "
                f"{len(self._fp_by_ip):,} FP"
            )

    def _load_asn_reputation(self) -> None:
        """Load asn_reputation.yaml and optionally initialize pyasn."""
        if os.path.exists(self._asn_rep_path):
            try:
                with open(self._asn_rep_path, encoding="utf-8") as fh:
                    self._asn_rep = yaml.safe_load(fh) or {}
            except (OSError, yaml.YAMLError) as exc:
                logger.warning("Cannot load asn_reputation.yaml: %s", exc)

        try:
            import pyasn  # type: ignore[import-untyped]  # noqa: PLC0415

            bgp_path = os.path.join(
                os.path.dirname(self._asn_rep_path), "asn_table.dat"
            )
            if os.path.exists(bgp_path):
                self._asndb = pyasn.pyasn(bgp_path)
                logger.debug("pyasn BGP table loaded from %s", bgp_path)
        except ImportError:
            pass  # pyasn is optional

    def _load_maxmind(self) -> None:
        """Load MaxMind GeoLite2 City and ASN databases if available.

        Gracefully degrades when ``geoip2`` is not installed or the ``.mmdb``
        files are absent — all lookups will return ``None`` instead of raising.

        Download databases (free, requires MaxMind account) from:
        https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
        Place ``GeoLite2-City.mmdb`` and ``GeoLite2-ASN.mmdb`` in ``data/``.
        """
        try:
            import geoip2.database  # type: ignore[import-untyped]  # noqa: PLC0415
        except ImportError:
            _print(
                "  MaxMind: geoip2 not installed"
                " (uv add --optional offline-enrichment geoip2)"
            )
            return

        for attr, path, label in (
            ("_mmdb_city", self._maxmind_city_path, "City"),
            ("_mmdb_asn", self._maxmind_asn_path, "ASN"),
        ):
            if os.path.exists(path):
                try:
                    setattr(self, attr, geoip2.database.Reader(path))
                    _print(f"  MaxMind {label} DB: ready")
                except Exception as exc:  # noqa: BLE001
                    _print(f"  MaxMind {label} DB: failed to open — {exc}")
            else:
                _print(f"  MaxMind {label} DB: not found at {path}")

    def _flush_cache(self) -> None:
        """Write the enrichment cache to disk atomically."""
        tmp = self._cache_path + ".tmp"
        try:
            dump_json(self._ecache, tmp)
            os.replace(tmp, self._cache_path)
        except OSError as exc:
            logger.warning("Cannot flush enrichment cache: %s", exc)

    # ------------------------------------------------------------------
    # Per-IP lookup methods
    # ------------------------------------------------------------------

    def _lookup_blocklists(self, ip: str) -> list[str]:
        """Return blocklist source names that list *ip*."""
        hits: list[str] = []
        try:
            addr = ipaddress.ip_address(ip)
            if not isinstance(addr, ipaddress.IPv4Address):
                return hits  # only IPv4 blocklists for now
            for source, prefixes in self._cidr_prefixes.items():
                if any(addr in net for net in prefixes):
                    hits.append(source)
        except ValueError:
            pass

        for source, ip_set in self._ip_sets.items():
            if ip in ip_set:
                hits.append(source)

        return hits

    def _lookup_asn_tier(self, ip: str) -> str | None:
        """Return the reputation tier for the ASN that routes *ip*.

        Requires pyasn and a BGP dump at ``data/asn_table.dat``.  Returns
        ``None`` if either is unavailable.
        """
        if self._asndb is None or not self._asn_rep:
            return None

        try:
            asn, _ = self._asndb.lookup(ip)
            if asn is None:
                return None
            asn_key = f"AS{asn}"
            entry = self._asn_rep.get(asn_key)
            if entry:
                return entry.get("tier")
        except Exception as exc:  # noqa: BLE001
            logger.debug("ASN lookup failed for %s: %s", ip, exc)

        return None

    def _lookup_local_prior(self, ip: str) -> str | None:
        """Return the local analyst-verdict prior for *ip*.

        Rules (§7 of pipeline architecture doc):
            - ≥2 malicious tickets, no FP entry  → ``"malicious"``
            - ≥3 FP tickets, no malicious entry  → ``"false_positive"``
            - Present in both registries          → ``"conflicted"``
        """
        in_mal = ip in self._mal_by_ip
        in_fp = ip in self._fp_by_ip

        if in_mal and in_fp:
            return "conflicted"

        if in_mal:
            mal_rec = self._mal_by_ip[ip]
            ticket_count = mal_rec.get(
                "ticket_count", len(mal_rec.get("ticket_ids", []))
            )
            if ticket_count >= 2:
                return "malicious"

        if in_fp:
            fp_rec = self._fp_by_ip[ip]
            if len(fp_rec.get("ticket_ids", [])) >= 3:
                return "false_positive"

        return None

    def _lookup_api_cache(self, ip: str) -> tuple[str | None, int | None, str | None]:
        """Return (greynoise_classification, abuseipdb_confidence, country).

        Returns (None, None, None) if no fresh paid API result is cached for
        *ip*.  ``country`` is an ISO 3166-1 alpha-2 code sourced from the
        AbuseIPDB cache entry, or ``None`` when unavailable.
        """
        entry = self._ecache.get(ip)
        if not entry or not self._is_cache_entry_fresh(entry):
            return None, None, None

        gn_class: str | None = None
        gn = entry.get("greynoise")
        if gn:
            gn_class = gn.get("classification")

        abuse_conf: int | None = None
        country: str | None = None
        ab = entry.get("abuseipdb")
        if ab:
            abuse_conf = ab.get("confidence")
            raw_country = ab.get("country", "")
            country = raw_country if raw_country else None

        return gn_class, abuse_conf, country

    def _lookup_maxmind(self, ip: str) -> tuple[str | None, str | None, str | None]:
        """Return ``(country_code, asn, isp)`` from MaxMind GeoLite2 databases.

        - ``country_code``: ISO 3166-1 alpha-2 from GeoLite2-City (e.g. ``"RU"``).
        - ``asn``: Autonomous system number string from GeoLite2-ASN (e.g. ``"AS15169"``).
        - ``isp``: Autonomous system organisation name (e.g. ``"GOOGLE"``).

        Returns ``(None, None, None)`` when both databases are unavailable, the
        IP is not indexed, or the IP is private/reserved.
        """
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return None, None, None
        except ValueError:
            return None, None, None

        country: str | None = None
        asn: str | None = None
        isp: str | None = None

        if self._mmdb_city is not None:
            try:
                rec = self._mmdb_city.city(ip)
                code = rec.country.iso_code
                if code:
                    country = code
            except Exception:  # noqa: BLE001
                pass

        if self._mmdb_asn is not None:
            try:
                rec = self._mmdb_asn.asn(ip)
                if rec.autonomous_system_number:
                    asn = f"AS{rec.autonomous_system_number}"
                org = rec.autonomous_system_organization
                if org:
                    isp = org
            except Exception:  # noqa: BLE001
                pass

        return country, asn, isp

    def get_country(self, ip: str) -> str | None:
        """Return the ISO 3166-1 alpha-2 country code for *ip*.

        Priority: AbuseIPDB paid API cache → MaxMind GeoLite2 City DB.
        Returns ``None`` when neither source has data for the IP.
        """
        _, _, country = self._lookup_api_cache(ip)
        if country:
            return country
        mm_country, _, _ = self._lookup_maxmind(ip)
        return mm_country

    def get_asn(self, ip: str) -> str | None:
        """Return the ASN string for *ip* from MaxMind GeoLite2 (e.g. ``"AS15169"``).

        Returns ``None`` when GeoLite2-ASN.mmdb is unavailable or the IP is
        not indexed.
        """
        _, asn, _ = self._lookup_maxmind(ip)
        return asn

    def get_isp(self, ip: str) -> str | None:
        """Return the ISP / autonomous-system organisation name for *ip*.

        Sourced from the MaxMind GeoLite2 ASN database.  Returns ``None``
        when the database is unavailable or the IP is not indexed.
        """
        _, _, isp = self._lookup_maxmind(ip)
        return isp

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_cache_entry_fresh(self, entry: dict[str, Any]) -> bool:
        """Return True if *entry* was fetched within the cache TTL."""
        fetched_at = entry.get("fetched_at")
        if not fetched_at:
            return False
        try:
            ts = datetime.fromisoformat(fetched_at)
            age_days = (datetime.now(tz=timezone.utc) - ts).days
            return age_days < _CACHE_TTL_DAYS
        except (ValueError, TypeError):
            return False


# ---------------------------------------------------------------------------
# Blocklist parsing helpers
# ---------------------------------------------------------------------------


def _parse_cidr_txt(content: str) -> list[ipaddress.IPv4Network]:
    """Parse a text file of CIDR ranges (one per line, ``#`` comments)."""
    networks: list[ipaddress.IPv4Network] = []
    for line in content.splitlines():
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.IPv4Network(line, strict=False)
            networks.append(net)
        except ValueError:
            pass
    return networks


def _parse_ip_txt(content: str) -> set[str]:
    """Parse a plain text file of individual IP addresses (one per line)."""
    ips: set[str] = set()
    for line in content.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
            ips.add(line)
        except ValueError:
            pass
    return ips


def _parse_feodo_json(content: str) -> set[str]:
    """Parse the Feodo Tracker JSON blocklist (``ip_address`` field)."""
    ips: set[str] = set()
    try:
        data = json.loads(content)
        for entry in data:
            ip = entry.get("ip_address")
            if ip:
                ips.add(ip)
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return ips


def _parse_threatfox_json(content: str) -> set[str]:
    """Parse ThreatFox export JSON — extract IPs from ``ioc_value`` fields."""
    ips: set[str] = set()
    try:
        data = json.loads(content)
        # ThreatFox format: {"query_status": "...", "data": [...]}
        entries = data if isinstance(data, list) else data.get("data", [])
        for entry in entries:
            ioc_type = entry.get("ioc_type", "")
            if ioc_type not in ("ip:port", "ip"):
                continue
            value: str = entry.get("ioc_value", "")
            # Strip port if present (e.g. "1.2.3.4:4444")
            ip_part = value.split(":")[0]
            try:
                ipaddress.ip_address(ip_part)
                ips.add(ip_part)
            except ValueError:
                pass
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return ips
