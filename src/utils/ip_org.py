"""IP organization lookup — bundled CIDR ranges + fetched AWS/GCP/Azure with disk cache."""
import ipaddress
import json
import threading
import time
import urllib.request
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

_CACHE_FILE = Path(__file__).parents[2] / "data" / "ip_ranges_cache.json"
_CACHE_TTL  = 86_400  # 24 hours

# ── Bundled orgs (hardcoded, always available) ────────────────────────────────
# (cidr_list, display_name, fa_icon_classes, category)
_BUNDLED = [
    # CDN
    (["103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13",
      "104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
      "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
      "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
      "1.1.1.0/24","1.0.0.0/24"],
     "Cloudflare","fa-brands fa-cloudflare","cdn"),
    (["23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
      "103.245.224.0/24","104.156.80.0/20","140.248.64.0/18","140.248.128.0/17",
      "151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","167.82.128.0/20",
      "167.82.160.0/20","167.82.224.0/20","172.111.64.0/18",
      "185.31.16.0/22","199.27.72.0/21","199.232.0.0/16"],
     "Fastly","fa-solid fa-bolt","cdn"),
    # Scanners
    (["198.20.69.74/32","198.20.69.98/32","198.20.70.114/32",
      "198.20.254.143/32","155.94.222.12/32","98.143.148.135/32","207.90.244.0/24"],
     "Shodan","fa-solid fa-eye","scanner"),
    (["66.132.159.0/24","162.142.125.0/24","167.94.138.0/24","167.94.148.0/24",
      "66.132.153.0/24","206.168.32.0/24","206.168.33.0/24"],
     "Censys","fa-solid fa-magnifying-glass","scanner"),
    (["64.39.96.0/20","139.87.112.0/23","69.67.179.0/24","69.67.181.0/24"],
     "Qualys","fa-solid fa-shield-halved","scanner"),
    (["71.6.233.0/24","5.63.151.96/27","88.202.190.128/27",
      "109.123.117.228/32","109.123.117.230/32","109.123.117.232/32"],
     "Rapid7","fa-solid fa-shield-halved","scanner"),
    (["64.62.197.254/32","149.20.4.0/24","149.20.5.0/24","149.20.6.0/24"],
     "ShadowServer","fa-solid fa-server","research"),
    (["185.162.235.0/24","185.162.236.0/24","185.162.237.0/24"],
     "BinaryEdge","fa-solid fa-circle-nodes","research"),
    # Public DNS
    (["8.8.8.0/24","8.8.4.0/24"],"Google DNS","fa-brands fa-google","cloud"),
]

# ── Index structure: first_octet → [(network, name, icon, category)] ─────────
# Bounds lookup to O(total_cidrs / 256) comparisons per IP.
_INDEX: dict[int, list] = defaultdict(list)

def _add_to_index(cidr: str, name: str, icon: str, cat: str) -> None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return
    first_octet = int(net.network_address) >> 24
    last_octet  = int(net.broadcast_address) >> 24
    entry = (net, name, icon, cat)
    for octet in range(first_octet, last_octet + 1):
        _INDEX[octet].append(entry)

# Load bundled orgs immediately at import
for _cidrs, _name, _icon, _cat in _BUNDLED:
    for _cidr in _cidrs:
        _add_to_index(_cidr, _name, _icon, _cat)

# ── Cache / fetch for AWS, GCP, Azure ────────────────────────────────────────
def _load_cache() -> bool:
    """Load cloud ranges from disk cache. Returns True if cache is fresh."""
    if not _CACHE_FILE.exists():
        return False
    try:
        entries = json.loads(_CACHE_FILE.read_text())
        for e in entries:
            _add_to_index(e["cidr"], e["org"], e["icon"], e["cat"])
        return True
    except Exception:
        return False

def _fetch_cloud_ranges() -> None:
    """Download AWS + GCP + Azure ranges and save to cache (runs in background thread)."""
    entries: list[dict] = []
    try:
        with urllib.request.urlopen(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15
        ) as r:
            aws = json.loads(r.read())
        for p in aws.get("prefixes", []):
            if "ip_prefix" in p:
                entries.append({"cidr": p["ip_prefix"],
                                 "org": "AWS", "icon": "fa-brands fa-aws", "cat": "cloud"})
    except Exception:
        pass

    try:
        with urllib.request.urlopen(
            "https://www.gstatic.com/ipranges/cloud.json", timeout=15
        ) as r:
            gcp = json.loads(r.read())
        for p in gcp.get("prefixes", []):
            if "ipv4Prefix" in p:
                entries.append({"cidr": p["ipv4Prefix"],
                                 "org": "Google Cloud", "icon": "fa-brands fa-google", "cat": "cloud"})
    except Exception:
        pass

    try:
        with urllib.request.urlopen(
            "https://cloud-ip-ranges.com/download/azure.txt", timeout=15
        ) as r:
            for line in r.read().decode().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append({"cidr": line,
                                     "org": "Azure", "icon": "fa-brands fa-microsoft", "cat": "cloud"})
    except Exception:
        pass

    if not entries:
        return  # nothing fetched — don't overwrite cache with empty file

    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(entries))
    except Exception:
        pass

    for e in entries:
        _add_to_index(e["cidr"], e["org"], e["icon"], e["cat"])
    # Clear LRU cache so fresh org data applies to subsequent lookups
    lookup_org.cache_clear()

# On import: load cache if it exists; kick off background fetch if missing or stale
_cache_loaded = _load_cache()
if not _cache_loaded or time.time() - _CACHE_FILE.stat().st_mtime > _CACHE_TTL:
    threading.Thread(target=_fetch_cloud_ranges, daemon=True).start()


# ── Public API ────────────────────────────────────────────────────────────────
@lru_cache(maxsize=4096)
def lookup_org(ip_str: str) -> dict | None:
    """Return org info dict for a public IP, or None if unknown/private/invalid."""
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if ip.is_multicast:
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return {"name": "Private", "icon": "fa-solid fa-network-wired", "category": "private"}
    octet = int(ip.packed[0])
    for net, name, icon, category in _INDEX.get(octet, []):
        if ip in net:
            return {"name": name, "icon": icon, "category": category}
    return None
