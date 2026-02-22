"""
GreyNoise IP lookup.

Returns classification: benign | malicious | not_found
"""

import os
import requests


_BASE_URL = "https://api.greynoise.io/v3/community"


def check_ip(ip: str) -> dict:
    """Query GreyNoise community API for an IP.

    Returns:
        {
            "classification": "benign" | "malicious" | "not_found",
            "name": str,
            "reason": str,
            "raw": dict | None,
        }
    """
    api_key = os.environ.get("GREYNOISE_API_KEY", "")
    headers = {"key": api_key} if api_key else {}

    try:
        resp = requests.get(f"{_BASE_URL}/{ip}", headers=headers, timeout=10)
    except requests.RequestException as exc:
        return {
            "classification": "not_found",
            "name": "",
            "reason": f"Request failed: {exc}",
            "raw": None,
        }

    if resp.status_code == 404:
        return {
            "classification": "not_found",
            "name": "",
            "reason": "IP not in GreyNoise dataset",
            "raw": None,
        }

    if resp.status_code == 401:
        return {
            "classification": "not_found",
            "name": "",
            "reason": "Invalid or missing GREYNOISE_API_KEY",
            "raw": None,
        }

    if not resp.ok:
        return {
            "classification": "not_found",
            "name": "",
            "reason": f"HTTP {resp.status_code}",
            "raw": None,
        }

    data = resp.json()
    classification = data.get("classification", "not_found")
    return {
        "classification": classification,
        "name": data.get("name", ""),
        "reason": data.get("message", ""),
        "raw": data,
    }
