#!/usr/bin/env python3
"""
Filter loader: walks filters/ directory, assembles must_not DSL clauses.

Usage (standalone):
    python src/querier/filter_loader.py
"""

import os
import sys
import time

import yaml

# Module-level cache: (filters_dir, municipality) → {mtime, result, checked}
_filter_cache: dict[tuple, dict] = {}

_MTIME_TTL = 5.0  # seconds — skip the directory walk when cache is this fresh


def _max_mtime(filters_dir: str) -> float:
    """Return the highest mtime across all *.yaml files under filters_dir."""
    max_t = 0.0
    for root, _dirs, files in os.walk(filters_dir):
        for fname in files:
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                try:
                    t = os.path.getmtime(os.path.join(root, fname))
                    if t > max_t:
                        max_t = t
                except OSError:
                    pass
    return max_t


def _load_categories(filters_dir: str) -> dict[str, set[str]]:
    """Load categories.yaml and return {category: set(subcategories)}.

    Returns an empty dict if the file is absent or unparseable (non-fatal).
    """
    cat_path = os.path.join(filters_dir, "categories.yaml")
    try:
        with open(cat_path) as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return {}

    if not isinstance(raw, dict):
        return {}
    registry: dict[str, set[str]] = {}
    for cat, meta in raw.get("categories", {}).items():
        subs = meta.get("subcategories", []) if isinstance(meta, dict) else []
        registry[cat] = set(subs)
    return registry


def load_filters(
    filters_dir: str,
    municipality: str | None = None,
) -> dict:
    """Walk all *.yaml files under filters_dir and assemble must_not clauses.

    Args:
        filters_dir: Path to the filters/ directory.
        municipality: If given, only include composite filters that list this
                      municipality (or filters with no municipalities field).

    Returns:
        {
            "must_not": [<ES DSL clause>, ...],
            "filter_count": int,    # number of YAML files processed
            "errors": [str, ...]    # parse/schema errors
        }
    """
    cache_key = (filters_dir, municipality)
    now = time.monotonic()
    cached = _filter_cache.get(cache_key)
    if cached is not None and (now - cached["checked"]) < _MTIME_TTL:
        return cached["result"]
    current_mtime = _max_mtime(filters_dir)
    if cached is not None and cached["mtime"] == current_mtime:
        cached["checked"] = now
        return cached["result"]

    must_not_clauses: list[dict] = []
    errors: list[str] = []
    filter_count = 0

    if not os.path.isdir(filters_dir):
        return {
            "must_not": [],
            "filter_count": 0,
            "errors": [f"filters_dir not found: {filters_dir}"],
        }

    categories = _load_categories(filters_dir)

    for root, _dirs, files in os.walk(filters_dir):
        for fname in sorted(files):
            if not fname.endswith(".yaml") and not fname.endswith(".yml"):
                continue
            # Skip the categories registry itself
            if fname == "categories.yaml":
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath) as fh:
                    data = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                errors.append(f"{fpath}: YAML parse error: {exc}")
                continue
            except OSError as exc:
                errors.append(f"{fpath}: read error: {exc}")
                continue

            if not isinstance(data, dict):
                errors.append(f"{fpath}: expected a YAML mapping at top level")
                continue

            # Validate category/subcategory against the registry when present.
            if categories:
                cat = data.get("category")
                sub = data.get("subcategory")
                if cat is not None and cat not in categories:
                    errors.append(
                        f"{fpath}: unknown category '{cat}' (valid: {sorted(categories)})"
                    )
                elif cat is not None and sub is not None:
                    valid_subs = categories[cat]
                    if valid_subs and sub not in valid_subs:
                        errors.append(
                            f"{fpath}: unknown subcategory '{sub}' for category '{cat}' "
                            f"(valid: {sorted(valid_subs)})"
                        )

            # Respect enabled flag (default True)
            if not data.get("enabled", True):
                continue

            # Municipality scoping for composite filters
            file_municipalities = data.get("municipalities")
            if file_municipalities and municipality:
                if municipality not in file_municipalities:
                    continue

            clauses = data.get("must_not")
            if clauses is None:
                errors.append(f"{fpath}: missing 'must_not' key")
                continue
            if not isinstance(clauses, list):
                errors.append(f"{fpath}: 'must_not' must be a list")
                continue

            for entry in clauses:
                if isinstance(entry, dict) and "comment" in entry:
                    entry = {k: v for k, v in entry.items() if k != "comment"}
                must_not_clauses.append(entry)
            filter_count += 1

    result = {
        "must_not": must_not_clauses,
        "filter_count": filter_count,
        "errors": errors,
    }
    _filter_cache[cache_key] = {"mtime": current_mtime, "result": result, "checked": now}
    return result


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    filters_dir = os.path.join(base, "filters")

    result = load_filters(filters_dir)
    print(
        f"Loaded {result['filter_count']} filter file(s), "
        f"{len(result['must_not'])} must_not clause(s)"
    )

    if result["errors"]:
        print(f"\n{len(result['errors'])} error(s):")
        for err in result["errors"]:
            print(f"  ! {err}")
    else:
        print("No errors.")

    if "--verbose" in sys.argv:
        import json

        print("\nmust_not clauses:")
        print(json.dumps(result["must_not"], indent=2))
