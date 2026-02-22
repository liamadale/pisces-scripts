#!/usr/bin/env python3
"""
Filter loader: walks filters/ directory, assembles must_not DSL clauses.

Usage (standalone):
    python src/querier/filter_loader.py
"""

import os
import sys
import yaml


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
    must_not_clauses: list[dict] = []
    errors: list[str] = []
    filter_count = 0

    if not os.path.isdir(filters_dir):
        return {"must_not": [], "filter_count": 0, "errors": [f"filters_dir not found: {filters_dir}"]}

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

            must_not_clauses.extend(clauses)
            filter_count += 1

    return {
        "must_not": must_not_clauses,
        "filter_count": filter_count,
        "errors": errors,
    }


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    filters_dir = os.path.join(base, "filters")

    result = load_filters(filters_dir)
    print(f"Loaded {result['filter_count']} filter file(s), "
          f"{len(result['must_not'])} must_not clause(s)")

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
