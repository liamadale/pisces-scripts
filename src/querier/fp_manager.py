#!/usr/bin/env python3
"""
False Positive Manager — interactive FP filter creation and management.

Standalone usage:
    python src/querier/fp_manager.py --list
    python src/querier/fp_manager.py --validate
    python src/querier/fp_manager.py --edit <subcategory>
"""

import argparse
import datetime
import os
import subprocess
import sys

import yaml
from rich import box
from rich.console import Console
from rich.table import Table

console = Console(file=sys.stderr)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILTERS_DIR = os.path.join(_BASE, "filters")
CATEGORIES_FILE = os.path.join(FILTERS_DIR, "categories.yaml")


# ---------------------------------------------------------------------------
# categories.yaml helpers
# ---------------------------------------------------------------------------


def load_categories() -> dict:
    """Load categories.yaml, returning the inner dict (never raises)."""
    if not os.path.exists(CATEGORIES_FILE):
        return {"categories": {}}
    try:
        with open(CATEGORIES_FILE) as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {"categories": {}}
    except yaml.YAMLError:
        return {"categories": {}}


def save_categories(data: dict) -> None:
    with open(CATEGORIES_FILE, "w") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _categories_dict(data: dict) -> dict:
    return data.get("categories", {})


def ensure_subcategory(category: str, subcategory: str) -> None:
    """Add category/subcategory to categories.yaml if not already present."""
    data = load_categories()
    cats = _categories_dict(data)
    if category not in cats:
        cats[category] = {"subcategories": []}
    subs = cats[category].setdefault("subcategories", [])
    if subcategory not in subs:
        subs.append(subcategory)
    data["categories"] = cats
    save_categories(data)


# ---------------------------------------------------------------------------
# Filter file helpers
# ---------------------------------------------------------------------------


def filter_file_path(category: str, subcategory: str) -> str:
    return os.path.join(FILTERS_DIR, category, f"{subcategory}.yaml")


def load_filter_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def write_filter_file(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)


def delete_ip_from_filter(path: str, ip: str) -> int:
    """Remove must_not clauses that match *ip* as src_ip or dest_ip.

    Handles single-value ``term`` and multi-value ``terms`` clauses.
    For ``terms`` clauses with multiple IPs only the matching IP is removed;
    the clause is kept with the remaining IPs.  If the clause had only that
    one IP it is dropped entirely.

    Returns the number of clause entries affected (removed or shrunken).
    Raises ``FileNotFoundError`` if *path* does not exist.
    Raises ``ValueError`` if no clauses matched the IP.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    data = load_filter_file(path)
    original_clauses: list = data.get("must_not", [])
    kept: list = []
    removed_count = 0

    for clause in original_clauses:
        term = clause.get("term", {})
        if term.get("src_ip") == ip or term.get("dest_ip") == ip:
            removed_count += 1
            continue

        terms = clause.get("terms", {})
        matched_field: str | None = None
        for field in ("src_ip", "dest_ip"):
            if ip in terms.get(field, []):
                matched_field = field
                break

        if matched_field:
            remaining = [v for v in terms[matched_field] if v != ip]
            if remaining:
                new_clause = dict(clause)
                new_clause["terms"] = {**terms, matched_field: remaining}
                kept.append(new_clause)
            removed_count += 1
            continue

        kept.append(clause)

    if removed_count == 0:
        raise ValueError(f"No clauses found matching IP {ip}")

    data["must_not"] = kept
    write_filter_file(path, data)
    return removed_count


def append_clauses_to_file(path: str, new_clauses: list[dict], author: str = "analyst") -> None:
    """Append must_not clauses to an existing filter file, or create it."""
    if os.path.exists(path):
        existing = load_filter_file(path)
        existing.setdefault("must_not", [])
        existing["must_not"].extend(new_clauses)
        write_filter_file(path, existing)
    else:
        category = os.path.basename(os.path.dirname(path))
        subcategory = os.path.splitext(os.path.basename(path))[0]
        data = {
            "description": f"{category} / {subcategory} false positive filters",
            "author": author,
            "date_added": datetime.date.today().isoformat(),
            "category": category,
            "subcategory": subcategory,
            "enabled": True,
            "must_not": new_clauses,
        }
        write_filter_file(path, data)


# ---------------------------------------------------------------------------
# Sync / validate helpers
# ---------------------------------------------------------------------------


def sync_categories() -> list[str]:
    """Scan filters/ directory and report files not in categories.yaml registry."""
    data = load_categories()
    cats = _categories_dict(data)
    warnings = []

    for category in os.listdir(FILTERS_DIR):
        cat_dir = os.path.join(FILTERS_DIR, category)
        if not os.path.isdir(cat_dir):
            continue
        for fname in os.listdir(cat_dir):
            if not fname.endswith(".yaml") and not fname.endswith(".yml"):
                continue
            subcategory = os.path.splitext(fname)[0]
            if category not in cats or subcategory not in cats[category].get("subcategories", []):
                warnings.append(f"  {category}/{fname} — not in categories.yaml registry")

    return warnings


def validate_all_filters() -> tuple[int, list[str]]:
    """Validate all filter YAML files. Returns (ok_count, errors)."""
    errors = []
    ok_count = 0

    for root, _dirs, files in os.walk(FILTERS_DIR):
        for fname in sorted(files):
            if not fname.endswith(".yaml") and not fname.endswith(".yml"):
                continue
            if fname == "categories.yaml":
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath) as fh:
                    data = yaml.safe_load(fh)
                if not isinstance(data, dict):
                    errors.append(f"{fpath}: top-level must be a mapping")
                    continue
                required = {
                    "description",
                    "author",
                    "date_added",
                    "category",
                    "subcategory",
                    "enabled",
                    "must_not",
                }
                missing = required - set(data.keys())
                if missing:
                    errors.append(f"{fpath}: missing keys: {', '.join(sorted(missing))}")
                    continue
                if not isinstance(data["must_not"], list):
                    errors.append(f"{fpath}: 'must_not' must be a list")
                    continue
                ok_count += 1
            except yaml.YAMLError as exc:
                errors.append(f"{fpath}: YAML parse error: {exc}")
            except OSError as exc:
                errors.append(f"{fpath}: {exc}")

    return ok_count, errors


# ---------------------------------------------------------------------------
# Interactive filter creation
# ---------------------------------------------------------------------------


def _prompt_category() -> tuple[str, bool]:
    """Return (category_name, is_new)."""
    data = load_categories()
    cats = list(_categories_dict(data).keys())

    console.print("\n[bold cyan]Select category:[/bold cyan]")
    for i, cat in enumerate(cats, 1):
        console.print(f"  [{i}] {cat}")
    console.print("  [N] New category")

    choice = input("Choice: ").strip()
    if choice.lower() == "n":
        name = input("New category name: ").strip().lower().replace(" ", "_")
        return name, True
    try:
        idx = int(choice) - 1
        return cats[idx], False
    except (ValueError, IndexError):
        console.print("[red]Invalid choice, defaulting to 'ips'[/red]")
        return "ips", False


def _prompt_subcategory(category: str) -> tuple[str, bool]:
    """Return (subcategory_name, is_new)."""
    data = load_categories()
    subs = _categories_dict(data).get(category, {}).get("subcategories", [])

    console.print(f"\n[bold cyan]Select subcategory for '{category}':[/bold cyan]")
    for i, sub in enumerate(subs, 1):
        console.print(f"  [{i}] {sub}")
    console.print("  [N] New subcategory")

    choice = input("Choice: ").strip()
    if choice.lower() == "n":
        name = input("New subcategory name: ").strip().lower().replace(" ", "_")
        return name, True
    try:
        idx = int(choice) - 1
        return subs[idx], False
    except (ValueError, IndexError):
        console.print("[red]Invalid choice[/red]")
        return subs[0] if subs else "general", False


def _infer_clauses_from_alert(alert: dict, category: str) -> list[dict]:
    """Build a best-guess must_not clause from the alert dict."""
    clauses = []
    if category == "ips" and alert.get("src_ip"):
        clauses.append({"term": {"src_ip": alert["src_ip"]}})
    elif category == "signatures" and alert.get("alert", {}).get("signature"):
        clauses.append({"match_phrase": {"alert.signature": alert["alert"]["signature"]}})
    elif category == "ports" and alert.get("dest_port"):
        clauses.append({"term": {"dest_port": alert["dest_port"]}})
    return clauses


def create_notice_filter_interactive(record: dict, author: str = "analyst") -> None:
    """Create a narrow notice-type filter: suppress (src_ip + notice.note) in filters/notices/."""
    src_ip = record.get("src_ip", "")
    notice_note = record.get("notice_note", "")

    console.print("\n[bold yellow]=== Narrow Notice Filter Creator ===[/bold yellow]")
    console.print(f"  src_ip:      [yellow]{src_ip}[/yellow]")
    console.print(f"  notice.note: [cyan]{notice_note}[/cyan]")

    if not src_ip or not notice_note:
        console.print("[red]Missing src_ip or notice_note — cannot create narrow filter.[/red]")
        return

    subcategory, _ = _prompt_subcategory("notices")

    clause = {
        "bool": {
            "must": [
                {"term": {"src_ip": src_ip}},
                {"term": {"zeek.notice.note": notice_note}},
            ]
        }
    }

    comment = input("Comment (optional, Enter to skip): ").strip()
    if comment:
        clause["comment"] = comment

    fpath = filter_file_path("notices", subcategory)
    import yaml as _yaml

    preview = {
        "category": "notices",
        "subcategory": subcategory,
        "target_file": fpath,
        "must_not": [clause],
    }
    console.print("\n[bold cyan]Preview:[/bold cyan]")
    console.print(
        _yaml.dump(preview, default_flow_style=False, allow_unicode=True, sort_keys=False)
    )

    confirm = input("Write filter? [y/N]: ").strip().lower()
    if confirm != "y":
        console.print("[yellow]Aborted.[/yellow]")
        return

    append_clauses_to_file(fpath, [clause], author=author)
    ensure_subcategory("notices", subcategory)
    console.print(f"[green]Written: {fpath}[/green]")


def create_filter_interactive(
    alert: dict | None = None, author: str = "analyst", comment_hint: str = ""
) -> None:
    """Guide analyst through creating a new FP filter, optionally seeded from an alert."""
    console.print("\n[bold yellow]=== False Positive Filter Creator ===[/bold yellow]")

    # Sync check
    warnings = sync_categories()
    if warnings:
        console.print("[yellow]Registry sync warnings:[/yellow]")
        for w in warnings:
            console.print(w)

    category, cat_new = _prompt_category()
    subcategory, sub_new = _prompt_subcategory(category)

    # Build initial clauses
    clauses: list[dict] = []
    if alert:
        clauses = _infer_clauses_from_alert(alert, category)
        if clauses:
            console.print("\n[green]Inferred clause(s) from alert:[/green]")
            for c in clauses:
                console.print(f"  {c}")
            add_more = input("Add additional clauses? [y/N]: ").strip().lower()
        else:
            add_more = "y"
    else:
        add_more = "y"

    if add_more == "y":
        console.print("\nEnter must_not clauses as YAML (one clause per entry).")
        console.print('Example:  term:\\n  src_ip: "1.2.3.4"')
        console.print("Enter a blank line to finish.\n")
        lines = []
        while True:
            line = input("  > ")
            if line == "":
                if lines:
                    break
                elif clauses:
                    break
            else:
                lines.append(line)
        if lines:
            raw = "\n".join(lines)
            try:
                parsed = yaml.safe_load(raw)
                if isinstance(parsed, dict):
                    clauses.append(parsed)
                elif isinstance(parsed, list):
                    clauses.extend(parsed)
            except yaml.YAMLError as exc:
                console.print(f"[red]YAML parse error: {exc}[/red]")
                return

    if not clauses:
        console.print("[red]No clauses provided. Aborting.[/red]")
        return

    # Comment prompt — shown after clauses are confirmed
    if comment_hint:
        raw_comment = input(f"Comment [{comment_hint}]: ").strip()
        comment = raw_comment if raw_comment else comment_hint
    else:
        comment = input("Comment (optional, Enter to skip): ").strip()

    if comment:
        for clause in clauses:
            clause["comment"] = comment

    # Preview
    fpath = filter_file_path(category, subcategory)
    preview = {
        "category": category,
        "subcategory": subcategory,
        "target_file": fpath,
        "must_not": clauses,
    }
    console.print("\n[bold cyan]Preview:[/bold cyan]")
    console.print(yaml.dump(preview, default_flow_style=False, allow_unicode=True, sort_keys=False))

    confirm = input("Write filter? [y/N]: ").strip().lower()
    if confirm != "y":
        console.print("[yellow]Aborted.[/yellow]")
        return

    append_clauses_to_file(fpath, clauses, author=author)
    ensure_subcategory(category, subcategory)
    console.print(f"[green]Written: {fpath}[/green]")


# ---------------------------------------------------------------------------
# CLI subcommands
# ---------------------------------------------------------------------------


def cmd_list() -> None:
    data = load_categories()
    cats = _categories_dict(data)

    table = Table(title="FP Filters by Category", box=box.SIMPLE)
    table.add_column("Category", style="cyan")
    table.add_column("Subcategory", style="green")
    table.add_column("File", style="white")
    table.add_column("Enabled", style="yellow")
    table.add_column("Clauses", justify="right")

    for category, cat_data in sorted(cats.items()):
        for subcategory in sorted(cat_data.get("subcategories", [])):
            fpath = filter_file_path(category, subcategory)
            if os.path.exists(fpath):
                fdata = load_filter_file(fpath)
                enabled = str(fdata.get("enabled", True))
                clauses = len(fdata.get("must_not", []))
                short_path = os.path.relpath(fpath, _BASE)
            else:
                enabled = "—"
                clauses = 0
                short_path = f"filters/{category}/{subcategory}.yaml [missing]"
            table.add_row(category, subcategory, short_path, enabled, str(clauses))

    console.print(table)


def cmd_validate() -> None:
    ok_count, errors = validate_all_filters()
    warnings = sync_categories()

    console.print(f"\n[bold]Validation results:[/bold] {ok_count} file(s) OK")
    if errors:
        console.print(f"[red]{len(errors)} error(s):[/red]")
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
    else:
        console.print("[green]No errors.[/green]")

    if warnings:
        console.print(f"\n[yellow]{len(warnings)} registry warning(s):[/yellow]")
        for w in warnings:
            console.print(f"  [yellow]⚠[/yellow] {w}")


def cmd_edit(subcategory_name: str) -> None:
    editor = os.environ.get("EDITOR", "nano")
    # Search all categories for this subcategory
    for root, _dirs, files in os.walk(FILTERS_DIR):
        for fname in files:
            if os.path.splitext(fname)[0] == subcategory_name and fname.endswith(".yaml"):
                fpath = os.path.join(root, fname)
                subprocess.run([editor, fpath])
                return
    console.print(f"[red]No filter file found for subcategory '{subcategory_name}'[/red]")


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES FP Filter Manager")
    parser.add_argument("--list", action="store_true", help="List all current filters")
    parser.add_argument("--validate", action="store_true", help="Validate all filter YAML files")
    parser.add_argument("--edit", metavar="SUBCATEGORY", help="Open filter file in $EDITOR")
    parser.add_argument("--new", action="store_true", help="Create a new FP filter interactively")
    args = parser.parse_args()

    if args.list:
        cmd_list()
    elif args.validate:
        cmd_validate()
    elif args.edit:
        cmd_edit(args.edit)
    elif args.new:
        create_filter_interactive()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
