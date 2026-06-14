"""Batch device profiling for private IPs in the infrastructure registry.

Reads the infra registry (known_infra_ips.json), filters to RFC1918 addresses,
and runs profile_device() for each using a thread pool.  Results are written to
a sidecar file (private_ip_profiles.json) that the web app loads at startup.

Supports incremental re-runs: IPs already in the sidecar are skipped unless
force=True is passed.
"""

from __future__ import annotations

import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime

from src.mantis.threat_model._shared import console
from src.utils.cache import dump_json, load_json

_PROGRESS_INTERVAL = 50


def _is_rfc1918(ip: str) -> bool:
    """Return True for RFC1918/link-local/loopback addresses that profile_device() accepts."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private and not addr.is_unspecified
    except ValueError:
        return False


def _profile_one(
    ip: str,
    time_range: str,
    sensor: str,
) -> dict | None:
    """Run profile_device() for one IP, returning a serialisable dict or None on error."""
    try:
        from src.profiler.device_profiler import profile_device

        profile = profile_device(ip, time_range=time_range, sensor=sensor)
        record = asdict(profile)
        # orjson requires string dict keys — port distributions use int keys
        record["dest_port_distribution"] = {
            str(k): v for k, v in record["dest_port_distribution"].items()
        }
        record["profiled_at"] = datetime.now().isoformat(timespec="seconds")
        return record
    except Exception as exc:
        console.print(f"[yellow]  profile skipped {ip}: {exc}[/yellow]")
        return None


def profile_private_ips(
    infra_path: str,
    output_path: str,
    time_range: str = "now-7d",
    sensor: str = "all",
    workers: int = 5,
    force: bool = False,
) -> None:
    """Batch-profile private IPs from the infra registry and write a sidecar file.

    Args:
        infra_path: Path to known_infra_ips.json.
        output_path: Destination path for private_ip_profiles.json.
        time_range: Elasticsearch date-math range string (default: now-7d).
        sensor: Sensor hostname or "all" for cross-sensor aggregate.
        workers: Number of concurrent IP profilers (each spawns 11 ES queries internally).
        force: Re-profile IPs already present in the sidecar.
    """
    if not os.path.exists(infra_path):
        console.print(f"[red]Infra registry not found: {infra_path}[/red]")
        console.print("[dim]Run the threat model generator first.[/dim]")
        return

    infra: list[dict] = load_json(infra_path)  # type: ignore[assignment]
    private_ips = [r["ip"] for r in infra if _is_rfc1918(r["ip"])]

    console.print(
        f"[dim]Found {len(private_ips):,} private IPs in infra registry "
        f"(total infra records: {len(infra):,})[/dim]"
    )

    # Load existing sidecar for incremental skip.
    existing: dict[str, dict] = {}
    if os.path.exists(output_path):
        loaded: list[dict] = load_json(output_path)  # type: ignore[assignment]
        existing = {r["ip"]: r for r in loaded if "ip" in r}
        console.print(f"[dim]Existing sidecar: {len(existing):,} profiles loaded[/dim]")

    to_profile = [ip for ip in private_ips if force or ip not in existing]
    skipped = len(private_ips) - len(to_profile)

    if skipped:
        console.print(
            f"[dim]Skipping {skipped:,} already-profiled IPs (use --profile-force to re-run)[/dim]"
        )

    if not to_profile:
        console.print("[green]All private IPs already profiled — nothing to do.[/green]")
        return

    console.print(
        f"[bold]Profiling {len(to_profile):,} private IPs[/bold]"
        f"  workers={workers}  sensor={sensor}  range={time_range}"
    )

    done = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_profile_one, ip, time_range, sensor): ip for ip in to_profile}
        for future in as_completed(futures):
            ip = futures[future]
            result = future.result()
            done += 1
            if result is not None:
                existing[ip] = result
            else:
                errors += 1

            if done % _PROGRESS_INTERVAL == 0 or done == len(to_profile):
                console.print(
                    f"[dim]  profiled: {done:,}/{len(to_profile):,}  errors: {errors}[/dim]"
                )

    # Write sidecar atomically.
    records = sorted(existing.values(), key=lambda r: r["ip"])
    tmp = output_path + ".tmp"
    dump_json(records, tmp)
    os.rename(tmp, output_path)

    console.print(
        f"[green]Done — {len(records):,} profiles written to {output_path}[/green]"
        f"  ({errors} errors skipped)"
    )
