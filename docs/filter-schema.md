# Filter Schema

Filters are YAML files that map directly to Elasticsearch DSL `must_not` clauses. The filter loader merges all enabled files into the query at runtime, suppressing matching events before results are returned.

## File Header

Every filter file must begin with this header:

```yaml
description: <human-readable summary>
author: <analyst name or handle>
date_added: 'YYYY-MM-DD'
category: <ips | signatures | ports | composite>
subcategory: <name matching an entry in categories.yaml>
enabled: true
must_not:
  - ...
```

| Field | Required | Notes |
|---|---|---|
| `description` | Yes | One-line summary shown in `--list` output |
| `author` | Yes | Who created the filter |
| `date_added` | Yes | ISO date string |
| `category` | Yes | Must match a top-level key in `categories.yaml` |
| `subcategory` | Yes | Must match a subcategory list entry in `categories.yaml` |
| `enabled` | Yes | Set to `false` to disable without deleting |
| `must_not` | Yes | List of ES DSL clauses (see below) |

---

## Clause Types

### `term` — exact match on a single value

```yaml
must_not:
  - term:
      src_ip: 198.235.24.220
    comment: Cortex Xpanse scanner
```

### `terms` — exact match on any value in a list

```yaml
must_not:
  - terms:
      src_ip:
        - 71.6.135.131
        - 71.6.165.200
        - 85.214.149.236
```

### `match_phrase` — substring/phrase match (used for signature text)

```yaml
must_not:
  - match_phrase:
      alert.signature: SURICATA AF-PACKET truncated packet
```

### `range` — numeric or date bounds

```yaml
must_not:
  - range:
      alert.severity:
        gte: 3
```

### `bool` composite — combine conditions (IP + port, IP + signature)

```yaml
must_not:
  - bool:
      must:
        - term:
            src_ip: 192.168.1.100
        - term:
            dest_port: 53
```

---

## Optional `comment` Field

Any clause may include a `comment` key. It is stripped by the filter loader before the clause is sent to Elasticsearch — it exists only for human context in the YAML file.

```yaml
must_not:
  - term:
      src_ip: 23.44.175.9
    comment: Akamai Technologies Cloud Services — GreyNoise benign
```

---

## Categories

Categories and subcategories are registered in `filters/categories.yaml`. A filter file's `category`/`subcategory` fields must match entries there, or the filter loader will skip the file.

```yaml
# filters/categories.yaml
categories:
  ips:
    subcategories:
      - known_scanners           # Internet-wide research scanners (Censys, Shodan, etc.)
      - known_bad_blocked        # Confirmed malicious IPs already actioned or blocked
      - network-misconfigurations  # Misconfigured devices generating recurring noise
      - normal-flagged-traffic   # Benign traffic that routinely trips signatures
      - internal_ranges          # RFC 1918 ranges specific to a city (use --public-only instead where possible)
  signatures:
    subcategories:
      - et_scan_suppression      # High-frequency ET SCAN rules with no triage value
      - dns_noise                # DNS amplification/NXDOMAIN noise
      - network-misconfiguration # SURICATA internal engine messages
  ports:
    subcategories:
      - common_services          # High-port ephemeral or expected service traffic
  composite:
    subcategories:
      - bonney_lake_internal     # City-specific multi-field suppressions
```

To add a new subcategory, either:
- Run `fp_manager.py` interactively — it will prompt to register new subcategories automatically
- Or add the entry to `categories.yaml` manually, then create the YAML file in the matching directory

---

## Adding a New Filter File Manually

1. Choose the correct category directory (`filters/ips/`, `filters/signatures/`, etc.)
2. Name the file after the subcategory: `<subcategory>.yaml`
3. Write the header and `must_not` clauses following the schema above
4. Ensure the `subcategory` value is registered in `filters/categories.yaml`
5. Run the querier — filters are reloaded on every search, no restart needed

### Example: suppressing a new known scanner

```yaml
# filters/ips/known_scanners.yaml  (append to existing file, or create a new one)
description: ips / known_scanners false positive filters
author: analyst
date_added: '2026-02-22'
category: ips
subcategory: known_scanners
enabled: true
must_not:
  - term:
      src_ip: 66.132.153.125
    comment: Censys
  - term:
      src_ip: 205.210.31.44
    comment: Lithuania - serveoffer.it scanner
```
