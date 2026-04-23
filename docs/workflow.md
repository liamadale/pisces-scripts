# Analyst Workflow — Web UI

A typical triage session using the OpenSearch web app from launch to resolution.

For the terminal-based querier workflow, see [cli-workflow.md](cli-workflow.md).

---

## 1. Launch and open the overview

Start the web UI if it isn't already running:

```bash
uv run run_all.py
```

Open **http://localhost:5000** and navigate to **OpenSearch**. The overview page shows
a cross-protocol IP activity matrix — every source IP seen in the selected time window,
with hit counts across all log type categories (alerts, network, web, remote access,
auth, messaging, and file activity).

Use the search bar at the top to scope the view:

| Control | Purpose |
|---|---|
| **Time** | Time window to query (last 1h, 6h, 24h, 7d, etc.) |
| **Sensor** | Filter to one or more sensors, or browse active sensors with the list button |
| **Src IP** | Narrow to a specific source IP |
| **Direction** | Filter by traffic direction: inbound, outbound, internal, external |
| **Public only** | Check to exclude RFC 1918 / private addresses from results |
| **Limit** | Maximum number of raw records to fetch before deduplication |

Click any column header to sort. The **TOTAL** column sorts by overall activity across
all log types.

---

## 2. Investigate an IP

**Click a count cell** to go directly to the log view for that IP and protocol — e.g.
clicking the `conn` count for an IP opens the connection log filtered to that IP.

**Click an IP address** to open the IP pivot view — all protocol records for that
address stacked in one page. From here:

- Click **Enrich** (public IPs) to run the full threat intelligence pipeline — GreyNoise,
  AbuseIPDB, Shodan, and VirusTotal results appear inline with reference links
- Click **Profile Device** (private/RFC 1918 IPs) to generate a device activity profile
- Click **Full view** on any protocol section to open the full log view for that protocol

---

## 3. Inspect a record

In any table — overview, IP pivot, or log view — **click a row** to open the record
detail panel on the right. The panel shows:

- **Field details** — protocol-specific key-value breakdown for the record
- **Create FP Filter** — opens an inline form to suppress this IP. Select a category
  and subcategory, optionally add a comment, and submit. The filter is written
  immediately and will take effect on the next search
- **Mantis Tickets** — buttons to search for existing tickets by source IP, destination
  IP, or alert signature. Results appear inline without leaving the page
- **Enrich / Profile Device** — per-IP threat intelligence or device profile, one button
  each for source and destination

Click the same row again or press **Escape** to close the panel.

---

## 4. Drill into a protocol

Use the left sidebar to jump to any protocol log directly. Some protocol views open in
**summary mode** first — for example, alerts show rule name groups by frequency before
you drill into individual records. Click a summary item to filter to those records.

The search bar persists across pages — your time range, sensor, and IP filter carry
over when you navigate between views.

---

## 5. Share a view

The share button in the search bar generates shareable links:

- **Copy PISCES link** — a URL that opens this exact view (time range, sensor, IP
  filter, protocol) in PISCES for another analyst
- **Copy Dashboards link** — a shortened link to the equivalent view in Malcolm
  OpenSearch Dashboards
- **Open in Dashboards** — opens the Dashboards view directly in a new tab

---

## Typical session patterns

### Spot and suppress a noisy scanner

```
Overview → IP with high conn count → click IP → Enrich
  GreyNoise: benign, Censys → click a conn row → Create FP Filter
  category: ips / known_scanners, comment: Censys
Search again → IP is gone
```

### Check for an existing ticket before triaging

```
Click a row → detail panel → Mantis Tickets → click src IP button
  Existing ticket found → review admin note verdict → close panel
```

### Investigate a specific sensor's traffic

```
Search bar: Sensor → browse modal → select hedgehog-example-city → Search
Overview now scoped to that sensor's source IPs only
```

### Share a filtered view with another analyst

```
Set time range, sensor, Src IP → Share button → Copy PISCES link → paste in chat
```
