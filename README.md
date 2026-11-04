# shodan-axi

An agent-facing CLI for Shodan investigation, scans, alerts, notifiers and organization membership.
It supports SecretRef-based profiles, host and DNS inspection, search, counts, bounded statistics, historical and shared intelligence reads, geographic active probes, scan submission and job inspection, and alert, notifier and organization membership management.

```sh
shodan-axi profile set default --env SHODAN_AXI_API_KEY
shodan-axi auth status
shodan-axi info
shodan-axi account profile
shodan-axi host 192.0.2.7
shodan-axi search 'port:443' --allow-operation OP-003 --query-credit-budget 1
shodan-axi query list --page 2 --sort votes --order asc
```

Use `--json` for JSON output.
The API key is supplied through the referenced environment variable or a private absolute file, never a command argument.
`doctor` makes one account information request and does not establish access to other API families.
Queries that may consume credits require an exact operation grant and a credit budget.
Unknown-cost reads also require `--accept-unknown-cost` and an explicit request cap.
Hosted use admits free reads and refuses all writes before retrieving credentials; chargeable or unknown-cost reads and saved files are available through the native CLI.
`internetdb host` uses no API key; `myip --ipv6` requires an IPv6 transport and never falls back to IPv4.
Honeyscore and services remain source-only and unverified.
Trends and Exploits access and redirect behavior remain unverified against live services; `trends <query>`, `exploits search` and `exploits count` are unknown-cost reads.
For native Trends exports, choose `--save` for a query-derived filename or `--filename <path>` for an explicit destination.
Exports append gzip-compressed JSON lines with one record per month and nested facets; filenames end in `.json.gz`, and query-derived filenames replace spaces, `/` and `\` with `-` and end in `-trends.json.gz`.
Alert and notifier reads and writes are available through the native CLI.
`parse <file>...` filters local JSON or gzip-compressed JSONL with repeated `--filters`, projects dotted `--fields`, and supports a custom `--separator`.
`convert <file> <format>` produces CSV, KML, GeoJSON (`geo.json`), XLSX or extracted JPEG images without credentials or network access.
Inputs are bounded to 1 MiB compressed and 10 MiB decompressed; outputs use private paths and existing conversion outputs are not overwritten.
`alert export` saves secret-free alert configuration as gzip JSONL.
`alert stats` uses free count-facet reads, normalizes overlapping networks and labels top-facet results partial.
Partial statistics saved to a file use a `.partial` suffix.
Hosted upload and file-based transformations are deferred pending a defined upload boundary.
Organization access is available with `org info`, `org add <email>` and `org remove <email>`.
The native `geonet ping`, `geonet geoping`, `geonet dns` and `geonet geodns` commands perform active probes without an API key.
Ping commands take an IP address; DNS commands take a hostname and accept `--type <record-type>` (default `A`).
Each requires its exact operation grant and request bound, followed by a protected preview and exact confirmation; observer locations are selected by the service.
For example, preview a DNS probe with `shodan-axi geonet dns example.test --type A --allow-operation OP-062 --max-requests 1`, then repeat the same request with `--execute --confirm <token>` after owner approval.
Probe confirmations bind the operation, target, DNS type, service origin and request bound.
GeoNet results preserve each observer's values without assigning undocumented units.
An uncertain probe returns `OUTCOME_UNKNOWN` and is never automatically retried.
Hosted execution refuses these active probes before retrieving credentials.
Use `scan protocols`, `scan list` and `scan status <id>` to inspect scan capabilities and jobs.
The status command can poll with `--poll-attempts`, `--poll-interval-ms` and an explicit `--max-requests` bound.
Scan list pagination is undocumented, so the response indicates whether the returned scope is complete without inventing a page parameter.
Native `scan submit <targets>` requires OP-009, a scan-credit budget sufficient for the conservative expanded target count and a request bound.
Targets are comma-separated IPv4 or IPv6 addresses or CIDR networks; `--force` requests a forced scan and is bound to the preview.
Overlapping targets count separately for the credit estimate.
`scan internet <port> <protocol>` requires OP-010, a scan-credit budget, a request bound and acceptance of unknown cost; the budget cannot bound a provider cost that is unknown.
Both commands preview their active effects and require exact confirmation before one submission; a returned scan ID does not mean that the job has finished.
Stream collection, vendor cancellation and saved scan results are not provided by these commands.
An organization membership add notifies the member unless `--silent` is supplied; a removal preview reports the downgrade effect.
Writes require an exact operation grant and request and credit bounds; unknown-cost writes also require `--accept-unknown-cost`.
Run the desired command first to create a protected preview, then repeat it with the same arguments and `--execute --confirm <token>`.
For example, preview a removal with `shodan-axi alert remove <id> --allow-operation OP-015 --accept-unknown-cost --query-credit-budget 1 --max-requests 3`.
Set `SHODAN_AXI_READ_ONLY=true` to refuse write and active probe execution before credential retrieval; previews remain available.
Write plans bind the selected profile, credential, input, effects and observed state; uncertain sends are never automatically retried.
Confirmation tokens expire after 15 minutes and are consumed before dispatch.
Plans and the default `writes.log` journal live under `shodan-axi` in the absolute `XDG_STATE_HOME` directory, falling back to `~/.local/state`; Windows uses absolute `LOCALAPPDATA`, falling back to `~/AppData/Local`.
`SHODAN_AXI_WRITE_LOG` selects a private absolute journal path instead.
Scan execution returns `submitted` with a scan ID and unknown completion, or `OUTCOME_UNKNOWN` when the submission cannot be confirmed.
Other write execution lists every step as `verified`, `acknowledged-unverified`, `failed`, or `not-attempted`.
For those writes, definitively acknowledged mutations without a readback contract are journaled as `acknowledged-unverified` and allow ordered execution to continue; failed or ambiguous writes and failed or contradictory readbacks stop subsequent steps.
Notifier creation and updates use a private absolute `--body-file` containing JSON with an `args` object; creation also requires a provider.
`alert clear` previews a fixed snapshot of alerts to remove.
`alert domain <domain>` creates an alert from indexed IPv4 addresses on the first DNS page, reports whether more results exist, and does not track future DNS changes; use `--triggers` to override its default trigger bundle.
`alert import <absolute-path>` accepts a private JSON array or JSONL file, optionally gzip-compressed, and previews ordered notifier creation, alert creation, trigger, ignore and notifier attachment steps.
See [the generated command inventory](command-inventory.json) for command arguments, flags, operation grants and public output schemas for free reads.
Those reads omit unknown vendor fields, including provider-issued credential fields, in both hosted and native output.
GeoNet contacts `https://geonet.shodan.io` independently of profile configuration; other native commands use the configured Shodan origin or their service-specific endpoints.
Offline verification uses controlled fakes; live mutations and active probes require the owner's separate per-action approval.
Provider mutation encoding and live readback contracts remain unverified.

For offline verification, run `npm ci`, `npm run check`, then `npm run check:slice -- --id B4.1 --paths native,artium --offline --with-dependencies`.
The hosted check requires `ARTIUM_FIXTURE_ROOT` and `ARTIUM_FIXTURE_MANIFEST` to identify a matching local Artium build and installed package.
The JSON manifest supplies absolute `tarball`, `installedPackage`, `serverModule`, `clientExecutable` and `toolExecutable` paths, the tarball `sha256`, and the committed `artiumRevision`.
It fails if either path or matching coverage is unavailable.
Native Windows platform verification remains pending until run on Windows.
