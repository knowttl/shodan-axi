# shodan-axi

Shodan investigation and gated operations for agents and the humans running them.

[![npm](https://img.shields.io/npm/v/%40knowttl%2Fshodan-axi)](https://www.npmjs.com/package/@knowttl/shodan-axi) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![Node](https://img.shields.io/node/v/%40knowttl%2Fshodan-axi)](package.json) [![npm provenance](https://img.shields.io/npm/provenance/%40knowttl%2Fshodan-axi)](https://www.npmjs.com/package/@knowttl/shodan-axi#provenance)

[Why](#why-this-exists) · [Quickstart](#quickstart) · [Agent setup](#use-with-your-agent) · [Coverage](#what-it-covers) · [Safety](#safety) · [Configuration](#configuration) · [Commands](#commands) · [Contributing](#contributing) · [License](#license)

## Why this exists

Shodan investigations can involve multiple services, credit costs and operations that change remote state.
shodan-axi provides bounded reads, compact TOON output and explicit previews and confirmations for protected operations.
It uses the selected account's access and does not grant Shodan permissions.

## Quickstart

Requires Node.js >=24.14.0 and <25, and npm >=11.9.0 and <12.
Install the CLI and inspect local profiles:

```sh
npm install --global @knowttl/shodan-axi
shodan-axi profile list --json
```

With no saved profiles, the output is:

```json
{"profiles":[]}
```

Supply `SHODAN_AXI_API_KEY` through your secret manager, then create a profile referencing the variable and run a read:

```sh
shodan-axi profile set default --env SHODAN_AXI_API_KEY
shodan-axi auth status --profile default
shodan-axi host 192.0.2.7 --profile default
```

Replace the example IP with the address to investigate; results depend on Shodan's index and your account.
For a one-off installation, use `npx -y @knowttl/shodan-axi profile list`.

## Use with your agent

Install the session integration for the agent you use:

```sh
shodan-axi setup claude
shodan-axi setup codex
shodan-axi setup opencode
```

Claude and Codex run local authentication status at session start; OpenCode injects it into system context.
Setup writes Claude's `settings.json` under `CLAUDE_CONFIG_DIR` (default `~/.claude`), Codex's `hooks.json` and enables `features.hooks` in `config.toml` under `CODEX_HOME` (default `~/.codex`), or OpenCode's `opencode/plugins/shodan-axi.js` under `XDG_CONFIG_HOME` (default `~/.config`).
Restart the agent session after setup.
For on-demand guidance, install `npx skills add knowttl/shodan-axi --skill shodan-axi` or read the [packaged skill](skills/shodan-axi/SKILL.md).
`shodan-axi skill` prints the packaged skill.
These integrations grant no Shodan permissions.
To remove them, delete only the shodan-axi SessionStart hook from Claude's `settings.json` or Codex's `hooks.json`, or remove OpenCode's `opencode/plugins/shodan-axi.js` under its configuration root.
Preserve unrelated settings; Codex's `features.hooks` setting may be shared with other hooks.
Run setup again after relocating the executable to update its recorded absolute path.

## What it covers

| Group | Purpose | Access |
| --- | --- | --- |
| `host`, `search`, `count`, `stats`, DNS and query commands | Investigate indexed hosts and intelligence | Reads; some require credit grants |
| `stream`, `radar`, `threatnet`, `download` | Bounded streams and exports | Protected operations |
| `alert`, `notifier`, `org` | Manage alerts, notifiers and organization membership | Reads and gated writes |
| `scan`, `geonet` | Inspect scan jobs and perform active probes | Reads and gated active operations |
| `parse`, `convert` | Filter and convert local files | Local |
| `profile`, `auth`, `setup` | Configure credentials and agent integration | Local |

Run a command with `--help` for its arguments and flags; the [command inventory](command-inventory.json) records operation grants and output schemas.

## Safety

Writes and active probes preview first and require an exact operation grant, bounds and confirmation before execution.
Some reads consume credits or have unknown cost and require explicit grants and budgets.
Set `SHODAN_AXI_READ_ONLY=true` to refuse write, probe, stream and search export execution; previews remain available.
In read-only mode, writes and active probes are refused before credential retrieval.
Credentials use environment or private file references, never command arguments.
Network commands send requests to Shodan services using the selected profile and account permissions; local `parse` and `convert` need neither credentials nor network access.
Treat output and saved investigation data as sensitive.

## Configuration

`shodan-axi config path` prints the effective profile path.
On Linux and macOS the default is `~/.config/shodan-axi/config.json`, with an absolute `XDG_CONFIG_HOME` overriding the root; Windows uses `%APPDATA%\shodan-axi\config.json` or `~/AppData/Roaming/shodan-axi/config.json`.
`SHODAN_AXI_CONFIG` overrides the path and `SHODAN_AXI_PROFILE` selects a profile; command-specific `--config` and `--profile` take precedence.
Profiles reference an environment variable or private absolute file containing the API key.

## Commands

These examples illustrate common reads:

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

Account and investigation HTTP errors include the service hostname, status and sanitized vendor reason when available.
Their structured output includes `error`, `message` and `help`, plus `retryAfterSeconds` when a valid `Retry-After` header is supplied, including on errors other than rate limits.
Retry waits use seconds; HTTP dates are converted to a nonnegative wait.

`doctor` makes one account information request and does not establish access to other API families.
Queries that may consume credits require an exact operation grant and a credit budget.
Unknown-cost investigation reads also require `--accept-unknown-cost` and an explicit request cap; stream bounds are described below.
Ordinary hosted command dispatch admits free reads and refuses all writes before retrieving credentials; chargeable or unknown-cost reads and saved files are available through the native CLI.
`internetdb host` uses no API key; `myip --ipv6` requires an IPv6 transport and never falls back to IPv4.
Honeyscore and services remain source-only and unverified.
Trends and Exploits access and redirect behavior remain unverified against live services; `trends <query>`, `exploits search` and `exploits count` are unknown-cost reads.
For native Trends exports, choose `--save` for a query-derived filename or `--filename <path>` for an explicit destination.
Exports append gzip-compressed JSON lines with one record per month and nested facets; filenames end in `.json.gz`, and query-derived filenames replace spaces, `/` and `\` with `-` and end in `-trends.json.gz`.
Alert and notifier reads and writes are available through the native CLI.
`parse <file>...` filters local JSON or JSONL, optionally gzip-compressed, with repeated `--filters <field:value>`, projects dotted `--fields`, and supports a custom `--separator`.
Every filter must match; `net:<CIDR>` matches `ip_str`, strings use substring matching, and numbers, booleans and array elements use exact matching.
With `--filename <path>`, parsing requires a filter and appends matching full records, rather than projected fields, to gzip JSONL with a `.json.gz` suffix.
`convert <file> <format>` produces CSV (`csv`), KML (`kml`), GeoJSON (`geo.json`), XLSX (`xlsx`) or extracted JPEG images (`images`).
Each input file is bounded to 1 MiB on disk, including uncompressed files, and gzip input is bounded to 10 MiB decompressed; outputs use private paths and existing conversion outputs are not overwritten.
`alert export` saves secret-free alert configuration as gzip JSONL.
`alert stats` uses free count-facet reads, normalizes overlapping networks and labels top-facet results partial.
Partial statistics saved to a file use a `.partial` suffix.
Hosted upload and file-based transformations are deferred pending a defined upload boundary.
`data list` lists datasets; `data list --dataset <name>` lists file metadata without exposing signed URLs.
Real dataset retrieval is deferred for this release by owner decision.
The approved storage-host list is empty, so packaged `data download` refuses before credential access or network requests.
`download <query>` and `alert download` preview the selected query, destination, size and credit bounds before requiring exact confirmation.
Their confirmations bind the previewed result count and available query credits, which are checked again before export.
The generated inventory's `hostedWrites.budgetRules` maps each approved command to its budget rule, and `hostedWrites.budget` supplies the ceilings.
For mutation rules, the minimum query credits are the greater of one and `creditPerStep * steps + extraCredits`; the minimum requests are `requestPerPrecondition * preconditions + max(requestsPerStep * steps, minimumRequests) + extraRequests`.
Steps and preconditions are the selected mutation plan's counts; domain preflight additionally requires `creditsPerTrigger * triggers + extraCredits` credits and `minimumRequests` requests before DNS lookup.
For downloads, the minimum query credits are the result limit divided by `resultsPerCredit`, rounded up, and the minimum requests are those credits plus `searchOverheadRequests`.
Alert downloads also require requests at least equal to the supplied query credit budget plus `requestsPerNetwork * selected networks + alertOverheadRequests`.
These native exports require `--allow-operation OP-003`, `--query-credit-budget`, `--max-requests`, `--max-bytes`, `--limit` and `--filename`.
`alert download` exports the union of monitored networks from all alerts, or one alert selected with `--alert-id <id>`.
These exports save gzip JSONL, append `.json.gz` to the destination if needed, and refuse to overwrite existing output.
Export execution reports `total: null` when bounds prevent visiting every selected network; otherwise `total` covers the full selection.
The execution `requests` count includes search requests and, for `alert download`, the alert-selection request; it excludes requests from the separate preview invocation.
Exports that stop before all results are saved, or include provider-truncated records, report `complete: false` and retain a `.partial` suffix, even when `--fields` omits truncation metadata.
Hosted execution refuses chargeable exports and dataset transfers before retrieving credentials.
Native `stream` supports one of `--asn`, `--countries`, `--ports`, `--vulns`, `--custom-filters`, `--alert` or `--tags`, or the unfiltered banner stream.
Use comma-separated dotted `--fields` to select event fields and `--quiet` to suppress event output while retaining the final accounting.
For buffered output, `--separator` or `--color` or `--no-color` adds a text view; JSON output includes it as `display`.
`threatnet events`, `threatnet backscatter` and `threatnet ssh` select the separate Threatnet streams.
Streams require an exact `--allow-operation`, `--accept-unknown-cost`, `--limit`, `--max-bytes`, `--timeout` and `--idle-timeout`, followed by the same protected preview and confirmation used for other active operations.
Timeouts use milliseconds; the idle timer starts at dispatch and resets on each incoming chunk, including debug records and SSE keepalives.
Every stream execution ends with one summary carrying the approved `limit`, `maxBytes`, `timeout` and `idleTimeout`, accepted event `count`, consumed `bytes`, stop reason, discarded debug count and incomplete record count.
Execution failures attach their error to that summary and exit nonzero; connections are never automatically retried.
Native `--follow` requires `--json` or `--output json`, an absolute `--datadir`, `--max-file-bytes` and `--retain`; it emits one JSON object containing `event` per accepted record unless `--quiet` is set, followed by the summary.
Field selection affects emitted events; follow storage retains full records even with `--fields` or `--quiet`.
Native `radar` uses the same stream selectors and bounds, renders a map in an interactive terminal and stops on `q`.
For non-interactive use, the result includes a bounded map snapshot; `--filename` saves that snapshot to a private absolute path.
Follow mode retains the same read bounds; gzip JSONL files rotate by UTC day or compressed file size, and `--retain` bounds the number of retained stream files.
`--compresslevel` accepts 0 through 9, defaults to 6 and applies across rotations.
Ordinary hosted command dispatch refuses stream operations before retrieving credentials; supervised sessions use the Artium companion protocol described below.
Threatnet event schemas and tag-filtered stream availability remain unverified against the live service.
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
For bounded collection, add a positive `--wait` in seconds, `--limit`, `--max-bytes` and `--idle-timeout` in milliseconds.
Omitting `--wait` or supplying a nonpositive integer submits immediately without collection.
Targeted collection also requires OP-013, OP-015 and OP-053, an unknown-cost acceptance, a query-credit budget of at least 8 and at least 10 requests; its preview includes a temporary alert and its cleanup.
Use `--verbose` on targeted collection to add a JSONL display of collected events to the final output.
Internet collection requires OP-049 and at least two requests; `--quiet` suppresses returned events while retaining scan accounting, submission and optional file output.
The optional absolute `--filename` saves matching results as gzip JSONL.
Results are deduplicated by address, port and transport and filtered to the requested targets or port.
The stream reports matching observations, not proof that the scan produced them, and stopping collection does not cancel the vendor scan.
Cleanup failure reports the temporary alert identifier and preserves the scan ID and collected results.
If temporary alert creation loses its response, scan collection reports `cleanup: unknown` and a generated `reconciliation.alertName`; use `alert list` to find and inspect that exact name, then preview and confirm removal by ID before retrying.
An organization membership add notifies the member unless `--silent` is supplied; a removal preview reports the downgrade effect.
Writes require an exact operation grant and request and credit bounds; unknown-cost writes also require `--accept-unknown-cost`.
Run the desired command first to create a protected preview, then repeat it with the same arguments and `--execute --confirm <token>`.
For example, preview a removal with `shodan-axi alert remove <id> --allow-operation OP-015 --accept-unknown-cost --query-credit-budget 1 --max-requests 3`.
Write plans bind the selected profile, credential, input, effects and observed state; uncertain sends are never automatically retried.
Confirmation tokens expire after 15 minutes and are consumed before dispatch.
Plans and the default `writes.log` journal live under `shodan-axi` in the absolute `XDG_STATE_HOME` directory, falling back to `~/.local/state`; Windows uses absolute `LOCALAPPDATA`, falling back to `~/AppData/Local`.
`SHODAN_AXI_WRITE_LOG` selects a private absolute journal path instead.
Without collection, scan execution returns `submitted` with a scan ID and unknown completion, or `OUTCOME_UNKNOWN` when the submission cannot be confirmed.
Other write execution lists every step as `verified`, `acknowledged-unverified`, `failed`, or `not-attempted`.
For those writes, definitively acknowledged mutations without a readback contract are journaled as `acknowledged-unverified` and allow ordered execution to continue; failed or ambiguous writes and failed or contradictory readbacks stop subsequent steps.
Notifier creation and updates use a private absolute `--body-file` containing JSON with an `args` object; creation also requires a provider.
`alert clear` previews a fixed snapshot of alerts to remove.
`alert domain <domain>` creates an alert from indexed IPv4 addresses on the first DNS page, reports whether more results exist, and does not track future DNS changes; use `--triggers` to override its default trigger bundle.
`alert import <absolute-path>` accepts a private JSON array or JSONL file, optionally gzip-compressed, and previews ordered notifier creation, alert creation, trigger, ignore and notifier attachment steps.
See [the generated command inventory](command-inventory.json) for command arguments, flags, operation grants and public output schemas for free reads.
Those reads omit unknown vendor fields, including provider-issued credential fields, in both hosted and native output.
GeoNet contacts `https://geonet.shodan.io` independently of profile configuration.
Streams use the selected profile's `streamOrigin`, defaulting to `https://stream.shodan.io`; other native network commands use the configured Shodan origin or their service-specific endpoints.
Offline verification uses controlled fakes; live mutations and active probes require the owner's separate per-action approval.
Provider mutation encoding and live readback contracts remain unverified.

## Contributing

For offline verification, run `npm ci`, `npm run check`, then `npm run check:slice -- --id B6.1 --paths native,artium --offline --with-dependencies`.
The hosted check requires `ARTIUM_FIXTURE_ROOT` and `ARTIUM_FIXTURE_MANIFEST` to identify a matching local Artium build and installed package.
Hosted reads also require Docker and a prebuilt local `artium-test-node24` image, overridable with `ARTIUM_TEST_IMAGE`; the check runs it without network access as an unprivileged user and never pulls it.
See [the commissioning checklist](COMMISSIONING.md) for release evidence and separately authorized live checks.
The Artium companion owns session admission, authorization and revision rechecks, quotas, replay accounting, revocation and private-directory cleanup; this package owns the worker protocol.
The companion must launch the worker with a private inherited duplex fd 3 and send the first JSONL frame as `{ "version": 1, "type": "admit", "requestId": "<unique>", "admission": "<session-random-binding>", "profilePath": "<private-absolute-path>" }`.
The binding must contain 32 to 128 characters and appear as `admission` on every `start` and `extend` frame after the host has authorized that operation; duplicate admission, missing admission and mismatched bindings terminate the worker.
Protocol failures during streaming cancel active work and attach the error to the final `closed` frame while preserving stream progress counters.
The profile must be private, contain exactly the default profile `artium`, and use an API key SecretRef named `ARTIUM_SECRET_<n>`; the worker reads only this profile and never selects ambient credentials or origin overrides.
The host must provide only its selected secret and trusted runtime settings, isolate the inherited channel from callers, and create the confirmation plan using that same private profile and selected secret before sending `start`.
The channel is a trusted host-to-child boundary, not a public authorization endpoint or proof of host identity against another process with the same OS privileges.
Existing Artium launchers must add this handshake and admission fields before using this worker; the pinned real-host conformance check must pass with that companion change before delivery.
The JSON manifest supplies absolute `tarball`, `installedPackage`, `serverModule`, `clientExecutable` and `toolExecutable` paths, the tarball `sha256`, and the committed `artiumRevision`.
It fails if either path or matching coverage is unavailable.
Native Windows platform verification remains pending until run on Windows.

## License

[MIT](LICENSE).
