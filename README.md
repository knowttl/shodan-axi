# shodan-axi

An agent-facing CLI for Shodan investigation, alerts and notifiers.
It supports SecretRef-based profiles, host and DNS inspection, search, counts, bounded statistics, historical and shared intelligence reads, and alert and notifier management.

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
Hosted use admits free reads, including alert and notifier reads, and refuses all writes before retrieving credentials; chargeable or unknown-cost reads and saved files are available through the native CLI.
`internetdb host` uses no API key; `myip --ipv6` requires an IPv6 transport and never falls back to IPv4.
Honeyscore and services remain source-only and unverified.
Trends and Exploits access and redirect behavior remain unverified against live services; `trends <query>`, `exploits search` and `exploits count` are unknown-cost reads.
For native Trends exports, choose `--save` for a query-derived filename or `--filename <path>` for an explicit destination.
Exports append gzip-compressed JSON lines with one record per month and nested facets; filenames end in `.json.gz`, and query-derived filenames replace spaces, `/` and `\` with `-` and end in `-trends.json.gz`.
Alert and notifier reads and writes are available through the native CLI.
Organization access is available with `org info`, `org add <email>` and `org remove <email>`.
An add notifies the member unless `--silent` is supplied; a removal preview reports the downgrade effect.
The `org info --credential-file <absolute-path>` option explicitly saves an issued credential to a protected local file without displaying it.
Writes require an exact operation grant, unknown-cost acceptance and request and credit bounds.
Run the desired command first to create a protected preview, then repeat it with the same arguments and `--execute --confirm <token>`.
For example, preview a removal with `shodan-axi alert remove <id> --allow-operation OP-015 --accept-unknown-cost --query-credit-budget 1 --max-requests 3`.
Set `SHODAN_AXI_READ_ONLY=true` to refuse execution before credential retrieval; previews remain available.
Plans bind the selected profile, credential, input, effects and observed state; uncertain sends are never automatically retried.
Confirmation tokens expire after 15 minutes and are consumed before dispatch.
Plans and the default `writes.log` journal live under `shodan-axi` in the absolute `XDG_STATE_HOME` directory, falling back to `~/.local/state`; Windows uses absolute `LOCALAPPDATA`, falling back to `~/AppData/Local`.
`SHODAN_AXI_WRITE_LOG` selects a private absolute journal path instead.
Execution lists every step as `verified`, `acknowledged-unverified`, `failed`, or `not-attempted`.
Definitively acknowledged mutations without a readback contract are journaled as `acknowledged-unverified` and allow ordered execution to continue; failed or ambiguous writes and failed or contradictory readbacks stop subsequent steps.
Notifier creation and updates use a private absolute `--body-file` containing JSON with an `args` object; creation also requires a provider.
`alert clear` previews a fixed snapshot of alerts to remove.
`alert domain <domain>` creates an alert from indexed IPv4 addresses on the first DNS page, reports whether more results exist, and does not track future DNS changes; use `--triggers` to override its default trigger bundle.
`alert import <absolute-path>` accepts a private JSON array or JSONL file, optionally gzip-compressed, and previews ordered notifier creation, alert creation, trigger, ignore and notifier attachment steps.
See [the generated command inventory](command-inventory.json) for command arguments, flags and operation grants.
Native commands contact the configured Shodan origin; offline verification uses controlled fakes, and live mutations require the owner's separate per-action approval.
Provider mutation encoding and live readback contracts remain unverified.

For offline verification, run `npm ci`, `npm run check`, then `npm run check:slice -- --id B3.2 --paths native,artium --offline --with-dependencies`.
The hosted check requires `ARTIUM_FIXTURE_ROOT` and `ARTIUM_FIXTURE_MANIFEST` to identify a matching local Artium build and installed package.
The JSON manifest supplies absolute `tarball`, `installedPackage`, `serverModule`, `clientExecutable` and `toolExecutable` paths, the tarball `sha256`, and the committed `artiumRevision`.
It fails if either path or matching coverage is unavailable.
Native Windows platform verification remains pending until run on Windows.
