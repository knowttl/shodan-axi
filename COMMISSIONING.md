# Commissioning checklist

Offline tests establish behavior against synthetic services, not entitlement or compatibility with the live service.
Record the package version and SHA-256, Artium revision and inventory hashes, operating system, runtime versions, date, operator, and each result without recording credentials or signed URLs.
Mark every check that cannot be performed as pending.

## Release preparation

- [ ] Run `npm ci`, `npm run check`, and `npm run check:slice -- --id B6.1 --paths native,artium --offline --with-dependencies` with a matching Artium fixture.
- [ ] Inspect the packed tarball, executable, credential schema, generated inventory and skill.
- [ ] Verify setup in disposable Claude Code, Codex and OpenCode homes, including a second install and ordinary command behavior.
- [ ] Run the applicable checks on Windows, Linux and an unprivileged Artium container; record platform and runtime versions.
- [ ] Verify the final Artium package and inventory pins and reject a mismatched pin before credential retrieval.
- [ ] Obtain separate authorization to publish the package, and record the published version and integrity before updating the companion pin.

## Live checks

Each live action requires prior authorization for its exact operation, target, effect, maximum requests, credits, bytes and duration, and any notification, readback and cleanup.
Do not reuse a general release approval as authorization for a scan, probe, stream, download or mutation.
Use a dedicated account and approved test targets, and stop on an unexpected response or uncertain outcome.

- [ ] For each approved free read, run the packaged standalone command and the corresponding hosted command against the same authorized identity and bounded selection; compare the selected fields and record request limits and outcomes.
- [ ] For each approved chargeable read, record its query and credit budget before dispatch and compare the returned rows, total and continuation independently.
- [ ] For each approved mutation, record the preview and exact confirmation, send once, read back the selected resource, and execute the separately approved cleanup.
  Record uncertain sends without retrying them automatically.
- [ ] For an approved scan or geographic probe, record the exact target, protocol, port, budget and expected effect before dispatch; retain the job identity and perform only the approved readback and cleanup.
- [ ] For an approved stream, record the selectors, bounds, duration, credential and session policy; verify stop and cleanup, and report lost ranges or upstream interruption.
- [ ] Repeat relevant discovery observations through both finished public paths with explicit bounds and compare results to retained observations.
  Treat access denials and redirects as failures, not empty results; do not bypass or automatically retry them.

Dataset downloads remain disabled until a storage-host list is reviewed and implemented.
Trends, Exploits, InternetDB, source-only routes, PUT encoding and readback variants require separate current-provider evidence where their contracts or access remain unverified.
No pending or failed live check is a passed commissioning result.
