# shodan-axi

An agent-facing CLI for Shodan account information.
This initial slice supports account reads and SecretRef-based profiles.

```sh
shodan-axi profile set default --env SHODAN_AXI_API_KEY
shodan-axi auth status
shodan-axi info
shodan-axi account profile
```

Use `--json` for JSON output.
The API key is supplied through the referenced environment variable or a private absolute file, never a command argument.
`doctor` makes one account information request and does not establish access to other API families.
The tool does not run scans or change account settings in this slice.

For offline verification, run `npm ci`, `npm run check`, then `npm run check:slice -- --id B1.1 --paths native,artium --offline --with-dependencies`.
The hosted check requires `ARTIUM_FIXTURE_ROOT` and `ARTIUM_FIXTURE_MANIFEST` to identify a matching local Artium build and installed package.
The JSON manifest supplies absolute `tarball`, `installedPackage`, `serverModule`, `clientExecutable` and `toolExecutable` paths, the tarball `sha256`, and the committed `artiumRevision`.
It fails if either path or matching coverage is unavailable.
Native Windows platform verification remains pending until run on Windows.
