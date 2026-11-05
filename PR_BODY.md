Adds a manually dispatched release workflow and release-please configuration.
See the [commissioning checklist](COMMISSIONING.md#release-preparation) for release preparation and publishing instructions.

Previous offline validation covered the native dependency suite, generated inventory and skill, disposable setup homes, and hosted reads and sessions against isolated fake services.
The previous B6.1 gate passed as sequential native, hosted-worker, hosted session/read and remaining release groups.
That evidence applies to `@knowttl/shodan-axi` 0.11.0 with SHA-256 `60bd81df77d1c73190ae9c062735048493cea5c35b0214790dc08eb75753420f`, paired with Artium revision `30b6f882dce04b665656452fe65b60b3464b2e1c`, rather than the current package.
Windows and live-provider checks remain pending.
