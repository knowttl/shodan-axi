Adds bounded search and alert result exports and dataset listings that omit signed URLs.

Real dataset retrieval is deferred for this release by owner decision.
The approved storage-host list is empty, so packaged `data download` refuses before credential access or network requests.
Transfer logic is covered directly through the exported internal module with an injected offline policy; installed-package tests assert refusal through the unmodified package.
