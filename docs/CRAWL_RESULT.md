# Shared crawl-result contract

TorBot exposes a versioned, machine-readable crawl result through
`LinkTree.to_crawl_result()`. It is an integration contract, not a replacement
for the existing tree JSON saved by `--save json`; that legacy format remains
available through the 4.x series. Consumers must feature-detect
`schemaVersion` and reject versions they do not understand.

## Version 1

The top-level object contains `schemaVersion`, a unique `runId`, `engine` and
`engineVersion`, normalized `target`, effective `settings`, terminal status,
timestamps, `durationMs`, `pages`, and privacy-safe `diagnostics`.

Each page records `url`, `parentUrl`, `depth`, `outcome`, HTTP `status`,
`skippedReason`, bounded `errorCategory`, extracted `links`, and `contacts`.
`outcome` is `fetched` or `failed`; failures expose one of `cancelled`,
`invalid_input`, `network`, `parse`, or `unknown`, never an exception message.
Links and contacts include their source (`anchor`, `mailto`, or `tel`). Raw
HTML, headers, cookies, credentials, and arbitrary exception strings are not
part of the contract.

When a caller explicitly requests analysis-ready output, a fetched page may
also include a `title`, deterministic classification metadata, and `content`.
Content contains bounded visible plain text and its SHA-256 digest. Scripts,
styles, templates, and raw markup are excluded. The CLI exposes this form only
through `--save result`; legacy `--save json` behavior is unchanged.

GoTor's versioned report is the compatibility baseline: both projects use
`schemaVersion: 1`, `engine`, `target`, depth/settings, timestamps, duration,
and per-page URL/parent/depth/status/link information. TorBot's fields are
additive where GoTor's current report has no equivalent (`runId`, terminal
state, provenance, bounded errors, and diagnostics). Consumers should retain
unknown fields and branch only on the schema version, not on engine-specific
internals.

## Deprecation path

No existing CLI output changes in this issue. A future major release may mark
the legacy tree JSON as deprecated only after the shared result is available
from an explicit CLI/API surface and downstream consumers have migrated.
