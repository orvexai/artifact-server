# Vendored data — Unicode confusables table (UTS #39)

This project vendors the official Unicode **confusables** table, used by
`confusables.js` for homoglyph / look-alike detection and skeleton computation.

## Provenance (pinned)

| field | value |
| --- | --- |
| File | `confusables.txt` (byte-exact, as fetched) |
| Source URL | https://www.unicode.org/Public/security/latest/confusables.txt |
| Standard | Unicode Technical Standard #39 (UTS #39), *Unicode Security Mechanisms* — see https://www.unicode.org/reports/tr39 |
| **Unicode version** | **17.0.0** (pinned) |
| File date (from header) | 2025-07-22 |
| Fetched | 2026-07-21 via public HTTPS GET |
| SHA-256 of `confusables.txt` | `091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a` |
| Entries parsed | 6565 single-codepoint → prototype mappings (all type `MA`) |

The pinned version is asserted in the test suite (`UNICODE_VERSION === '17.0.0'`),
so a silent data swap fails CI.

## License

The Unicode data files are distributed under the **Unicode License V3** (a
permissive, BSD-style license — free to use, copy, modify, and redistribute with
attribution and the license notice). Terms of use:
https://www.unicode.org/terms_of_use.html and
https://www.unicode.org/license.txt

This is compatible with this project's MIT license. Unicode® and the Unicode Logo
are registered trademarks of Unicode, Inc.

## How the data is used at runtime (no filesystem in the core)

We ship **two** files and pick the pre-parsed-JSON strategy the task allows:

1. `confusables.txt` — the raw, byte-exact official file. It is the **provenance
   artifact**: a reviewer can diff it against unicode.org and recompute the hash
   above. It is **not** read at runtime.
2. `confusables-data.json` — a compact, checked-in, pre-parsed module
   (`{ unicodeVersion, map }`, where `map` is `sourceCodepoint → [prototype,
   officialName]`). The pure `confusables.js` core `require()`s this JSON.

**Why pre-parsed JSON instead of a require-time text loader:** the core modules in
this project must be pure — no filesystem, no DOM, no network. A loader that read
`confusables.txt` with `fs.readFileSync` would put filesystem I/O in the core.
Bundling the data as JSON through `require()` keeps `confusables.js` free of any
I/O call of our own.

## Reproducing `confusables-data.json`

The JSON is generated from the vendored `confusables.txt` by a dev-time build
script (the only file in the project that touches the filesystem, never imported
by the library or its tests):

```sh
node scripts/build-confusables-data.mjs
```

The small checked-in build loader parses only the pinned MA mappings and rejects
unexpected table counts. Re-running it against the same `confusables.txt`
reproduces `confusables-data.json`.
