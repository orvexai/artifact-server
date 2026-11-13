# Vendored Unicode confusables data

Artifact Server vendors the Unicode 17.0.0 UTS #39 confusables table to build
identity skeletons in `src/core/confusables.ts`. The runtime imports the
generated JSON and does not read files, contact the network, or depend on a
third-party confusables package.

## Pinned source

- Source: https://www.unicode.org/Public/security/17.0.0/confusables.txt
- Standard: Unicode Technical Standard #39, Unicode Security Mechanisms:
  https://www.unicode.org/reports/tr39/
- Version/date in source header: 17.0.0 / 2025-07-22
- SHA-256 of `confusables.txt`:
  `091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a`
- SHA-256 of generated `confusables-data.json`:
  `c5172e647efd550afb93b49d9e4d7afdabef59794be136cc921010674fc41383`
- Included mappings: 6,565 single-codepoint MA mappings

The tests pin both hashes and the Unicode version.

## Regeneration

The deterministic developer script reads the checked-in source and writes the
checked-in JSON:

```sh
node scripts/build-confusables-data.mjs
```

Review the generated JSON diff and run the focused tenant identity tests after
regenerating. Do not edit the generated JSON by hand.

## License

Unicode data is distributed under Unicode License V3:
https://www.unicode.org/license.txt and https://www.unicode.org/terms_of_use.html.
Keep the upstream copyright and license notice in the vendored source file.
