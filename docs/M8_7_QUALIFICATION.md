# M8.7 qualification — XVS and VirusZ support artifacts

## Result

**Real support artifacts identified and content-qualified. Scanner-consumption runtime qualification remains pending.**

The user supplied the original LHA distribution archives for `xvs.library` and `VirusZ_III.Bootblocks`. AAA qualification records the archive identity, exact archive member, decompressed member size, member CRC-16 and SHA-256 without committing the third-party binaries themselves.

## xvs.library

Distribution archive:

- archive: `xvslibrary.lha`
- archive SHA-256: `7642b238e8df256e3519a909682f43b607e61df383e04766b660b773713b2c0a`
- LHA member: `xvs/libs/xvs.library`
- method: `-lh5-`

Qualified component:

- name: `xvs.library`
- version: `33.49`
- size: `68092` bytes
- member CRC-16/IBM: `eab4`
- SHA-256: `d178b7770199cd2abac2bb66ee95a86880a649c98b8bb681e8255de117eee21c`

Version evidence comes from the archive member `xvs.readme`, which identifies the package as External Virus Scanner Library v33.49 and records the same 68,092-byte library size.

## VirusZ_III.Bootblocks

Distribution archive:

- archive: `vhtvzboot.lha`
- archive SHA-256: `e7fb59a015b2d425ad0b2d59d2b46de6fe887429e438e8d86110a776e26d3906`
- LHA member: `s\\VirusZ_III.Bootblocks`
- method: `-lh5-`

Qualified component:

- name: `VirusZ_III.Bootblocks`
- version/date identity: `24.01.2026`
- size: `62472` bytes
- member CRC-16/IBM: `7701`
- SHA-256: `64c12a6631e0c3e6e9246fee684902d0b50046b1167949691909d2e556ace1cb`

Version evidence comes from `VirusZ_III.Bootblocks.doc`, which states `Last updated: 24 january 2026` and identifies the expected 62,472-byte `s:VirusZ_III.Bootblocks` file.

The documentation describes the file as a VirusZ III bootblock recognition/reference collection and distinguishes harmless bootblocks from newly added virus bootblocks. AAA therefore retains this as third-party bootblock reference provenance and must not silently treat every entry as native AAA known-clean truth without per-entry classification.

## Extraction verification

Both target members were decoded from their LHA `-lh5-` streams and independently checked against the CRC-16 stored in the archive header before SHA-256 was accepted:

- `xvs.library`: computed CRC-16 `eab4` == archive CRC-16 `eab4`;
- `VirusZ_III.Bootblocks`: computed CRC-16 `7701` == archive CRC-16 `7701`.

This qualifies the artifact identity and extraction path. It does **not** yet prove that a real VirusZ/VirusExecutor/VirusChecker/VirusSlayer runtime loaded the declared support file during an emulated scan.

## Redistribution boundary

Neither LHA archive nor extracted binary/reference file is committed to the repository. Only hashes, sizes, member paths, version evidence and qualification metadata are retained.

## Remaining runtime gate

To close M8.7 runtime qualification, a controlled historical-scanner run must demonstrate at least:

1. the declared scanner/version starts under its qualified OS profile;
2. the exact qualified `xvs.library` is installed/loaded where applicable;
3. the exact qualified `VirusZ_III.Bootblocks` is installed/loaded for VirusZ III where applicable;
4. the resulting engine evidence records the scanner version plus component version and SHA-256;
5. a known clean/synthetic-positive fixture produces observable scanner output while the original evidence remains unchanged.

Until that run exists, M8.7 is **artifact-qualified, runtime-pending**.
