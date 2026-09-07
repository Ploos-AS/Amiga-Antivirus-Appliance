# M8.7 — XVS and VirusZ bootblock support provenance

## Goal

Treat independently versioned historical antivirus support data as first-class provenance rather than anonymous files inside an emulator image.

The initial component kinds are:

- `xvs-library` — `xvs.library`, used by VirusZ III and other historical Amiga antivirus programs;
- `virusz-iii-bootblocks` — `VirusZ_III.Bootblocks`, a known-harmless bootblock catalogue used by VirusZ III.

## Why this matters

A historical scanner verdict is reproducible only if AAA records the scanner version **and** the exact support data that influenced that verdict. Two runs of the same VirusZ executable can legitimately produce different interpretation when XVS or the bootblock catalogue changes.

M8.7 therefore extends the provenance model, not the malware-signature pipeline.

## Component identity

Every support artifact used in a qualified run records:

```text
kind
name
version
sha256
source/provenance when known
```

The SHA-256 is computed from the exact user-supplied file. Version strings are metadata and must not substitute for content identity.

## XVS

`xvs.library` is treated as an independently versioned detection/disinfection support component. AAA must not claim that the scanner executable alone identifies the effective detection database when XVS participates in the run.

For an XVS-backed engine, evidence should be expressible as:

```text
engine_id=virusz-iii
engine_version=<scanner version>
support.kind=xvs-library
support.version=<xvs version>
support.sha256=<exact file hash>
```

The same model applies to VirusExecutor, VirusChecker II, VirusSlayer II or other engines when runtime qualification demonstrates that they use XVS.

## VirusZ_III.Bootblocks

`VirusZ_III.Bootblocks` is classified as a known-harmless bootblock naming/reference catalogue, not a malware corpus. Its identity must remain separate from XVS malware recognition data.

AAA may later import qualified entries into its native known-clean bootblock evidence layer, but such import must retain source/version/hash provenance and must not silently turn a third-party catalogue into unattributed AAA truth.

## Redistribution boundary

M8.7 does **not** commit or redistribute `xvs.library`, `VirusZ_III.Bootblocks`, VirusZ, AmigaOS or other third-party binaries. Acquisition and redistribution rights are qualified separately. The code records identities for user-supplied artifacts.

No SHA-256 values for real third-party files are guessed from filenames, screenshots or version labels.

## M9 interaction

M9 scan history and REST representations must be able to preserve the component records attached to historical-engine evidence. A history record must not collapse:

```text
VirusZ III + XVS A
VirusZ III + XVS B
```

into indistinguishable scanner results.

## Qualification

M8.7 code qualification requires:

1. typed support-component kinds for XVS and VirusZ III bootblocks;
2. exact SHA-256 identification of a supplied artifact;
3. mandatory component name, version and digest;
4. engine provenance capable of carrying multiple distinct component kinds;
5. duplicate component kinds rejected within one engine provenance record;
6. synthetic self-contained tests only;
7. `go test ./...`, `go vet ./...`, native build and linux/arm64 build green.

Runtime qualification additionally requires the real files, exact versions/hashes, and evidence that the declared scanner actually consumed those files. That runtime gate remains pending until the controlled Amiga scanner environment is exercised.
