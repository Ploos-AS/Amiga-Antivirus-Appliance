# M6 — Archive and compressed-image pipeline

## Goal

Safely unwrap common Amiga preservation containers and feed their contents into AAA's existing passive scanner pipeline without executing submitted material.

## Formats

M6 is delivered incrementally:

- M6.0: ADZ (gzip-wrapped ADF), bounded in-memory expansion, member hashing, and full scanner integration.
- M6.1a: ZIP member enumeration/extraction, hashing, and member format classification.
- M6.1b: LHA/LZH member extraction plus full native per-member ADF/Hunk scanning for ZIP and LHA.
- M6.2: DMS disk-image decoding through the reference xDMS decoder, with bounded stdin/stdout integration into the ADF scanner pipeline.
- M6.3: LZX support and nested-container policy.

A format is not claimed as supported merely because M1 can identify it.

## Safety contract

Archive processing is passive. Expanded bytes are not executed. Expansion is bounded. M6.0 and M6.1 use a 32 MiB hard aggregate expansion limit, and ZIP/LHA additionally permit at most 1024 members. Original submissions are never modified or deleted. Archive members are retained only in memory; member names are metadata and are never used as host extraction paths. Invalid, truncated, encrypted, unsupported, or over-limit containers fail closed with an attributable error/warning rather than being silently treated as clean.

## M6.0 contract

`internal/archive.DecodeADZ` accepts gzip bytes, expands them in memory, applies the hard expansion limit, and returns the expanded bytes plus SHA-256 metadata.

The scanner then requires the expanded payload to satisfy a supported raw ADF geometry and AmigaDOS bootblock contract before applying the existing native scanner chain. A valid ADZ therefore flows through:

`ADZ → expanded ADF → bootblock analysis/signatures → OFS/FFS traversal → reconstructed file SHA-256 → Hunk analysis`

No temporary extracted ADF is written to disk. The JSON result retains the outer submission hash and format, adds archive/member metadata, and attaches the normal ADF/filesystem analysis for the expanded image.

Malformed gzip, expansion over 32 MiB, unsupported ADF geometry, or a non-AmigaDOS expanded payload causes the scan to fail closed rather than being treated as an unknown clean container.

## M6.1a ZIP contract

`internal/archive.DecodeZIP` uses Go's standard-library ZIP reader. It expands regular members into memory, ignores directory entries, rejects encrypted members, caps the archive at 1024 entries, and applies a 32 MiB aggregate expanded-size limit. Each regular member receives an exact SHA-256.

The scanner classifies each expanded member using AAA's existing content-aware format detector and records the member name, expanded size, SHA-256, and detected format in the archive result.

## M6.1b LHA/LZH and member scanning contract

`internal/archive.DecodeLHA` uses the MIT-licensed `github.com/koron-go/lha` reader. AAA accepts the supported `-lh0-`, `-lh4-`, `-lh5-`, `-lh6-`, and `-lh7-` methods, validates that the input starts with a recognized LHA header, rejects unsupported or malformed streams, caps expansion at 32 MiB aggregate data, and caps extracted members at 1024. LHA member names remain metadata only.

ZIP and LHA members are then passed through the native scanner without writing extracted content to disk. Supported member payloads currently receive:

- raw ADF bootblock analysis and bootblock database matching;
- OFS/FFS filesystem traversal and reconstructed file hashing;
- Hunk analysis for standalone Hunk executables;
- per-member verdict, detection, error, and structural metadata.

An infected member propagates `infected` to the outer archive result with the member name retained in the detection string. Unknown or unsupported members remain `unknown`. Nested archive expansion is intentionally deferred to M6.3 so archive recursion limits can be specified explicitly before enabling it.

## M6.2 DMS contract

DMS is decoded with the reference `xdms` utility. xDMS is public-domain software and is packaged by Debian. The appliance installer installs the Debian `xdms` package alongside ClamAV.

`internal/archive.DecodeDMS` requires a `DMS!` header and invokes xDMS as a bounded subprocess using:

`xdms -q u stdin +stdout`

The submitted DMS bytes are sent through stdin and the expanded disk image is read from stdout. AAA does not create a temporary submitted DMS file or extracted ADF path. Decoder stdout is capped at 32 MiB and execution is limited to 15 seconds. Missing xDMS, decoder failure, timeout, empty output, over-limit output, unsupported ADF geometry, or a non-AmigaDOS result fails closed.

The resulting bytes are hashed and then passed through the same ADF chain used by ADZ:

`DMS → xDMS → expanded ADF → bootblock analysis/signatures → OFS/FFS traversal → reconstructed file SHA-256 → Hunk analysis`

`AAA_XDMS` may override the xDMS executable path for controlled testing or deployment. It is an executable path only; arguments are not interpreted through a shell.

## Dependency policy

AAA itself is MIT licensed. The LHA reader is also MIT licensed and remains a separately attributed third-party dependency. M6.1b raises the build baseline to Go 1.24 because the selected current LHA module requires Go 1.24 or later. Dependency checksums are committed in `go.sum`.

xDMS is a separate runtime utility rather than linked project code. Its upstream distribution states that xDMS is public-domain software. AAA does not relicense external components.

## Qualification

M6.0 is code-qualified when CI passes archive and scanner ADZ tests, gofmt, `go vet ./...`, all Go tests, and linux/amd64 plus linux/arm64 builds.

M6.1a is code-qualified when the same CI additionally passes ZIP unit tests and a scanner integration test proving member enumeration, SHA-256, and format classification.

M6.1b is code-qualified when CI additionally passes LHA decode/error tests, full ZIP ADF/Hunk member scan tests, an LHA Hunk member scan test, module metadata checks, vet, all tests, and both architecture builds.

M6.2 is code-qualified when CI passes DMS magic/error tests, bounded xDMS wrapper tests, a scanner integration test proving decoded bytes reach ADF analysis, module metadata checks, vet, all tests, and both architecture builds. Final runtime qualification additionally requires the real Debian xDMS package on the Orange Pi/DietPi reference appliance and a provenance-safe DMS fixture.

## Exit criteria for full M6

M6 is complete when ADZ, DMS, LHA/LZH, LZX and the supported ZIP subset have bounded extraction/decoding, tests, scanner integration, and explicit behavior for malformed and unsupported inputs.
