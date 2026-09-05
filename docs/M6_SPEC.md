# M6 — Archive and compressed-image pipeline

## Goal

Safely unwrap common Amiga preservation containers and feed their contents into AAA's existing passive scanner pipeline without executing submitted material.

## Formats

M6 is delivered incrementally:

- M6.0: ADZ (gzip-wrapped ADF), bounded in-memory expansion, member hashing, and full scanner integration.
- M6.1a: ZIP member enumeration/extraction, hashing, and member format classification.
- M6.1b: LHA/LZH member extraction plus full native per-member ADF/Hunk scanning for ZIP and LHA.
- M6.2: DMS disk-image decoding through the reference xDMS decoder, with bounded stdin/stdout integration into the ADF scanner pipeline.
- M6.3: Amiga LZX support plus bounded nested-container scanning, including nested DMS under the shared per-job budget.
- M6.4: preservation-oriented disk-image formats, beginning with IPF and FDI.

A format is not claimed as supported merely because M1 can identify it.

## Safety contract

Archive processing is passive. Expanded bytes are not executed. Expansion is bounded. The current hard global expanded-data ceiling for a scan job is 32 MiB and the entry ceiling is 1024. Original submissions are never modified or deleted. Archive members are retained only in memory and member names are metadata, not host extraction paths. Invalid, truncated, encrypted, unsupported, malformed or over-limit containers fail closed with an attributable error/warning rather than being silently treated as clean.

Nested ZIP, LHA/LZH and LZX scanning has an explicit maximum archive depth of 2. Nested layers share the same global expanded-byte budget instead of receiving a fresh 32 MiB budget per layer. Nested ADZ and DMS also consume that same remaining budget before expansion is accepted. A descendant `infected` verdict propagates through its ancestors to the outer result.

## M6.0 contract

`internal/archive.DecodeADZ` accepts gzip bytes, expands them in memory, applies the hard expansion limit, and returns the expanded bytes plus SHA-256 metadata.

The scanner then requires the expanded payload to satisfy a supported raw ADF geometry and applies the existing native scanner chain. A valid ADZ therefore flows through:

`ADZ → expanded ADF → bootblock analysis/signatures → OFS/FFS traversal when available → reconstructed file SHA-256 → Hunk analysis`

No temporary extracted ADF is written to disk. The JSON result retains the outer submission hash and format, adds archive/member metadata, and attaches the normal ADF/filesystem analysis for the expanded image.

Malformed gzip, expansion over the budget, unsupported ADF geometry, or an otherwise invalid expanded payload causes the scan to fail closed rather than being treated as an unknown clean container.

## M6.1a ZIP contract

`internal/archive.DecodeZIP` uses Go's standard-library ZIP reader. It expands regular members into memory, ignores directory entries, rejects encrypted members, caps archive entries, and applies the remaining expanded-size budget. Each regular member receives an exact SHA-256.

The scanner classifies each expanded member using AAA's existing content-aware format detector and records the member name, expanded size, SHA-256, and detected format in the archive result.

## M6.1b LHA/LZH and member scanning contract

`internal/archive.DecodeLHA` uses the MIT-licensed `github.com/koron-go/lha` reader. AAA accepts the supported `-lh0-`, `-lh4-`, `-lh5-`, `-lh6-`, and `-lh7-` methods, validates that the input starts with a recognized LHA header, rejects unsupported or malformed streams, and applies the remaining expanded-byte and entry budgets. Directory headers count toward the entry ceiling. LHA member names remain metadata only.

ZIP and LHA members are passed through the native scanner without writing extracted content to disk. Supported member payloads receive raw ADF bootblock analysis and bootblock database matching, OFS/FFS filesystem traversal and reconstructed file hashing, Hunk analysis for standalone Hunk executables, and per-member verdict/detection/error metadata.

## M6.2 DMS contract

DMS is decoded with the reference `xdms` utility. xDMS is public-domain software and is packaged by Debian. The appliance installer installs the Debian `xdms` package alongside ClamAV.

`internal/archive.DecodeDMS` requires a `DMS!` header and invokes xDMS as a bounded subprocess using:

`xdms -q u stdin +stdout`

The submitted DMS bytes are sent through stdin and the expanded disk image is read from stdout. AAA does not create a temporary submitted DMS file or extracted ADF path. Decoder stdout is capped at 32 MiB and execution is limited to 15 seconds. Missing xDMS, decoder failure, timeout, empty output, over-limit output, or unsupported ADF geometry fails closed.

`DecodeDMSLimited` allows the nested scanner to pass the remaining global expansion budget directly into the xDMS wrapper before output is accepted into memory.

The resulting bytes are hashed and then passed through the same ADF chain used by ADZ:

`DMS → xDMS → expanded ADF → bootblock analysis/signatures → OFS/FFS traversal when available → reconstructed file SHA-256 → Hunk analysis`

`AAA_XDMS` may override the xDMS executable path for controlled testing or deployment. It is an executable path only; arguments are not interpreted through a shell.

## M6.3 Amiga LZX contract

AAA uses Debian's `unar` package for Amiga LZX decoding. Debian's package description explicitly lists the historic Amiga LZX format among supported formats, and the package provides both `lsar` for archive inspection and `unar` for extraction.

`internal/archive.DecodeLZX` first writes the submitted archive to a private mode-0600 randomized temporary staging file because `lsar`/`unar` require a seekable archive path. That staging file contains only the original submitted archive and is removed after the operation. Extracted member payloads are never written to host paths.

AAA invokes `lsar -j -nr -- <archive>` to obtain machine-readable member metadata with recursive archive listing disabled. It then requests each regular member separately with `unar -o - -- <archive> <member>`, which sends member bytes to stdout. Decoder output is bounded by the remaining per-job expansion budget, metadata output and stderr are capped, and each tool invocation has a 15-second timeout. The listed member size must exactly match the bytes emitted by `unar`; mismatch fails closed.

`AAA_LSAR` and `AAA_UNAR` may override executable paths for controlled testing or deployment. They are executable paths only and are not interpreted through a shell.

Top-level and nested LZX members enter the same native member scanner as ZIP and LHA, including ADF and Hunk analysis. Detection currently treats the `.lzx` suffix as an LZX candidate and relies on `lsar` format recognition to reject mislabeled inputs.

## M6.3 nested-container policy

The current nested-container contract is intentionally conservative:

- maximum archive depth: 2;
- global expanded-data budget: 32 MiB across the archive tree;
- archive entry ceiling: 1024, with nested decoders receiving only remaining resources;
- ZIP, LHA/LZH and LZX may recurse;
- ADZ may appear as a member and must expand to a valid ADF;
- DMS may appear as a member and is decoded through `DecodeDMSLimited` using the same remaining expansion/member budget;
- member bytes remain in memory and archive member names never become host extraction paths;
- an infected descendant propagates `infected` to each ancestor and the top-level result;
- malformed or over-limit descendants retain an attributable error and are never promoted to clean.

## M6.4 preservation disk-image formats

M6.4 adds formats whose low-level track representation may contain information that cannot be represented faithfully by a normal sector-only ADF.

The first targets are IPF and FDI. The original image remains the primary evidence object and retains its own SHA-256. If a decoder can expose a normal AmigaDOS sector view, AAA may create a transient derived sector image for the existing native ADF/filesystem scanner, but the report must retain provenance between the original preservation image and the derived view.

IPF support uses an optional external CAPSImage-compatible decoder boundary rather than linking separately licensed CAPS/SPS code into the MIT AAA core. FDI will use an auditable parser or the same bounded helper model depending on the selected implementation and license.

See `docs/M6_4_SPEC.md` for the exact contract and qualification gates.

## Dependency policy

AAA itself is MIT licensed. The LHA reader is also MIT licensed and remains a separately attributed third-party dependency. M6.1b raises the build baseline to Go 1.24 because the selected current LHA module requires Go 1.24 or later. Dependency checksums are committed in `go.sum`.

xDMS is a separate runtime utility rather than linked project code. Its upstream distribution states that xDMS is public-domain software. `unar`/`lsar` are provided by Debian as a separate runtime package. AAA does not relicense external components.

CAPS/SPS decoder code used for IPF remains a separately licensed optional runtime component and is not bundled as MIT project code.

## Qualification

M6.0 is code-qualified when CI passes archive and scanner ADZ tests, gofmt, `go vet ./...`, all Go tests, and linux/amd64 plus linux/arm64 builds.

M6.1a is code-qualified when the same CI additionally passes ZIP unit tests and a scanner integration test proving member enumeration, SHA-256, and format classification.

M6.1b is code-qualified when CI additionally passes LHA decode/error tests, full ZIP ADF/Hunk member scan tests, an LHA Hunk member scan test, module metadata checks, vet, all tests, and both architecture builds.

M6.2 is code-qualified when CI passes DMS magic/error tests, bounded xDMS wrapper tests, a scanner integration test proving decoded bytes reach ADF analysis, module metadata checks, vet, all tests, and both architecture builds. Final runtime qualification additionally requires the real Debian xDMS package on the Orange Pi/DietPi reference appliance and a provenance-safe DMS fixture.

M6.3 is code-qualified when CI passes nested-depth/global-budget tests, bounded nested DMS tests, bounded LZX wrapper tests, an LZX scanner integration test proving an extracted Hunk member reaches Hunk analysis, module metadata checks, vet, all tests, and both architecture builds. Final runtime qualification additionally requires Debian `unar`/`lsar` and xDMS on the Orange Pi/DietPi reference appliance plus provenance-safe real DMS/LZX fixtures.

M6.4 has separate IPF and FDI qualification gates defined in `docs/M6_4_SPEC.md`.

## Exit criteria for full M6

M6 archive/compressed-image support is complete for ADZ, DMS, ZIP, LHA/LZH and LZX when all have bounded extraction/decoding, tests, scanner integration, and explicit malformed-input behavior. Preservation-image support then extends M6 with IPF and FDI under the separate M6.4 evidence/provenance contract.
