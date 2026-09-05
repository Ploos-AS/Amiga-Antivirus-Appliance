# M5 — Amiga Hunk analysis

M5 adds structural analysis of classic Amiga Hunk executables to AAA.

## Scope

AAA recognizes executable files beginning with `HUNK_HEADER` (1011) and parses enough of the load-file structure to report:

- Hunk table range from the executable header;
- CODE, DATA, and BSS segments;
- segment sizes in longwords and bytes;
- aggregate CODE, DATA, and BSS byte counts;
- malformed/truncated structures as warnings rather than executing or repairing them.

The same parser is used for standalone files passed directly to `aaa scan` and for complete file payloads reconstructed from OFS/FFS ADF images by M4.1.

## Safety model

Hunk parsing is passive. AAA does not load, relocate, execute, patch, or otherwise activate Amiga binaries. Payload bytes reconstructed from ADF images remain in process memory and are not automatically written to disk.

Malformed files must not cause out-of-bounds reads or unbounded loops. Unsupported Hunk records stop structural parsing and are reported as warnings.

## Initial supported records

M5 understands the structural framing required for common load files, including:

- `HUNK_HEADER`
- `HUNK_CODE`
- `HUNK_DATA`
- `HUNK_BSS`
- `HUNK_RELOC32`, `HUNK_RELOC16`, `HUNK_RELOC8`
- `HUNK_NAME`
- `HUNK_SYMBOL`
- `HUNK_DEBUG`
- `HUNK_END`

`HUNK_UNIT`, `HUNK_EXT`, `HUNK_OVERLAY`, `HUNK_BREAK`, and unknown record types are currently reported as unsupported rather than guessed.

## Verdict policy

Recognizing a Hunk executable does not imply malware and does not make the file clean. M5 is structural analysis only. Malware classification remains `unknown` unless another AAA detection source establishes a stronger verdict.

## Exit criteria

M5 is code-qualified when CI passes:

- gofmt;
- `go vet ./...`;
- unit tests for valid, non-Hunk, and malformed Hunk data;
- ADF integration test proving a reconstructed file can be identified and analyzed as Hunk;
- linux/amd64 build;
- linux/arm64 build.
