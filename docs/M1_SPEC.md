# M1 Specification — AAA CLI, hashing and format identification

## Status

M1 introduces the portable `aaa` command-line interface. It is intentionally host-independent and does not require the Orange Pi reference appliance.

M0 reference-platform runtime qualification remains pending until Orange Pi Zero 3 hardware is available.

## CLI contract

Primary command:

```sh
aaa scan [--json] <file>
```

Additional command:

```sh
aaa version
```

The product and executable are both named **AAA**. `amigascan` is not a public command name.

## Scan result

M1 reports:

- input path and basename;
- byte size;
- SHA-256;
- identified format;
- verdict.

M1 verdict is deliberately `unknown`. Format identification and hashing are not malware detection, and M1 must not label input clean or infected.

## Format identification

M1 recognizes the following by content where practical:

- ADF / AmigaDOS filesystem image (`DOS` boot-block identifier plus standard DD/HD ADF size);
- generic Amiga filesystem image;
- DMS (`DMS!`);
- ADZ / gzip;
- LHA/LZH level header family;
- ZIP;
- Amiga Hunk executable (`HUNK_HEADER`, 0x000003f3).

For formats without a sufficiently safe M1 content signature, the extension can produce an explicitly unrecognized classification such as `lzx-unrecognized` rather than pretending that the content was validated.

## JSON contract

`aaa scan --json <file>` emits one JSON object with stable M1 fields:

```json
{
  "path": "disk.adf",
  "name": "disk.adf",
  "size": 901120,
  "sha256": "...",
  "format": "adf",
  "verdict": "unknown"
}
```

## Portability

The M1 implementation uses only the Go standard library. It must build on Linux amd64 and Linux arm64. The Orange Pi appliance remains the reference runtime target, not a source-code dependency.

## Exit criteria

M1 is code-complete when:

```sh
go test ./...
go build ./cmd/aaa
./aaa version
```

pass on a supported development host, and cross-compilation succeeds for Linux ARM64:

```sh
GOOS=linux GOARCH=arm64 go build ./cmd/aaa
```

Reference-device runtime qualification is deferred until the Orange Pi Zero 3 is available.
