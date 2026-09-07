# M12.3 — Raw flux preservation capture

## Status

M12.3 adds a preservation-grade Greaseweazle raw-flux acquisition boundary using SuperCard Pro (`.scp`) output.

The raw flux artifact is **acquisition evidence**, not malware scan input. AAA does not treat an SCP file as an ADF and does not infer a malware verdict from flux-level variation.

Code qualification uses deterministic fake-`gw` tests. Real Greaseweazle hardware, drive and physical-media qualification remain a separate appliance gate.

## Why raw flux

ADF preserves the logical AmigaDOS sector image but cannot represent every physical-disk property. Copy protection, unusual track layouts, weak/marginal data and other non-standard recording details may require preservation below the sector-image layer.

Greaseweazle supports SCP as a raw-flux image type with multiple revolutions per track. For preservation capture AAA uses:

```text
gw read --raw --format amiga.amigados [--device DEVICE] OUTPUT.scp
```

`--raw` is mandatory. Greaseweazle documentation warns that specifying `--format` without `--raw` causes decoded data to be regenerated as idealized flux rather than preserving the original physical flux stream. The format remains present so Greaseweazle can verify/interpret the expected AmigaDOS geometry while retaining raw flux.

## Evidence

The existing `internal/acquisition.Evidence` model is reused with:

- `method = physical-floppy-flux`;
- `format = scp-raw-flux`;
- Greaseweazle tool version;
- optional device selector;
- output basename, exact SHA-256 and size;
- exact command arguments;
- start/finish timestamps;
- SHA-256 of the raw Greaseweazle log;
- optional operator note.

This evidence is separate from scanner/engine evidence.

## Safety semantics

The flux acquisition boundary:

- requires a `.scp` output name;
- refuses to overwrite an existing output;
- removes partial output after command failure or timeout;
- rejects empty output;
- hashes the completed SCP only after `gw read` exits successfully;
- validates the resulting acquisition evidence before returning success.

## Relationship to ADF acquisition

M12.3 does **not** claim that an independently acquired ADF is byte-derived from a particular SCP capture. A raw SCP capture and an ADF capture may be taken from the same physical disk/session, but that relationship needs an explicit session manifest before AAA may assert it.

This deliberate boundary avoids making a false provenance claim when the physical disk was read in separate passes.

## CLI integration boundary

The `acquireFluxCommand` implementation is present in `cmd/aaa/acquire_flux.go`, including write-once evidence/log sidecars and human/JSON output. Public dispatch from `aaa` is intentionally tracked separately from the raw-flux boundary qualification; M12.3 must not be called a public CLI feature until `main()` dispatch and usage are integrated and CI-qualified.

## CI gates

CI must prove at least:

- raw SCP command includes both `--raw` and `--format amiga.amigados`;
- output SHA-256 and size are recorded;
- format is `scp-raw-flux`;
- raw Greaseweazle log is retained/hashable;
- non-SCP output is rejected;
- failed acquisition removes partial SCP output;
- repository `gofmt`, vet, tests and amd64/arm64 builds remain green.

## Reference hardware gate

Hardware qualification later requires:

1. Greaseweazle device and firmware identification;
2. known drive/cable configuration;
3. physical Amiga floppy;
4. successful raw SCP capture;
5. recorded SHA-256, size, command and log evidence;
6. successful opening/inspection of the SCP in a compatible analysis/emulation tool where practical;
7. companion ADF acquisition and scan as separate evidence;
8. explicit session linkage without claiming the ADF was derived from the SCP unless a later conversion stage actually performs and verifies that derivation.

M12.3 is therefore **code-qualifiable without hardware, hardware-runtime-pending**.
