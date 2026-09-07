# M12.0 — Greaseweazle acquisition boundary

## Status

M12.0 introduces a physical-media acquisition boundary for Greaseweazle without mixing acquisition provenance with malware scan evidence.

Code qualification is performed with deterministic fake-`gw` tests. Real Greaseweazle hardware, floppy drive and physical-disk qualification remain a separate reference-appliance gate.

## Scope

M12.0 covers acquisition of a classic AmigaDOS floppy into an ADF image using the Greaseweazle host tool.

The supported command shape is:

```text
gw read --format amiga.amigados [--device DEVICE] OUTPUT.adf
```

`AAA_GW` may override the `gw` executable path. The default command is `gw`.

The acquisition timeout defaults to 10 minutes.

## Evidence separation

Physical-media acquisition is not a malware verdict.

`internal/acquisition.Evidence` records:

- acquisition method;
- tool identity and version;
- optional Greaseweazle device selector;
- acquisition format;
- output basename;
- exact output SHA-256 and size;
- exact command arguments;
- acquisition start/finish timestamps;
- SHA-256 of the captured raw tool log;
- optional operator acquisition note.

Malware scanner evidence remains in the existing scanner/engine evidence model. Later M12 stages may bind an acquisition record to a scan job by the acquired image SHA-256, but must not collapse these two evidence classes into one object.

## Safety semantics

M12.0 refuses to overwrite an existing acquisition output.

If `gw read` fails, times out, creates an empty image, or the resulting image cannot be hashed, the incomplete output is removed and no successful acquisition evidence is returned.

The resulting image is hashed only after the Greaseweazle command exits successfully.

## Tool version

Before acquisition, AAA probes:

```text
gw --version
```

A successful acquisition requires a non-empty tool version string. This makes later physical-media evidence attributable to the host-tool version used for the read.

## Qualification

CI must cover at least:

- successful fake-Greaseweazle ADF acquisition;
- exact output SHA-256 and size;
- captured tool version/device/command provenance;
- raw acquisition log hashing;
- refusal to overwrite an existing acquisition;
- removal of partial output on acquisition failure;
- evidence validation failures for malformed hashes;
- standard repository `gofmt`, module metadata, vet, tests and amd64/arm64 builds.

## Reference hardware gate

Real Greaseweazle qualification is intentionally pending. It will require:

1. a supported Greaseweazle device;
2. a known floppy drive/cable setup;
3. `gw info` evidence identifying host tools, device model, firmware and serial where available;
4. at least one known readable AmigaDOS floppy;
5. a completed ADF acquisition;
6. recorded acquisition SHA-256 and raw log;
7. subsequent AAA scan of that exact SHA-256 image;
8. comparison/repeatability evidence from at least two reads where practical.

M12.0 is therefore **code-qualifiable without hardware, hardware-runtime-pending**.

## Non-goals

M12.0 does not yet implement:

- a public `aaa acquire` CLI;
- daemon/API/Web UI acquisition jobs;
- flux-preservation formats such as SCP or raw flux archives;
- automatic retry strategy for marginal tracks;
- multi-read consensus;
- write-back to physical media;
- drive calibration or hardware setup automation.

Those are later M12 stages.
