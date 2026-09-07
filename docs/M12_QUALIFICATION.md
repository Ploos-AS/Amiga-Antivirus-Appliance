# M12 — Greaseweazle qualification

Status: **code-qualified through M12.5; physical runtime qualification pending hardware**.

M12 adds physical floppy acquisition to AAA without weakening the evidence boundary between acquisition provenance and malware scan results.

## Code-qualified scope

The repository/CI qualification covers:

- M12.0 Greaseweazle acquisition model and bounded helper boundary;
- M12.1 single-read ADF acquisition with evidence/log sidecars and exact scan hash binding;
- M12.2 repeated independent ADF reads and repeatability classification;
- M12.3 preservation-grade raw SCP flux capture using `gw read --raw --format amiga.amigados`;
- M12.4 session-level provenance linking raw SCP and independent ADF acquisitions without asserting SCP-to-ADF derivation;
- M12.5 public `aaa acquire`, `aaa acquire-flux`, and `aaa acquire-session` workflows.

CI cannot prove drive electronics, USB transport, firmware interoperability, media handling, flux capture quality, or real floppy repeatability.

## Physical gate

The physical gate requires:

- a system capable of running AAA and the Greaseweazle host tools;
- a connected Greaseweazle device and floppy drive;
- at least one physical Amiga floppy suitable for qualification;
- writeable storage for retained acquisition evidence.

Orange Pi Zero 3 / DietPi is the reference appliance target, but the Greaseweazle acquisition path may be exercised on another supported Linux host before final reference-appliance qualification.

## Qualification command

Build AAA and then run:

```sh
go build -o aaa ./cmd/aaa
AAA_M12_OUTPUT_ROOT=/data/aaa/reports/m12 \
AAA_M12_SESSION_NAME=reference-floppy \
AAA_M12_READS=3 \
sh scripts/qualify-m12.sh
```

For an explicitly selected Greaseweazle device:

```sh
AAA_M12_DEVICE=/dev/greaseweazle \
AAA_M12_OUTPUT_ROOT=/data/aaa/reports/m12 \
sh scripts/qualify-m12.sh
```

The qualifier performs a real `gw info` device/firmware probe and then invokes `aaa acquire-session`. Current Greaseweazle documentation identifies `gw info` as the normal connection test for attached hardware.

## Evidence to retain

A successful run must retain the full session directory contents, including:

- raw `.scp` capture;
- SCP acquisition JSON and Greaseweazle log;
- every independently captured `.adf`;
- ADF acquisition JSON and Greaseweazle log for every read;
- repeatability manifest;
- session manifest;
- console output from `scripts/qualify-m12.sh`;
- AAA version and Greaseweazle host-tool/device/firmware information.

Do not discard divergent ADF reads. Divergence is acquisition evidence and must not be converted into a malware verdict.

## Pass criteria

M12 physical qualification passes only when:

1. the Greaseweazle device/firmware probe succeeds;
2. raw SCP flux capture succeeds and is non-empty;
3. at least two independent ADF reads complete;
4. each ADF is scanned by AAA with exact acquisition/scan SHA-256 binding;
5. the repeatability manifest is retained, regardless of whether status is `reproducible` or `divergent`;
6. the session manifest is retained with schema `aaa-acquisition-session-v1`;
7. the relationship remains `same-operator-session; no SCP-to-ADF derivation asserted`.

A `divergent` repeatability result does not itself fail M12 qualification. It indicates that the physical reads differed and should be investigated while preserving all evidence.

## Claim boundary

Until this hardware gate has been executed successfully, M12 must be described as **code-qualified / hardware-runtime-pending**. CI success alone must not be presented as proof that a physical floppy was read successfully.
