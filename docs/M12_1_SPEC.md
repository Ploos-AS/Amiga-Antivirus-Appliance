# M12.1 — `aaa acquire` CLI and acquisition/scan hash binding

## Status

M12.1 exposes the M12.0 Greaseweazle boundary through the public AAA CLI and binds a successful physical-media acquisition to a normal AAA scan by exact SHA-256 identity.

Real Greaseweazle hardware qualification remains pending.

## Command

```text
aaa acquire [--json] [--device DEVICE] [--gw PATH] [--timeout DURATION]
            [--evidence PATH] [--log PATH] [--note TEXT] OUTPUT.adf
```

Defaults:

- Greaseweazle executable: `--gw`, else `AAA_GW`, else `gw`;
- timeout: 10 minutes;
- acquisition evidence: `OUTPUT.adf.acquisition.json`;
- raw Greaseweazle log: `OUTPUT.adf.gw.log`.

M12.1 accepts only an `.adf` output path. Existing image outputs are already protected by M12.0; existing evidence/log sidecars are rejected before physical acquisition begins.

## Execution order

The command performs:

1. preflight output and sidecar paths;
2. Greaseweazle version probe and physical-media acquisition;
3. acquisition evidence validation;
4. write-once acquisition JSON sidecar;
5. write-once raw Greaseweazle log sidecar;
6. normal `scanner.ScanFile` on the acquired image;
7. mandatory equality check between `acquisition.output_sha256` and `scan.sha256`;
8. normal Signature Factory candidate recording when the bound AAA scan verdict is `infected`.

A successful acquisition remains valid physical-media evidence even if the subsequent malware scan fails. For that reason M12.1 does not delete the acquired image or its acquisition sidecars when scanning fails.

## Evidence separation

The JSON output contains two separate objects:

```json
{
  "acquisition": { "...": "physical-media provenance" },
  "scan": { "...": "AAA malware analysis" },
  "evidence_path": "disk.adf.acquisition.json",
  "log_path": "disk.adf.gw.log"
}
```

The acquisition object is not a malware verdict. The scan object is not proof of how the physical media was acquired. Their trust relationship is the exact SHA-256 equality gate.

## Integrity failure

If the scanner observes a SHA-256 different from the completed acquisition SHA-256, the command fails closed with an acquisition/scan hash-mismatch error. No combined successful result is emitted.

This guards against accidental replacement or mutation of the image between acquisition and scanning.

## Sidecar safety

Evidence and raw-log sidecars are created with exclusive-create semantics and are fsynced. AAA does not overwrite existing sidecars.

The image, evidence and log paths must be distinct.

## Qualification

CI must cover:

- successful acquisition/scan binding by identical SHA-256;
- write-once evidence and log sidecars;
- operator note propagation into acquisition evidence;
- rejection of an existing sidecar before acquisition starts;
- rejection of mismatched acquisition and scan SHA-256;
- CLI build/dispatch integration;
- normal repository format, vet, tests, amd64 and arm64 build gates.

## Hardware gate

Real M12.1 qualification remains pending a Greaseweazle device, floppy drive and known physical AmigaDOS disk. The target run must retain the ADF, acquisition JSON, raw Greaseweazle log and AAA scan result, and must demonstrate identical acquisition/scan image SHA-256 values.

M12.1 is **code-qualifiable without Greaseweazle hardware; hardware-runtime-pending**.
