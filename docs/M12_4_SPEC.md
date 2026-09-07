# M12.4 — acquisition session manifest

## Purpose

M12.4 adds a session-level provenance object that can bind a raw SCP flux capture and one or more independently acquired ADF reads from the same operator/device handling session.

This is acquisition evidence, not malware evidence.

## Model

`internal/acquisition.Session` records:

- schema identifier `aaa-acquisition-session-v1`;
- UTC manifest creation time;
- optional operator note;
- one validated raw SCP flux `Evidence` object;
- one or more validated ADF `Evidence` objects;
- the M12.2 ADF repeatability result;
- an explicit relationship statement.

The relationship is deliberately conservative:

`same-operator-session; no SCP-to-ADF derivation asserted`

M12.4 therefore does **not** claim that any ADF was decoded or derived from the stored SCP file. The SCP and ADF acquisitions remain independently hashed evidence objects.

## Validation

A session is rejected when:

- flux evidence is not `physical-floppy-flux` / `scp-raw-flux`;
- no ADF acquisition is present;
- an ADF is not `physical-floppy` / `adf`;
- any embedded evidence object fails its normal provenance validation;
- both flux and ADF evidence identify devices and those device identifiers disagree.

ADF disagreement is retained and reported as `divergent`; it is not a session validation failure and is not interpreted as malware.

## Claim boundary

Code-level model and validation can be qualified in CI with synthetic evidence. A real session claim still requires a Greaseweazle, floppy drive and physical disk on the reference appliance. M12.4 does not close that hardware/runtime gate.

A later CLI orchestration step may create the complete SCP + ADF set and write this manifest atomically/write-once. The M12.4 model itself is intentionally independent of physical hardware execution.
