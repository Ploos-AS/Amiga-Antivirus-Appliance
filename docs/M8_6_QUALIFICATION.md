# M8.6 — Target appliance qualification

## Status

**Qualification framework implemented. Real target qualification pending.**

M8.6 is the final M8 gate for the intended Orange Pi Zero 3 + DietPi appliance. Ordinary CI can validate the evidence schema and fail-closed rules, but it cannot truthfully claim appliance qualification without execution on the real target hardware with the intended historical scanner/AmigaOS inputs.

## Evidence contract

Each qualification record captures:

- hostname and hardware model;
- architecture;
- operating-system name/version and kernel version;
- AAA version;
- overall start/finish timestamps;
- one or more per-engine/profile executions;
- historical scanner version and scanner binary SHA-256;
- input SHA-256 before and after the run;
- normalized verdict and runner exit state;
- duration in milliseconds;
- peak RSS in KiB.

The validator rejects missing target identity, malformed hashes, invalid profiles/verdicts, duplicate engine/profile/input runs and any case where the primary input SHA-256 changes during the historical scan.

## Target claim boundary

Synthetic CI fixtures use the target labels `Orange Pi Zero 3`, `aarch64` and `DietPi` only to exercise the record format. They are not runtime evidence and must never be cited as proof that M8 works on the appliance.

Real appliance qualification remains pending until a physical target is available and the intended scanner binaries and AmigaOS environments are supplied under appropriate rights.

## Required real run set

The target qualification should exercise the supported M8 inventory under the profiles claimed by the codebase, including VT-Schutz on `os13` and the M8.4 scanners on their declared `os204`/`os31`/`os32` profiles. Controlled known-clean and known-infected samples should be used where legally and operationally appropriate.

Each completed run must preserve original evidence, store the exact raw scanner log through the existing M8 result model, and record enough timing/resource data to identify unsuitable appliance behavior.

## Completion rule

M8 may be called **code-qualified** once this framework and the earlier M8 slices are green in CI. It may be called **appliance-qualified** only after the physical Orange Pi Zero 3 + DietPi run set is completed and reviewed.
