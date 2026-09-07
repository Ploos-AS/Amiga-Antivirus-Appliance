# M12.5 — acquisition session CLI

## Status

M12.5 exposes the M12 acquisition pipeline as a single operator workflow:

```text
aaa acquire-session [--json] [--device DEVICE] [--gw PATH] [--timeout DURATION] [--reads N] [--note TEXT] OUTPUT-PREFIX
```

The default is two independent ADF reads.

## Workflow

For prefix `disk`, AAA plans all artifacts before the first physical read and refuses to start if any target already exists. A successful session produces:

```text
disk.scp
disk.scp.acquisition.json
disk.scp.gw.log
disk.read-01.adf
disk.read-01.adf.acquisition.json
disk.read-01.adf.gw.log
disk.read-02.adf
disk.read-02.adf.acquisition.json
disk.read-02.adf.gw.log
disk.repeatability.json
disk.session.json
```

Additional ADF reads follow the same numbered naming scheme.

The workflow is:

1. preservation-grade raw SCP capture;
2. write-once SCP evidence and raw Greaseweazle log;
3. independent ADF reads;
4. normal AAA scan of each exact ADF acquisition;
5. exact acquisition/scan SHA-256 binding per read;
6. ADF repeatability classification;
7. session manifest creation only after all requested acquisitions complete successfully.

## Failure semantics

A completed physical artifact is not deleted merely because a later session step fails. For example, if the raw SCP capture succeeds and a later ADF read fails, the SCP and its sidecars remain as valid acquisition evidence, while no `session.json` is written.

The session manifest therefore means that the requested session workflow completed; absence of the manifest does not invalidate already completed individual acquisition evidence.

## Provenance boundary

`disk.session.json` embeds the exact raw-flux and ADF acquisition evidence and repeats the conservative M12.4 relationship:

`same-operator-session; no SCP-to-ADF derivation asserted`

The command does not claim that an ADF was decoded from the stored SCP. Both are independent physical reads unless a later explicitly qualified conversion stage proves otherwise.

ADF divergence remains acquisition-quality evidence and is never automatically interpreted as malware.

## Public acquisition commands

M12.5 also exposes the M12.3 raw-flux command in the top-level dispatcher:

```text
aaa acquire-flux ... output.scp
```

The existing `aaa acquire` usage now documents M12.2 `--reads` and `--repeatability` options.

## Qualification

CI uses synthetic acquisition functions and verifies at least:

- session artifact naming;
- preflight refusal before any physical-read callback;
- raw SCP + repeated ADF linkage;
- reproducible repeatability result;
- explicit no-derivation relationship;
- operator-note propagation;
- preservation of a completed SCP if later ADF capture fails;
- absence of a session manifest after an incomplete workflow;
- gofmt, vet, tests and amd64/arm64 builds.

Real Greaseweazle, drive and floppy execution remains the hardware/runtime gate.
