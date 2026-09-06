# M8 — Historical Amiga scanner integration

## Goal

M8 adds a second, independent evidence layer to AAA: historical native Amiga antivirus programs executed in controlled emulated Amiga environments. These engines complement, rather than replace, the Linux-native AAA scanner and ClamAV/signature pipeline.

M8 is preservation-oriented. The appliance must retain the original submitted image as primary evidence, run historical scanners without silently modifying that evidence, capture enough provenance to reproduce a verdict, and distinguish scanner/tool failure from malware detection.

## Status

**Foundation / implementation in progress.**

M7.5 is code-qualified. M8 starts from the green M7.5 closure HEAD and must not weaken the M6/M7 evidence, hashing, quarantine, signature or signed-distribution contracts.

## Initial scanner set

The first adapter targets are:

- VirusZ III v1.04ß;
- VirusExecutor v2.34;
- VirusChecker II v2.5;
- VirusSlayer II v1.0b;
- Mill v0.85;
- VT-Schutz v3.17.

These names/versions define initial compatibility targets, not permission to redistribute third-party binaries. Exact runtime compatibility and acquisition/licensing status are qualified separately per engine.

## OS profiles

Historical scanners run under explicit profiles rather than an unspecified generic Amiga environment:

- `os13` — AmigaOS 1.3; VT-Schutz is the primary early-OS target;
- `os204` — AmigaOS 2.04 / 2.x compatibility profile;
- `os31` — AmigaOS 3.1 compatibility profile;
- `os32` — AmigaOS 3.2 compatibility profile.

A scanner adapter declares the profiles it supports. The report records the exact profile used.

ROMs, Workbench/AmigaOS files and proprietary scanner binaries are user-supplied unless redistribution rights are explicitly established. AAA must not embed unlicensed proprietary components in the repository, OCI image or appliance image.

## Architecture

M8 separates orchestration from scanner-specific behavior:

```text
AAA job
  -> immutable/original evidence reference
  -> historical scanner orchestrator
  -> OS profile
  -> emulator runner
  -> engine adapter
  -> raw engine output
  -> normalized historical-scanner result
  -> combined AAA report
```

Scanner-specific adapters live below a dedicated M8 engine namespace, initially:

```text
m8/engines/<engine>/
```

Common emulator/profile orchestration must not be duplicated inside every adapter.

## Adapter contract

Each engine adapter must provide enough metadata and behavior to answer:

- engine identifier and human-readable name;
- expected scanner version;
- supported OS profile(s);
- executable/config/signature-database prerequisites;
- deterministic invocation inputs where the engine permits them;
- how the submitted artifact is exposed to the Amiga environment;
- how completion/timeout/crash is detected;
- how raw output/logs are collected;
- how a detection is parsed;
- how CLEAN, INFECTED, SUSPICIOUS, UNKNOWN and ERROR are distinguished;
- whether the scanner can modify media and, if so, how writes are prevented or redirected.

Adapters must fail closed: unknown output must never be normalized to CLEAN merely because no known detection string matched.

## Evidence preservation

The original submitted artifact remains primary evidence and must retain its original SHA-256 identity.

Historical scanner execution must not modify the primary evidence. Writable scanner environments must use a copy, snapshot, overlay or other disposable derived representation. If a format such as IPF/FDI requires lossless conversion to another representation for a scanner, the report records both the original artifact hash and the derived artifact hash plus conversion provenance.

A scanner's repair/disinfection feature is not part of the default M8 scan path. Future repair workflows, if any, must produce separate derived artifacts and never overwrite the submitted evidence.

## Normalized result

Every historical-engine run produces a normalized record containing at least:

```text
engine_id
engine_name
engine_version
os_profile
scanner_binary_sha256
signature_database_id/version when available
verdict
detection_name when available
raw_exit/completion state
raw_log reference/hash
input_sha256
derived_input_sha256 when applicable
started_at
finished_at
```

For engines using XVS, Brain or another independently versioned detection database, that version/identity is captured when technically available.

The raw scanner output remains evidence. Normalization is a derived interpretation and must not erase the original log.

## Verdict semantics

Historical scanner adapters use AAA's common verdict vocabulary:

- `clean` — the engine positively completed its intended scan and reported no detection;
- `infected` — the engine positively identified malware/virus according to its own database or algorithm;
- `suspicious` — the engine positively reported suspicious/unknown-virus-like evidence that is not a named confirmed detection;
- `unknown` — the engine completed but its output cannot be safely mapped to a stronger verdict;
- `error` — the engine, emulator, profile, input preparation or collection path failed or timed out.

No single historical engine is authoritative for the aggregate AAA verdict. Aggregation policy remains explicit and preserves per-engine disagreement.

## Runtime isolation

Each run uses a disposable runtime state. At minimum:

- no primary evidence writes;
- no persistent modification of the base OS/scanner profile;
- bounded wall-clock runtime;
- bounded output/log capture;
- deterministic cleanup of temporary state;
- no network access unless an engine-specific future requirement is explicitly documented and opted into;
- no automatic execution of submitted Amiga startup scripts outside what the scanner workflow strictly requires.

The appliance must treat submitted media as untrusted input even inside emulation.

## Emulator boundary

M8 does not hard-code scanner parsing into the emulator implementation. The emulator runner provides lifecycle, mounts/media attachment, profile boot, command/input injection where supported, timeout and artifact/log collection. Adapters own scanner-specific invocation and parsing.

The first implementation may use FS-UAE or another suitable emulator where automation is reliable. The architecture must allow a different backend for profiles where compatibility requires it.

## Automation levels

An engine can be qualified at one of these levels:

- `adapter-only` — metadata/parser contract covered by synthetic fixtures;
- `emulator-synthetic` — end-to-end orchestration exercised with a redistributable/synthetic Amiga-side fixture;
- `runtime-qualified` — actual target scanner/version executed successfully against known clean and infected fixtures under the declared OS profile;
- `appliance-qualified` — runtime-qualified on the Orange Pi Zero 3/DietPi target.

Documentation must state the achieved level per engine. Code-level parser tests must not be described as runtime qualification.

## Test corpus boundary

M8 tests should use harmless synthetic fixtures where possible. Real historical malware samples are preservation corpus material and must not be committed casually to the public source repository.

Known infected runtime fixtures require explicit provenance, hashes and controlled storage. CI must not depend on downloading live malware or proprietary scanner/OS binaries.

## CI strategy

Ordinary CI must remain self-contained and license-safe. It should cover:

- adapter registry and metadata validation;
- unique engine IDs;
- OS-profile validation;
- parser fixtures for clean/detection/suspicious/error/unknown outputs;
- timeout/crash normalization;
- preservation of raw logs;
- original/derived SHA-256 provenance;
- aggregate-report serialization;
- linux/amd64 and linux/arm64 builds remaining green.

Actual proprietary historical scanners and AmigaOS runtimes are qualified separately on controlled runtime hosts/appliances.

## Planned implementation slices

### M8.0 — Contract and inventory

Define engine adapter/result/profile contracts, initial engine inventory, redistribution boundary, evidence rules and qualification levels.

### M8.1 — Common adapter framework

Implement engine registry, normalized result schema, OS-profile validation, raw-log evidence and synthetic adapter fixtures.

### M8.2 — Emulator runner

Implement disposable emulator lifecycle, profile/media staging, timeout, output collection and no-write evidence boundary with a synthetic Amiga-side fixture.

### M8.3 — VT-Schutz / OS 1.3 path

Implement and qualify the first early-Amiga adapter around the `os13` profile, initially parser/fixture-qualified and then runtime-qualified when the user-supplied scanner/OS environment is available.

### M8.4 — OS 2.x/3.x scanner adapters

Add VirusZ III, VirusExecutor, VirusChecker II, VirusSlayer II and Mill adapters with declared compatible profiles and per-engine qualification records.

### M8.5 — Multi-engine orchestration

Run configured historical engines as independent evidence producers, preserve disagreements and integrate normalized results into the AAA report without weakening native/ClamAV evidence.

### M8.6 — Target appliance qualification

Exercise the qualified historical-scanner set on Orange Pi Zero 3 + DietPi, measure runtime/resource behavior and record remaining engine/profile limitations.

## Non-goals

M8 does not:

- redistribute Amiga ROMs, Workbench/AmigaOS files or proprietary scanner binaries without rights;
- overwrite or disinfect original evidence;
- treat emulator success as scanner success;
- turn parser fixture tests into claims of real scanner compatibility;
- require historical proprietary software in ordinary CI;
- replace ClamAV, native AAA analysis or M7 signature generation;
- merge the separate Atari antivirus appliance into AAA.

## Exit criteria

M8 can be called **code-qualified** when the common historical-scanner framework, disposable emulator boundary, normalized evidence/report integration and the planned engine adapters are implemented with self-contained CI coverage and exact green qualification HEADs.

M8 can be called **appliance-qualified** only after the intended actual scanner versions have been exercised under their declared OS profiles on the Orange Pi Zero 3/DietPi target, with original-evidence preservation and reproducible per-engine qualification records.
