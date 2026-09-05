# Emulated Native Amiga Scanner Architecture

AAA is intentionally a hybrid scanner. The Linux/Go engine is the deterministic first layer, while a later isolated Amiga emulation layer runs genuine native Amiga antivirus software as independent scanner engines.

## Reference appliance

The reference hardware remains Orange Pi Zero 3 running DietPi/ARM64. Raspberry Pi and other ARM64 Debian-family systems are portability targets, not a change to the reference platform.

## Scanner layers

1. **AAA native engine** — format identification, hashing, ADF/HDF structure, bootblocks, OFS/FFS, Hunk and later archive-aware analysis.
2. **ClamAV** — generic host-side malware coverage. It is not treated as complete Amiga coverage.
3. **Emulated Amiga engines** — one or more native Amiga scanners running inside an isolated 68k Amiga environment. VirusZ and VirusExecutor are initial candidates subject to licensing, redistributability and automation qualification.

No single engine is treated as infallible. AAA records the engine name, version/database identity, result and evidence separately before deriving a final policy verdict.

## Isolation contract

The emulated scanner environment must:

- start from a known immutable or reproducibly reset baseline;
- have no untrusted host filesystem write access outside a job-specific exchange area;
- have networking disabled by default;
- never execute submitted Amiga programs merely as part of scanning;
- impose wall-clock, memory and artifact-size limits;
- preserve the original submitted material unchanged;
- export scanner results through a narrow machine-readable exchange boundary;
- be disposable or restored to the known baseline after each job.

## Result policy

A finding from a qualified Amiga scanner is preserved with scanner identity and evidence. A known-malicious exact AAA signature or a qualified native-scanner malware finding may raise the aggregate result to `infected`. A `clean` result from one scanner does not prove the sample clean; the aggregate wording should remain conservative, such as `no known malware detected`, unless policy explicitly defines stronger criteria.

## Planned milestone

The emulation layer is promoted to an explicit roadmap milestone before the web UI. It will cover emulator selection, deterministic guest image construction, scanner automation, result extraction, isolation qualification and cross-engine consensus semantics.
