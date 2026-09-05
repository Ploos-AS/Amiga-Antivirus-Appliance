# M7.1 — Evidence and provenance qualification

## Status

**Code-qualified.**

M7.1 provides normalized cross-engine evidence and provenance semantics, deterministic source-correlation handling, bounded ClamAV execution, explicit candidate integration, archive-recursion control and post-engine input-integrity verification.

## Qualified scope

The qualified M7.1 scope includes:

- structured evidence attribution for engine, engine version, signature-database identity, OS profile and correlation key;
- fail-closed validation for partially attributed evidence;
- deterministic unique-correlation-key counting so multiple frontends backed by one knowledge source count once;
- native AAA bootblock evidence with stable provenance/correlation identity;
- strict ClamAV engine/database version parsing and normalized `FOUND` evidence;
- ClamAV correlation identity rooted in signature-database version rather than frontend or engine revision;
- bounded `clamscan` execution with no shell interpolation, explicit timeouts and independently capped stdout/stderr;
- strict ClamAV exit-code/result consistency checks;
- explicit `--scan-archive=no`, keeping archive expansion under AAA's own bounded provenance model;
- opt-in `aaa scan --clamav <file>` integration without changing ordinary native scan behavior or native result schema;
- infected ClamAV detections entering Signature Factory only with attributable normalized evidence;
- clean/error ClamAV states never masquerading as malware evidence;
- exact-repeat candidate idempotence while preserving `ErrCandidateConflict` for same-ID/different-content records;
- post-ClamAV SHA-256 verification of the submitted host path before an infected result may create a candidate.

## Preservation and safety properties

The qualified implementation maintains these code-level properties:

1. ClamAV does not recursively expand archives behind AAA's back.
2. External-engine execution is bounded by time and output limits.
3. The adapter invokes the configured executable directly without a shell.
4. Missing engine/database provenance fails closed.
5. Result text and process exit status must agree.
6. A ClamAV malware candidate cannot be committed if the submitted file disappears, changes type, cannot be re-read or no longer hashes to the exact SHA-256 produced by the native AAA scan.
7. Repeated identical candidate evidence is idempotent; conflicting evidence for the same candidate ID is rejected.
8. ClamAV remains opt-in and does not redefine the native scanner's top-level verdict.

## CI evidence

The preservation blockers were closed incrementally by:

- CI **#175** — candidate idempotence/conflict semantics;
- CI **#177** — explicit no-archive ClamAV execution;
- CI **#180** — post-ClamAV input-integrity enforcement.

The final code-changing qualification state is commit:

```text
40f6d822445611d06c893eb28fc317f8ec18f237
```

GitHub Actions CI #180 completed successfully. Its test job passed:

- research-manifest validation;
- format check;
- module metadata check;
- `go vet`;
- tests;
- linux/amd64 build;
- linux/arm64 build.

This qualification document is a descendant of that green state and does not alter runtime code.

## Intentionally outside M7.1

This qualification does not claim completion of:

- M7.2 deterministic signature export;
- M7.3 corpus/false-positive validation and later pattern-signature policy;
- M7.4 signed/versioned signature distribution;
- aggregate cross-engine verdict/confidence policy;
- real M8 historical-engine runtime qualification;
- reference Orange Pi Zero 3 appliance runtime qualification.

## Exit decision

M7.1 satisfies its code-qualification criteria and is closed as **code-qualified**. Development may continue with M7.2 export qualification without treating later historical-engine or appliance-runtime work as complete.
