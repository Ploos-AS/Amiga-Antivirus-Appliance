# M7.0 — Signature Factory qualification

## Status

**Code-qualified.**

M7.0 now provides a local, provenance-first Signature Factory foundation for exact malware signature candidates. The implementation is CI-qualified on both linux/amd64 and linux/arm64. Runtime qualification on the reference Orange Pi Zero 3 remains part of the broader appliance qualification effort and is not required to proceed to M7.1.

## Qualified scope

The qualified M7.0 scope includes:

- schema-v1 candidate records with strict status, kind, ID and SHA-256 validation;
- exact `file-sha256` and `bootblock-sha256` candidate creation;
- pattern candidates explicitly disabled in M7.0;
- default persistent root `/data/aaa/signatures`, overrideable with `AAA_SIGNATURE_STORE_ROOT` for controlled deployments/tests;
- safe store layout for candidates, promoted, rejected, generated AAA, generated ClamAV and state data;
- deterministic JSON serialization;
- validated-ID filename construction and path-traversal rejection;
- idempotent duplicate writes and conflict rejection without evidence overwrite;
- strict read-back with unknown JSON fields rejected;
- automatic candidate recording after an `infected` scan result;
- recursive archive-member candidate generation so the infected member, rather than only its outer container, can receive an exact signature candidate;
- exact malicious bootblock candidates that retain both containing-sample SHA-256 and bootblock SHA-256;
- explicit lifecycle CLI operations for listing, validating, promoting and rejecting candidates.

## CLI contract

M7.0 exposes:

```text
aaa signatures candidates [--json]
aaa signatures validate
aaa signatures promote <id>
aaa signatures reject <id>
```

Promotion and rejection are explicit operator actions. An `infected` verdict may create a candidate, but it does not publish or promote it automatically.

## Safety properties qualified in code

The following properties are covered by implementation and automated tests:

1. Candidate IDs are syntactically constrained and cannot be used as arbitrary filesystem paths.
2. Candidate files are not silently overwritten.
3. Identical repeated candidate generation is idempotent.
4. Different evidence for the same candidate ID fails as a conflict.
5. Malformed or unsupported stored records fail closed.
6. No malware binary, disk image or historical malware payload is required by the test suite; synthetic hashes and metadata are used.
7. Pattern-signature generation is outside M7.0 and remains blocked until later corpus validation work.
8. Automatic generation does not imply publication, deletion or modification of the submitted historical material.

## CI evidence

The final M7.0 lifecycle implementation was qualified by GitHub Actions CI run **#136** on commit:

```text
d1a5c3926633e985b313b86ecffd11c0c066c74e
```

The run completed successfully with:

- research-manifest validation;
- format check;
- module metadata check;
- `go vet`;
- tests;
- linux/amd64 build;
- linux/arm64 build.

Earlier M7.0 increments also passed CI while introducing the candidate schema, persistent store and automatic scan-result integration.

## Remaining work intentionally outside M7.0

The following are not claimed complete by this qualification:

- normalized cross-engine evidence records and independence/correlation policy enforcement — M7.1;
- deterministic ClamAV export — M7.2;
- clean/malware corpus validation, false-positive gates and pattern qualification — M7.3;
- signed/versioned signature distribution — M7.4;
- reference-appliance runtime qualification;
- real historical scanner-engine integration, which belongs to the later emulated-engine milestones.

## Exit decision

M7.0 satisfies its code-qualification criteria and is closed as **code-qualified**. Development may proceed to **M7.1 Evidence/Provenance** without treating pending appliance runtime qualification or later corpus/export/distribution work as completed.
