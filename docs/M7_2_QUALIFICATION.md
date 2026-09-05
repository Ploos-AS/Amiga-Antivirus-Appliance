# M7.2 — Signature export qualification

## Status

**Code-qualified.**

M7.2 provides deterministic, promotion-gated signature export for AAA's native bootblock database and ClamAV SHA-256 hash databases. The exporter code, validation tests, CLI contract and final qualification record have all passed the normal GitHub Actions CI gates.

## Qualified scope

The M7.2 implementation includes two explicit export targets:

```text
aaa signatures export aaa
aaa signatures export clamav
```

The CLI help advertises both targets. No implicit `all` target exists.

### Native AAA export

`ExportNativeBootblocks`:

- reads only strictly validated records from the `promoted` store;
- exports only exact `bootblock-sha256` candidates;
- ignores pending/rejected and unrelated candidate kinds;
- rejects duplicate promoted bootblock SHA-256 values instead of choosing one record silently;
- sorts deterministically by SHA-256 and source;
- emits schema-1 JSON at `generated/aaa/bootblocks.json`;
- writes generated output atomically and is idempotent when bytes are unchanged.

### ClamAV export

`ExportClamAVHashes`:

- reads only strictly validated records from the `promoted` store;
- exports only exact `file-sha256` candidates attributed to the `clamav` source engine;
- ignores pending/rejected candidates and promoted file hashes attributed to other engines;
- preserves the exact sample SHA-256 and sample size from the promoted record;
- prefers `DetectionName` and falls back to `MalwareName` for the ClamAV signature name;
- rejects duplicate promoted ClamAV SHA-256 values instead of silently selecting one record;
- sorts output deterministically by SHA-256 and candidate ID;
- emits ClamAV SHA-256 hash-signature lines in `HashString:FileSize:MalwareName` form at `generated/clamav/aaa.hsb`;
- accepts only ASCII letters, digits, `-`, `.`, and `_` in the exported signature name and fails closed on unsupported characters;
- writes generated output atomically and is idempotent when bytes are unchanged.

The ClamAV export intentionally remains provenance-conservative in M7.2: a promoted exact file hash is not exported into the ClamAV database unless its `SourceEngine` is `clamav`. Cross-engine publication policy is separate future work and is not inferred by this milestone.

## Safety properties

The M7.2 tests cover the following preservation and publication properties:

1. Only explicitly promoted records can reach generated signature databases.
2. Candidate validation is strict before export; malformed promoted records fail the operation.
3. Wrong-status records placed in the promoted directory fail closed.
4. Duplicate exact hashes fail instead of producing ambiguous output.
5. Native and ClamAV export targets remain isolated from unrelated candidate kinds and sources.
6. Generated ordering is deterministic.
7. Re-running an export with unchanged inputs is byte-idempotent.
8. ClamAV signature names outside the documented safe character set are rejected rather than rewritten or sanitized silently.
9. No malware samples are required by the automated tests; synthetic hashes and metadata are sufficient.

## CI evidence

The ClamAV signature-name hardening and its qualification tests were validated by GitHub Actions CI run **#184** on commit:

```text
67889d9ff30c2af4e6fbe5b7a560e29295280fe2
```

That run completed successfully.

The final CLI help correction was committed as:

```text
500f422ff60cb97f0a3c7432fa577a98f6f5bc1d
```

The qualification record was committed as:

```text
a592b0b16fbfb76e10cbb2532b688edb6399f261
```

GitHub Actions CI run **#186** completed successfully on that qualification-record HEAD, covering the normal format, module-metadata, `go vet`, test, linux/amd64 build and linux/arm64 build gates.

## Remaining work outside M7.2

M7.2 does not claim completion of:

- corpus-scale false-positive/false-negative qualification — M7.3;
- pattern-signature generation or publication;
- signed/versioned signature distribution — M7.4;
- automatic promotion;
- cross-engine file-hash publication policy;
- reference Orange Pi runtime qualification.

## Exit decision

M7.2 satisfies its code-qualification criteria and is closed as **code-qualified**. Development may proceed to **M7.3 corpus validation / false-positive gates / pattern qualification** without treating later distribution or appliance-runtime work as complete.
