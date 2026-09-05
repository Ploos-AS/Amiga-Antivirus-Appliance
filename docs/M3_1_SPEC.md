# M3.1 Specification — Historical Bootblock Source Qualification

## Goal

M3.1 establishes a reproducible provenance pipeline for real historical Amiga bootblock knowledge before any production fingerprint is added to AAA.

M3.1 does **not** treat a virus name, scanner claim, checksum value, or heuristic result as an exact AAA signature by itself. AAA's M3 production database matches the SHA-256 of the complete 1024-byte bootblock, so a source must ultimately provide or allow reconstruction of the exact bootblock bytes before a `known-malicious` or `known-clean` entry can be admitted.

## Initial qualified source candidate

The first source candidate is the preservation repository:

- `ResistanceVault/preservation-virus-executor`
- pinned preservation revision: `9a364275edbcbc90217f6ea1550c518c89f42d5f`
- upstream license reported by GitHub: GPL-3.0
- relevance: VirusExecutor source and associated historical lists document bootblock-virus handling, bootblock database functionality, and named virus families.

The repository is currently classified as **metadata / corroboration**, not as a source of exact AAA SHA-256 fingerprints. Its historical virus lists can corroborate names and scanner coverage, but M3.1 must not manufacture a 1024-byte fingerprint from a name or heuristic percentage.

## Admission contract

A real entry may enter `internal/signatures/bootblocks.json` only when all of the following are recorded:

1. Exact 1024-byte bootblock bytes are available from a lawful preservation source or reproducible image extraction.
2. SHA-256 is calculated by AAA tooling from those exact bytes.
3. Classification (`known-clean` or `known-malicious`) is supported by an identified historical source.
4. The source is pinned by immutable identifier where possible: artifact hash, archive identifier, repository commit, release, or equivalent.
5. Virus/family naming is normalized but the historical source wording is retained in notes when useful.
6. Conflicting classifications are not silently resolved; the fingerprint remains excluded until investigated.
7. No malware sample bytes are committed merely to make unit tests pass.

## Source classes

- **primary-sample** — exact bootblock bytes with provenance; eligible for hashing and possible admission.
- **scanner-database** — historical scanner data that identifies a specimen exactly enough to reproduce/verify it; potentially eligible after validation.
- **metadata** — names, family lists, detection capabilities, heuristic scores; corroboration only.
- **secondary-reference** — prose or catalog references; corroboration only.

## Preservation policy

AAA preserves historical malware evidence but does not publish live malware samples as ordinary repository fixtures. Production signatures contain hashes and provenance, not executable sample payloads.

## Exit criteria

M3.1 is complete when:

- source candidates are tracked in a machine-readable manifest;
- the admission rules above are documented and enforced operationally;
- at least one exact historical bootblock can be reproduced, hashed, independently classified, and added without weakening the provenance rules; or the milestone records explicitly that no candidate yet meets the admission bar.

The latter state is acceptable: an empty trustworthy corpus is preferable to an invented or ambiguous one.
