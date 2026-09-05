# M4 — OFS/FFS filesystem traversal

## Goal

M4 makes AAA enumerate directory and file header blocks from classic AmigaDOS ADF files so later milestones can inspect and scan individual files.

M4 is metadata traversal only. It does not yet extract file payloads, parse executable Hunks from inside the image, or declare files clean or infected.

## Supported images

M4 operates on the classic ADF images already admitted by M2:

- DD: 901120 bytes / 1760 blocks
- HD: 1802240 bytes / 3520 blocks
- AmigaDOS `DOS\\0` through `DOS\\7`

Both OFS and FFS directory metadata use the header/hash-chain layout traversed here.

## Traversal contract

AAA:

1. resolves the filesystem root block from the bootblock pointer, falling back to the geometry-defined root when the pointer is zero;
2. validates the root as an AmigaDOS root header;
3. follows directory hash buckets and hash chains;
4. recognizes file header secondary type `-3` and user-directory secondary type `2`;
5. reads Amiga BSTR names from header blocks;
6. recursively enumerates nested directories;
7. records each object's path, type, and header block number.

The result is included in JSON as `filesystem` with:

- `root_block`
- `root_block_valid`
- `file_count`
- `directory_count`
- `entries[]`
- `warnings[]`

Each entry contains `path`, `name`, `type`, and `header_block`.

## Corruption handling

Preservation comes before convenience. Malformed directory metadata is not silently ignored and does not cause deletion or repair.

M4 bounds-checks block references, rejects implausible hash-table sizes, detects hash-chain loops and directory recursion loops, and limits traversal depth. Structural problems are surfaced in `warnings` where traversal can safely continue.

A corrupt or missing root block leaves `root_block_valid=false`; this does not by itself produce a malware verdict.

## Verdict policy

M4 does not introduce new malware verdicts. Filesystem structure alone is evidence, not proof of infection.

Existing M3 bootblock matches retain their current behavior:

- known malicious bootblock -> `infected`
- known clean bootblock -> whole disk remains `unknown`
- unknown bootblock -> `unknown`

File-level verdicts require later content extraction and scanning milestones.

## Out of scope

- file payload extraction
- OFS data-block chain reconstruction
- FFS data pointer reconstruction
- file SHA-256 inside ADF
- Amiga Hunk parsing of embedded files
- archive expansion
- native Amiga emulator scanning
- filesystem repair

## Qualification

M4 is qualified by synthetic tests covering:

- root-block resolution
- file enumeration
- directory enumeration
- nested directories
- hash chains
- corrupt/out-of-range root metadata

No copyrighted disk image or live malware sample is required for CI.
