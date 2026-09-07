# M11.0 — Secure drop-folder ingest foundation

## Goal

Add a filesystem ingest boundary for the future SMB drop-folder workflow without scanning files directly from an externally writable share.

M11.0 is deliberately transport-independent. Samba configuration and appliance exposure are deferred to M11.1. This stage establishes the security and integrity contract that every drop-folder transport must use.

## Security model

An SMB client may still be writing, renaming or replacing a file while AAA observes the share. AAA therefore must not hand a live share path directly to the scanner.

The M11.0 ingest boundary follows this sequence:

1. observe a visible, non-empty regular file directly inside the configured drop root;
2. require two matching observations before a later watcher may classify it as stable;
3. reject/ignore directories, symbolic links, hidden temporary names and unsafe basenames;
4. reopen and revalidate the file before staging;
5. copy through a bounded reader into a temporary file under AAA's controlled incoming root;
6. calculate SHA-256 while copying;
7. require the copied byte count to match the stable observation;
8. `fsync` and close the temporary snapshot;
9. publish by hard-link under `<sha256>-<basename>`;
10. treat an already-existing target as content-addressed deduplication.

The resulting controlled snapshot, not the SMB/drop path, is the only path that may later be submitted to the daemon manager.

## Package

`internal/dropfolder` provides:

- `Observe(root, name)` for safe candidate discovery;
- `Stable(first, second)` for unchanged size/mtime qualification;
- `Stage(candidate, incomingRoot, maxBytes)` for bounded immutable snapshot creation;
- `Candidate` and `Snapshot` evidence records.

M11.0 does not start a watcher goroutine and does not install Samba. Those integration steps are intentionally separate so that file-integrity behavior is CI-qualified first.

## Limits

The caller supplies `maxBytes`. M11 daemon integration should default this to the same 256 MiB ceiling used by M9 HTTP submission unless a separate operator-configured limit is introduced explicitly.

Zero-byte files are ignored because they are commonly transient SMB creation artifacts and contain no useful scan payload.

## Source ownership

M11.0 never deletes, renames or modifies the source drop file. Source lifecycle policy belongs to the later watcher/workflow milestone. This avoids surprising data loss while the ingest contract is being qualified.

## Qualification

M11.0 is code-qualified when repository CI passes with tests proving:

- visible regular files are accepted as candidates;
- hidden, empty, directory, symlink and path-traversal entries are ignored;
- stability requires unchanged path, size and modification time;
- staged snapshots use exact SHA-256 content addressing;
- a second identical stage operation deduplicates to the same controlled path;
- changed and oversized candidates fail closed;
- normal amd64 and arm64 builds remain green.

## Runtime boundary

No appliance-runtime claim is made by M11.0. Samba installation, share permissions, stable-write timing and end-to-end SMB client qualification are M11.1+ concerns.
