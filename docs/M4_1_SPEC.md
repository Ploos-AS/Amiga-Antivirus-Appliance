# M4.1 — OFS/FFS file payload reconstruction

M4.1 extends M4 filesystem traversal with deterministic reconstruction and SHA-256 hashing of file payloads stored in classic AmigaDOS ADF images.

## Scope

Supported inputs remain classic 512-byte-sector DD and HD ADF images recognized by AAA. M4.1 handles the data layout used by OFS-family DOS types (`DOS\\0`, `DOS\\2`, `DOS\\4`, `DOS\\6`) and FFS-family DOS types (`DOS\\1`, `DOS\\3`, `DOS\\5`, `DOS\\7`).

For every traversed file header AAA reports:

- declared byte size;
- number of data blocks consumed while reconstructing the file;
- exact SHA-256 of the reconstructed byte stream when reconstruction completes;
- `complete=true` only when the declared byte size is satisfied;
- a warning when pointers, extension blocks, or OFS data blocks are malformed.

## Reconstruction rules

A file header contains up to 72 data-block pointers. Pointers are consumed in AmigaDOS sequence order from the end of the pointer table. If more data blocks are required, the extension pointer is followed through file extension blocks with the same pointer ordering.

FFS-family data blocks contain raw 512-byte file data. The concatenated stream is truncated to the file header's declared byte size.

OFS-family data blocks have a 24-byte metadata header. AAA validates the `T_DATA` type and payload-size field and appends only the declared payload bytes from each block.

Empty files are represented by the SHA-256 of the empty byte stream and `complete=true`.

## Preservation and safety semantics

M4.1 is read-only. It never executes, repairs, rewrites, deletes, or normalizes file content. A failed reconstruction is structural evidence and is reported as a warning; it is not by itself a malware verdict.

The reconstructed bytes are currently used transiently for hashing and are not written out to the host filesystem. This keeps the scanner passive and avoids materializing potentially hostile Amiga files before the later scanning pipeline is defined.

## Exit criteria

M4.1 is code-qualified when CI passes:

- gofmt check;
- `go vet ./...`;
- `go test ./...` including synthetic OFS, FFS, extension-block, and filesystem-integration tests;
- Linux amd64 build;
- Linux arm64 build.

No copyrighted Amiga disk images or malware samples are required by the test suite.
