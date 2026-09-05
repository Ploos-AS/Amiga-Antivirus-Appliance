# Security Policy

AAA processes intentionally untrusted and potentially malicious historical software.

- Never execute submitted Amiga binaries during ordinary scanning.
- Never automatically delete an original sample.
- Treat disk images and archives as hostile parser input.
- Preserve cryptographic hashes and reports for traceability.
- Run scanner services without root privileges.
- Keep writable service paths narrowly scoped.
- Apply recursion, file-count, decompression-size and timeout limits before archive support ships.
- Do not expose future upload/API services to untrusted networks by default.

M0 installs a non-networked placeholder service as the `aaa` user with writes restricted to `/data/aaa`.

Do not publish live malware samples, credentials, or sensitive host information in public issue reports.
