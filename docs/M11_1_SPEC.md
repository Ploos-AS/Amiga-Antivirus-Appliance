# M11.1 — daemon drop-folder watcher

## Status

Implementation target: code qualification in the standard repository CI. Reference-appliance runtime qualification remains pending Orange Pi Zero 3 / DietPi hardware.

## Goal

M11.1 connects the M11.0 secure drop-folder ingestion primitive to the production `aaa daemon` lifecycle. It deliberately does **not** configure Samba yet. Network sharing, users and SMB protocol policy belong to M11.2.

## Paths and defaults

The daemon now has three distinct persistent roles:

- `AAA_DROP_ROOT` / `--drop-root`, default `/data/aaa/drop`: externally writable landing directory;
- `AAA_INCOMING_ROOT` / `--incoming-root`, default `/data/aaa/incoming`: AAA-controlled immutable staged inputs;
- `AAA_STATE_ROOT` / `--state-root`, default `/data/aaa/state`: persistent scan history/state.

`drop-root` and `incoming-root` must differ.

## Polling contract

Default polling interval is 2 seconds (`--drop-poll`). A candidate must remain unchanged for at least 5 seconds (`--drop-stable`) before staging.

The watcher:

1. reads only direct children of the drop root;
2. accepts only visible, non-empty regular files accepted by M11.0 `Observe`;
3. records size and mtime on first observation;
4. resets the stability window whenever either changes;
5. after the stability window, copies the file through M11.0 `Stage` into `incoming`;
6. submits only the staged content-addressed snapshot to the existing `daemon.Manager`;
7. leaves the original drop-folder file in place;
8. marks the unchanged source handled for the lifetime of the daemon process so normal polling does not repeatedly submit it.

A source file that disappears or changes is removed/reset from the observation set. If a file changes during staging, it is retried from a fresh observation rather than terminating the daemon.

## Queue behavior

Drop-folder jobs use the exact same bounded `daemon.Manager` queue and worker pool as HTTP-submitted jobs. A transient submit failure such as a full queue leaves the source observation unhandled, so a later poll retries submission.

No second scanner pipeline or history format is introduced.

## Limits

Drop-folder staging uses the daemon `--max-upload-bytes` value as the common maximum input size. The default remains 256 MiB.

M11.1 does not recursively scan directory trees and does not treat directories, symlinks, sockets, device nodes or hidden temporary files as submissions.

## Shutdown and failure behavior

The watcher runs under the same daemon context as the scan manager and HTTP server. SIGINT/SIGTERM cancels all three. An unrecoverable drop-root read/staging error terminates the daemon rather than silently disabling the drop workflow.

The drop root is created with mode 0750 if absent. Final ownership and SMB write policy are an appliance-install concern for M11.2.

## Qualification gates

CI must verify:

- standard format/vet/test/build gates remain green for amd64 and arm64;
- a stable source is staged and submitted exactly once during an unchanged watcher lifetime;
- the source remains present after submission;
- a changing source does not submit until a fresh stability window completes;
- transient submit failure is retried;
- equal drop/incoming roots are rejected.

## Known boundary

The handled set is currently in-memory. An unchanged source left in `/data/aaa/drop` can therefore be reconsidered after a daemon restart. M11.2 must define the appliance-level processed-file/retention policy before enabling SMB for users; M11.1 intentionally avoids deleting or moving user material without that explicit policy.
