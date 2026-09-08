# M14.4 — Integrated M13 operation ledger recording

Status: CODE-QUALIFIED — CI #499 PASS

## Purpose

M14.4 connects the M14 append-only evidence ledger to selected M13 operations so operators do not need to reconstruct routine provenance manually after the fact.

The integration is deliberately opt-in and backward-compatible. Existing M13 commands behave exactly as before unless `--ledger <path>` is supplied.

When `--ledger` is supplied, successful ledger recording becomes part of the command's reported success criteria.

## Integrated operations

M14.4 adds optional ledger recording to:

```text
aaa evidence pack --ledger <path> ...
aaa evidence verify-bundle --ledger <path> <bundle.zip>
aaa evidence sign --ledger <path> ... <bundle.zip>
aaa trust-update install --ledger <path> ... <trust-store.json> <update.json>
```

The event/object mappings are:

| Operation | Ledger event | Object kind | Hashed object |
| --- | --- | --- | --- |
| `evidence pack` | `bundle-created` | `evidence-bundle` | completed deterministic evidence ZIP |
| `evidence verify-bundle` | `bundle-verified` | `evidence-bundle` | verified evidence ZIP |
| `evidence sign` | `bundle-signed` | `evidence-signature` | completed detached evidence signature |
| `trust-update install` | `trust-store-installed` | `evidence-trust-store` | immutable installed trust-store file |

The ledger stores the SHA-256 identity of the exact regular file present at the time of recording. Host paths are not written into ledger records.

## Why integration is opt-in

The normal M13 commands are useful on developer workstations, offline review hosts and CI systems that may not have `/data/aaa/state` or any persistent appliance ledger.

Making ledger recording an unconditional default would turn an optional M14 provenance layer into a new prerequisite for all established M13 workflows. M14.4 therefore requires an explicit `--ledger` path.

An appliance profile may later choose to supply the default ledger path operationally.

## Recording gate

Integrated recording uses the same M14.2 append implementation as the explicit `aaa evidence ledger append` command.

Before a record is appended:

1. the selected output/input object is opened and SHA-256 hashed using the existing regular-file/path-identity checks;
2. the ledger is opened under the existing advisory exclusive lock;
3. the complete existing ledger is verified from byte zero to EOF;
4. the next sequence and previous-record link are derived from the validated tail;
5. one deterministic record is appended;
6. the ledger and containing directory are fsynced before success.

An invalid existing ledger therefore blocks integrated recording rather than being silently extended.

## Trust-store installation identity

`trust-update install` does not record the operator's candidate input pathname as the installed object.

After M13.7 successfully installs the authenticated store, M14.4 hashes and records the immutable sequence-addressed trust-store file under the persistent trust-state directory. This binds the ledger event to the bytes that actually became installed state.

## Failure and transaction boundary

M14.4 does **not** claim an atomic transaction spanning both the primary M13 operation and the ledger file.

For example, `evidence pack` creates and fsyncs the evidence ZIP before the ledger append is attempted. Likewise, trust-store installation may already have durably advanced the M13.7 state before integrated ledger recording begins.

Therefore, if the primary operation succeeds but ledger recording fails:

- the command returns an error;
- the already-completed primary artifact/state is retained;
- AAA does not delete or roll back valid evidence merely to simulate cross-file atomicity;
- the operator can inspect the failure and record the existing exact object later with the explicit ledger command when appropriate.

This behavior is intentional and tested.

## Security boundaries

Integrated ledger recording does not change malware classification and does not replace M13 validation.

A `bundle-verified` event records that the M13.3 verification gate succeeded during that command invocation; later independent consumers should still verify the bundle themselves when current validity matters.

M14.4 does not automatically journal every M13 command. In particular, manifest-only creation/verification and the alternative signed/trust verification paths remain available without integrated recording. The explicit M14.2 append command remains the general mechanism for operator-selected events.

The M14.3 checkpoint boundary remains unchanged: local ledger integrity does not prove absence of suffix deletion unless an independently retained signed checkpoint/tail is available.

## Qualification

No physical hardware is required for M14.4 code qualification.

Automated coverage verifies:

- integrated `bundle-created` recording from `evidence pack`;
- integrated `bundle-verified` recording from `evidence verify-bundle`;
- integrated `bundle-signed` recording using the detached signature object identity;
- integrated `trust-store-installed` recording using the immutable installed trust-store file;
- a valid multi-event integrated ledger chain;
- exact controlled object kinds;
- failure when the selected ledger is already invalid;
- retention of a completed primary evidence artifact when a later ledger append fails;
- unchanged no-ledger behavior through the existing M13 test suite;
- normal repository format, vet, tests, AmiGuard compatibility and amd64/arm64 build gates.

CI #499 passed the complete repository gate with the M14.4 implementation present.
