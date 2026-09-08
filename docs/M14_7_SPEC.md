# M14.7 — Installed checkpoint trust verification

Status: IMPLEMENTED — CI qualification pending.

M14.7 makes the authenticated, rollback-gated checkpoint trust state from M14.6 directly consumable by ledger checkpoint verification.

## CLI

```text
aaa evidence ledger checkpoint verify-installed \
  [--ledger /data/aaa/state/evidence-ledger.jsonl] \
  [--checkpoint <path>] \
  [--state-root /data/aaa/state/checkpoint-trust]
```

The default checkpoint path remains `LEDGER.checkpoint.json`.

## Verification contract

`verify-installed`:

1. loads the persistent checkpoint trust state through the same fail-closed M14.6 state loader used by `trust-update status/install`;
2. requires an installed state and rejects missing, malformed, incomplete or hash-mismatched state;
3. loads the exact immutable trust-store file named by the authenticated state pointer;
4. strictly decodes the checkpoint trust store;
5. strictly decodes the detached checkpoint;
6. verifies the complete ledger;
7. resolves the checkpoint signer under the installed policy using current-time active/revoked and validity-window semantics;
8. verifies the checkpoint signature and ledger prefix/tail binding;
9. reports the installed trust sequence used for the decision.

The command does not accept a loose `--trust-store` argument. `verify-trusted` remains available for explicit operator-supplied policy files; `verify-installed` is the appliance path for authenticated installed policy.

## Security boundary

The M14.6 limitations remain unchanged. The state pointer is local mutable state protected by filesystem integrity plus the authenticated immutable store chain and pinned root used during installation. M14.7 does not add TPM-backed monotonic state, root-key rotation, a trusted timestamp, remote transparency or protection against an attacker who can rewrite the entire state directory together with the independently pinned root source.

Checkpoint signer validity and revocation are evaluated at verification time; a checkpoint does not contain a trusted signing timestamp.

## Qualification

Code qualification requires:

- successful verification using an installed authenticated checkpoint trust store;
- rejection when no installed state exists;
- rejection of malformed/tampered active state or active store;
- rejection of unknown, revoked, not-yet-valid and expired checkpoint signers through the installed policy;
- preservation of M14.3 checkpoint prefix/tail semantics;
- `gofmt`, `go vet`, repository tests, AmiGuard compatibility, amd64 and arm64 builds.
