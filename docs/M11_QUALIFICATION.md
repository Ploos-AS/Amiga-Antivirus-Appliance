# M11 — SMB drop-folder qualification

## Status

M11 is **code-qualified, appliance-runtime-pending**.

The implementation chain is complete through M11.2:

- M11.0 — safe stable-file observation and immutable SHA-256-addressed staging;
- M11.1 — daemon watcher integration using the existing queue and persistent scan history;
- M11.2 — authenticated Samba appliance integration plus persistent ingest receipts.

The final M11.2 code gate passed on GitHub Actions CI #384 at commit `e4f56c539b46d6a3f018cd9b175775936d733bda`.

Reference-appliance qualification remains pending Orange Pi Zero 3 / DietPi hardware.

## Code-qualified guarantees

Repository tests and CI establish that:

- the externally writable drop root and controlled incoming root are distinct;
- only stable regular files are ingested;
- symlinks, directories, hidden temporary files and unsafe names are not accepted as scan inputs;
- the daemon scans an immutable staged snapshot rather than the live SMB source;
- staging is content-addressed by SHA-256 and bounded by the configured maximum input size;
- a transient queue-submission failure is retried rather than silently losing the source;
- successful ingest receipts survive daemon restart and suppress unintended resubmission of an unchanged retained source;
- removing a source prunes its receipt so a later explicit re-drop can be scanned again;
- the Samba share exports only `/data/aaa/drop` as `aaa-drop`;
- guest access and anonymous fallback are disabled;
- the supported protocol floor is SMB2.1 and the maximum is SMB3;
- symlink following and wide links are disabled;
- amd64 and arm64 builds pass alongside `gofmt`, module metadata, `go vet`, `go test`, systemd verification and the existing AmiGuard compatibility gate.

## Reference-appliance gate

After M9 has been installed on the Orange Pi Zero 3 / DietPi reference appliance, install M11 and provision a dedicated Samba password:

```sh
sudo AAA_SMB_PASSWORD_FILE=/root/aaa-smb-password \
  sh scripts/install-m11.sh
```

Then run the authenticated qualification:

```sh
sudo AAA_SMB_PASSWORD_FILE=/root/aaa-smb-password \
  sh scripts/qualify-m11.sh
```

The target gate must prove the real end-to-end path:

```text
SMB3 client
  -> //127.0.0.1/aaa-drop
  -> /data/aaa/drop
  -> stability window
  -> SHA-256-addressed immutable snapshot
  -> /data/aaa/incoming
  -> daemon queue
  -> persistent scan history
```

The target evidence must also record:

- hardware/model and architecture;
- DietPi/Debian version;
- Samba version;
- AAA binary version and SHA-256;
- effective `testparm -s` share policy;
- `aaa.service` and `smbd.service` active/enabled state;
- authenticated SMB3 qualification result;
- receipt path and staged snapshot identity;
- resulting scan-history job identity and terminal state.

## Claim boundary

Until that target gate passes, M11 must not be described as appliance-qualified. CI proves the code, policy assertions and cross-builds; it does not prove Samba behavior, filesystem permissions, systemd group propagation, storage behavior or network transport on the Orange Pi reference system.

M11 is intended for a trusted LAN/VPN deployment. It does not claim WAN-safe SMB exposure, directory-service integration, per-user tenancy or firewall/VPN configuration.

## Completion decision

No additional M11 feature work is required before reference hardware arrives. The next software milestone is M12 Greaseweazle integration. M11 target qualification can be resumed independently when the Orange Pi Zero 3 is available.
