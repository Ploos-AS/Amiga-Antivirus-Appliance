# M11.2 — Samba appliance integration

## Status

M11.2 adds the appliance-side SMB transport for the M11 drop-folder pipeline. Code qualification is provided by repository CI. Reference-appliance Samba/runtime qualification remains pending Orange Pi Zero 3 / DietPi hardware.

## Share boundary

The only SMB-exported AAA path is:

```text
/data/aaa/drop
```

The share name is `aaa-drop`.

The following AAA paths are deliberately not exported:

- `/data/aaa/incoming`
- `/data/aaa/state`
- `/data/aaa/quarantine`
- `/data/aaa/clean`
- `/data/aaa/unknown`
- `/data/aaa/reports`
- `/data/aaa/signatures`

SMB clients therefore write only to the externally writable drop boundary. The daemon never scans that live file directly; M11.0/M11.1 stage an immutable SHA-256-addressed snapshot into controlled `incoming` storage before submitting a scan job.

## Account and filesystem model

The installer creates:

- Unix/Samba user `aaa-drop`;
- group `aaa-drop`;
- `/data/aaa/drop` owned by `aaa-drop:aaa-drop` with mode `0770`;
- supplementary `aaa-drop` group membership for the `aaa` daemon account.

The `aaa` service is restarted after group membership is configured.

No guest account is used. The share requires the dedicated Samba account.

## Protocol and share policy

`samba/aaa-drop.conf` requires:

```text
server min protocol = SMB2_10
server max protocol = SMB3
map to guest = Never
restrict anonymous = 2
```

The share additionally requires:

```text
guest ok = no
valid users = aaa-drop
read only = no
follow symlinks = no
wide links = no
smb encrypt = desired
```

SMB1 is therefore outside the supported appliance contract.

## Credential provisioning

AAA never stores a default SMB password in the repository or appliance configuration.

Interactive setup:

```sh
sudo smbpasswd -a aaa-drop
```

For unattended provisioning, the installer accepts an explicit password file:

```sh
sudo AAA_SMB_PASSWORD_FILE=/root/aaa-smb-password \
  sh scripts/install-m11.sh
```

The password file is read only for `smbpasswd`; it is not copied into AAA configuration.

## Persistent restart receipts

M11.1 originally retained handled-file state only in process memory. M11.2 adds:

```text
/data/aaa/state/drop-ingest.json
```

A receipt contains the source basename, staged SHA-256 and size after a successful queue submission.

On daemon restart, an unchanged retained source is staged/hash-checked but is not submitted again when its receipt matches. When the source is removed from the drop folder, its receipt is pruned. Re-dropping the file later is therefore an explicit rescan action.

This receipt is an ingest/idempotency record, not malware evidence and not a substitute for scan history.

## Installation

M9.5 must already be installed.

```sh
sudo sh scripts/install-m11.sh
```

The installer:

1. installs `samba` and `smbclient` when needed;
2. creates the dedicated account/group;
3. prepares `/data/aaa/drop`;
4. installs `/etc/samba/aaa-drop.conf`;
5. adds one idempotent include line to `/etc/samba/smb.conf`;
6. validates the resulting Samba configuration with `testparm`;
7. optionally provisions credentials from `AAA_SMB_PASSWORD_FILE`;
8. enables/restarts `smbd` and restarts `aaa.service`.

It does not replace the distribution-owned main `smb.conf`.

## Qualification

Static/code gates include:

- Go tests for persistent receipt/restart behavior;
- `gofmt`, `go vet`, `go test`;
- amd64 and arm64 builds;
- shell syntax checks for M11 installer/qualifier;
- CI assertions for SMB2/SMB3-only, no guest, dedicated user, isolated path and no symlink following.

On the reference appliance:

```sh
sudo AAA_SMB_PASSWORD_FILE=/root/aaa-smb-password \
  sh scripts/qualify-m11.sh
```

The qualifier verifies Unix/group permissions, Samba configuration and service state, AAA daemon health and credential existence. With a password file it additionally performs a real authenticated SMB3 upload to `//127.0.0.1/aaa-drop`, then proves that:

- the drop watcher recorded an ingest receipt;
- a controlled SHA-256-addressed snapshot exists in `/data/aaa/incoming`;
- the submission reached persistent scan history.

The test source is then removed through SMB. No production sample is deleted automatically.

## Claim boundary

Until the authenticated target qualification has been executed on Orange Pi Zero 3 / DietPi, M11.2 is **code-qualified, appliance-runtime-pending**.

M11.2 does not provide WAN-safe file sharing, VPN configuration, firewall policy, directory services integration or per-user multi-tenant isolation. The SMB share is intended for a trusted LAN/VPN appliance deployment.
