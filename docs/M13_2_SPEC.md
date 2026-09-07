# M13.2 — Evidence manifest CLI

Status: IMPLEMENTED — CI qualification pending

## Commands

M13.2 exposes the portable M13 evidence manifest model through the public `aaa` CLI.

```sh
aaa evidence create \
  --output evidence.json \
  --entry artifact:artifacts/disk.adf:./artifacts/disk.adf \
  --entry scan-report:reports/scan.json:./reports/scan.json \
  --note "case A"

aaa evidence verify evidence.json
```

Verification defaults to the manifest directory as the entry root. A different root can be supplied explicitly:

```sh
aaa evidence verify --root /archive/case-a evidence.json
```

## Entry syntax

`--entry` is repeatable and has the form:

`KIND:PORTABLE-NAME:SOURCE-PATH`

The portable name is what appears in the manifest. The source path is used only while creating the manifest and is never serialized.

Supported kinds are:

- `artifact`
- `scan-report`
- `engine-evidence`
- `acquisition-evidence`
- `repeatability`
- `acquisition-session`
- `raw-flux`
- `signature-evidence`

## Creation contract

Creation:

- requires at least one explicit entry;
- hashes the exact opened regular file with SHA-256;
- records byte size and portable relative name;
- rejects symlink sources and source-path replacement between open and validation;
- rejects unsafe or absolute portable names;
- writes a deterministic `aaa-evidence-bundle-v1` manifest;
- records the running AAA version;
- never serializes source host paths;
- creates the manifest write-once with `O_EXCL` and does not overwrite an existing output;
- fsyncs the completed manifest before success is reported.

M13.2 creates the manifest only. It does not silently copy evidence files into another directory or archive. A later M13 step may add an explicit portable package/container operation.

## Verification contract

Verification is offline and does not execute evidence content. It:

- rejects non-regular or oversized manifest files;
- rejects unknown JSON fields and unsupported schemas;
- validates all manifest paths, kinds, hashes and relationships;
- rejects missing evidence files and symlink entries;
- verifies exact size and SHA-256 of every referenced file;
- fails closed on any mismatch.

The manifest size limit is 4 MiB.

## Provenance boundary

Creating or verifying a bundle does not change malware classification. It only proves that the referenced bytes match the manifest.

M12 semantics remain unchanged: placing an SCP flux capture and one or more ADF reads in the same M13 manifest does not assert that any ADF was derived from the SCP. Such relationships must remain explicit in the underlying M12 session evidence.

## Qualification

M13.2 requires no physical hardware. CI qualification covers create/verify success, deterministic model validation inherited from M13.1, write-once output, tamper detection, unsafe portable-name rejection, symlink-source rejection, strict manifest parsing and the absence of source host paths in portable manifests.
