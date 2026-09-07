# M10.2 Engine attribution and result model

## Goal

Make independent scanner evidence a first-class part of the persisted M9 result contract so M10 can present native AAA, ClamAV and historical Amiga scanners without collapsing their identities into one bare verdict.

## Common attribution envelope

`internal/engineevidence` defines an additive engine-result record containing:

- engine kind, stable ID and human-readable name;
- engine version when execution completed;
- completion/error status separated from malware verdict;
- verdict and detection name;
- exact input SHA-256;
- signature/database identity and version when available;
- OS profile for historical Amiga engines;
- scanner binary SHA-256 when available;
- raw-evidence SHA-256 when available;
- start/finish timestamps when available;
- independently versioned support components such as `xvs.library`;
- explicit execution/integration error text.

The model is additive. Existing detailed native `scanner.Result`, ClamAV evidence structures and M8 `historical.Result` remain valid specialized records.

## Native AAA

Daemon scans attach an `aaa-native` engine record to the normal native result. It records the AAA binary version, native verdict/detection and the exact input SHA-256.

The detailed ADF/filesystem/Hunk/archive/preservation/bootblock result remains the authoritative native-analysis payload.

## ClamAV

Daemon scans also attempt the existing bounded ClamAV runner against the exact submitted host file.

A successful ClamAV execution records:

- engine ID `clamav`;
- engine version;
- ClamAV signature database version;
- verdict/detection;
- SHA-256 of the normalized raw result line rather than exposing that host-path-bearing line through the common envelope.

ClamAV execution failure does **not** turn a successful native AAA scan job into a failed job. It is persisted as an attributed `status=error`, `verdict=error` engine record. This preserves the distinction between "AAA could not scan the input" and "one independent external engine was unavailable or failed".

## Historical Amiga engines

`historical.EngineEvidence` projects the existing rich M8 normalized result into the common envelope while retaining the original M8 result model.

It preserves engine ID/name/version, OS profile, scanner binary SHA-256, historical signature database identity, verdict/detection, input hash, raw-log hash and timestamps.

M8.7 support components can be attached explicitly to that projection. For example, a qualified VirusZ run can carry the exact `xvs.library` version/SHA-256 and other independently versioned support artifacts. No support component is inferred merely because an engine commonly uses it.

## Persistence and API

`scanner.Result` gains the additive JSON field:

```json
"engine_results": []
```

Because M9 history already persists the full `scanner.Result`, attributed engine results automatically survive JSONL journal replay and are returned from:

```text
GET /api/v1/scans/{id}/results
```

Older history entries without `engine_results` remain readable because the field is optional.

## Aggregate verdict boundary

M10.2 does not silently replace the existing native top-level verdict with a multi-engine consensus verdict. Per-engine disagreement remains visible evidence. A later explicit aggregation policy may derive a combined verdict, but it must preserve the individual records that produced it.

## UI boundary

M10.1 already retains unknown/additional attributed evidence rather than discarding it, so the new `engine_results` field is visible immediately. A following M10 slice may give engine results dedicated cards/tables without changing this API contract.

## Qualification gate

M10.2 is code-qualified when:

1. common engine evidence validates identity, hashes, status/verdict separation and support-component uniqueness;
2. daemon-native results contain an attributed `aaa-native` record;
3. successful ClamAV normalization preserves engine/database identity and raw-result digest;
4. unavailable/failing ClamAV is represented as engine error evidence without failing a successful native scan;
5. historical M8 results project into the common envelope without losing scanner/version/profile/hash attribution;
6. M8.7 support components can be carried explicitly by historical projections;
7. engine results serialize inside `scanner.Result` and therefore persist through existing M9 history/API paths;
8. `gofmt`, module metadata, `go vet`, `go test ./...`, linux/amd64 build and linux/arm64 build pass in CI.

Real historical scanner execution and Orange Pi Zero 3/DietPi appliance qualification remain separate runtime gates.
