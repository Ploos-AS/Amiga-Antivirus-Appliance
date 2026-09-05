# M7.1 — Evidence and provenance

## Goal

M7.1 strengthens Signature Factory evidence so every attributable detection can preserve engine identity, version/database identity, OS profile and correlation semantics without accidentally counting two frontends backed by the same knowledge source as independent confirmation.

M7.1 builds on the M7.0 candidate/store/lifecycle foundation. It does not publish signatures automatically and it does not change the rule that malware samples stay outside Git.

## Normalized evidence record

Schema-v1 candidate JSON keeps the existing `evidence` array, but evidence entries may now carry structured attribution:

```json
{
  "type": "engine-detection",
  "detail": "Virus detected as Foo",
  "source_engine": "virusz",
  "source_version": "1.04",
  "signature_db_version": "...",
  "os_profile": "os31",
  "correlation_key": "xvs:<database identity>"
}
```

The fields are:

- `type`: evidence class, for example `engine-detection`, `bootblock-database`, `lifecycle`, `corpus-check`;
- `detail`: short attributable description or source reference;
- `source_engine`: logical scanner/engine name;
- `source_version`: exact engine version when known;
- `signature_db_version`: exact database/XVS/Brain/signature-set identity when known;
- `os_profile`: execution profile such as `os13`, `os204`, `os31`, `os32` when applicable;
- `correlation_key`: identity of the underlying knowledge source used for independence calculations.

Unattributed administrative evidence such as lifecycle transitions may contain only `type` and `detail`. Once any engine/version/database/profile/correlation attribution is present, `source_engine` and `correlation_key` are mandatory and validation fails closed if they are absent.

## Correlation policy

`correlation_key` represents the underlying source of detection knowledge, not merely the frontend process name.

Examples:

- two wrappers around the same ClamAV database use the same correlation key and count as one source;
- two historical scanners that both consume the same XVS signature database use the same XVS correlation key and count as one source for that evidence;
- an independent scanner with its own unrelated database uses a different correlation key;
- AAA's curated bootblock database uses an AAA bootblock-database correlation key tied to its provenance source.

M7.1 code provides deterministic counting of unique correlation keys. This is infrastructure only: M7.1 does not automatically promote confidence merely because the count reaches a threshold.

## Independence versus agreement

Agreement and independence are separate concepts. Multiple engines may agree on a malware name while still deriving that answer from the same database. Such agreement is useful evidence but is not independent corroboration.

Future confidence/promotion policy may use independent-source counts, but it must remain explicit and auditable.

## Native AAA evidence

When the native scanner creates a candidate from a known-malicious bootblock database match, the evidence record is attributed to `aaa-native` and receives a stable correlation key rooted in the bootblock database provenance source. The containing sample SHA-256 and exact bootblock SHA-256 remain distinct candidate fields as defined by M7.0.

## ClamAV evidence

M7.1 includes a strict ClamAV normalization helper for attributable `clamscan` results. A `FOUND` result becomes `engine-detection` evidence only when the detection name, ClamAV engine version and signature database version are all known. Clean (`OK`) and unrelated/error output do not become malware evidence.

The common `clamscan --version` form `ClamAV <engine>/<database>/<build-date>` is parsed into separate engine and database identities. Build dates are not used as source identity. The correlation key is `clamav-db:<database version>`, so multiple wrappers or ClamAV engine revisions using the same underlying database count once for independence calculations.

Missing database identity fails closed instead of inventing provenance. Raw result text may be retained as a single-line evidence detail, but control/newline content is rejected.

## Bounded ClamAV execution adapter

M7.1 now also includes a bounded `clamscan` execution adapter. `RunClamAV` scans one already-existing regular host file and uses `AAA_CLAMSCAN` when configured, otherwise `clamscan` from `PATH`.

The adapter:

- validates that the target is a regular file before execution;
- executes `clamscan --version` first and fails closed unless engine and signature database identity can be parsed;
- executes a single-file scan with `--no-summary --stdout -- <path>` without invoking a shell;
- applies a 5-second version-query timeout and a 30-second scan timeout;
- caps stdout and stderr independently at 64 KiB;
- accepts ClamAV exit code 0 only for a parsed `OK` result;
- accepts exit code 1 only for exactly one parsed `FOUND` result;
- rejects exit codes above 1, output/exit-code mismatches, multiple `FOUND` lines, missing result lines, timeouts and output-limit violations;
- converts successful `FOUND` results immediately into the same normalized M7.1 evidence model and correlation policy used by the parser-only helper.

A clean ClamAV result is returned as clean engine evidence state but does not create malware evidence. This slice intentionally does not yet merge the ClamAV verdict into AAA's top-level native scanner verdict or automatically create a Signature Factory candidate from a ClamAV-only detection; that integration remains explicit follow-up work.

## Historical engines

M8 adapters will eventually feed normalized evidence into this model for:

- VirusZ III;
- VirusExecutor;
- VirusChecker II;
- VirusSlayer II;
- Mill;
- VT-Schutz.

Those adapters must record engine version, database/XVS/Brain identity where observable, OS profile and raw-result provenance. Missing metadata must remain missing rather than being guessed.

## M7.1 initial code qualification

The first M7.1 slice is code-qualified when:

- normalized evidence fields exist without breaking M7.0 schema-v1 records;
- evidence validation fails closed for partially attributed records;
- correlated frontends sharing one `correlation_key` count once;
- independent keys are returned deterministically;
- AAA native bootblock evidence carries structured attribution and correlation identity;
- tests use synthetic evidence only;
- gofmt, vet, tests and amd64/arm64 builds pass.

The ClamAV provenance slice additionally requires:

- strict parsing of the common ClamAV engine/database version form;
- deterministic parsing of `FOUND` versus `OK` result lines;
- a normalized ClamAV evidence constructor that requires engine and signature database identity;
- correlation by ClamAV database identity rather than frontend or engine revision;
- synthetic-only tests covering positive, clean and fail-closed cases.

The bounded execution slice additionally requires:

- no shell interpolation of the target path;
- regular-file validation;
- bounded stdout/stderr;
- bounded execution time;
- explicit ClamAV exit-code semantics;
- fail-closed result/output consistency checks;
- synthetic fake-scanner tests for infected, clean, scanner-error and timeout behavior.

Further M7.1 work will integrate ClamAV engine results with AAA's aggregate scan/candidate pipeline and later historical-engine results before M7.2 export work begins.
