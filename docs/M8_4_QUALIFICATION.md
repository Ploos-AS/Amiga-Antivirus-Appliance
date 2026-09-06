# M8.4 — OS 2.x/3.x historical scanner adapters

## Status

**Adapter/fixture qualification in progress. Runtime qualification pending.**

M8.4 covers the initial adapters for VirusZ III v1.04ß, VirusExecutor v2.34, VirusChecker II v2.5, VirusSlayer II v1.0b and Mill v0.85.

## Code scope

The M8.4 common parser/result path is deliberately conservative. Synthetic fixtures cover explicit clean, infected, suspicious, unknown and runtime-failure outcomes. Unrecognized successful output remains `unknown`; it is never promoted to `clean` merely because no detection marker matched.

The common M8.1 evidence model preserves the exact raw scanner log and its SHA-256, input identity, scanner binary identity, timestamps, declared scanner version and selected OS profile. The adapter rejects an OS profile not declared for that engine in the M8 inventory.

VT-Schutz remains on its dedicated M8.3 `os13` adapter and is intentionally rejected by the M8.4 common path.

## Qualification boundary

The parser strings used by ordinary CI are synthetic compatibility fixtures. They are not claims about the complete literal output vocabulary of the proprietary/historical scanner binaries.

Actual runtime qualification requires each intended scanner/version to be run under each profile we claim for it, using user-supplied licensed software and controlled known-clean and known-infected inputs. Per-engine records must capture scanner binary SHA-256, profile identity, input hashes, raw output, normalized result and proof that original evidence was not modified.

Until those runs exist, these engines are **adapter/fixture-qualified only**, not runtime-qualified or appliance-qualified.

## AmiGuard research relationship

M8 historical detections can become corroborating evidence for AAA signature candidates and therefore feed the existing AAA → AmiGuard research bridge. A historical scanner verdict must not directly create or promote an AmiGuard production signature. AmiGuard sample/signature qualification remains a separate explicit gate.

## Next gate

After green CI, M8.5 can add multi-engine orchestration and disagreement-preserving aggregate evidence. Real scanner runtime automation/qualification remains separately required before M8 can make runtime compatibility claims.
