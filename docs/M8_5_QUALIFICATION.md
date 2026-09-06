# M8.5 — Multi-engine historical evidence orchestration

## Status

**Code qualification in progress. Runtime qualification pending.**

M8.5 adds deterministic aggregation of independent historical-scanner results without collapsing disagreement into a single opaque verdict.

## Qualified behavior

The aggregate layer:

- requires every result to pass the common M8 evidence validator;
- requires all results to refer to the same input SHA-256;
- rejects duplicate results from the same engine;
- preserves every per-engine result and raw-evidence identity;
- deterministically sorts results by engine ID;
- counts verdicts without hiding minority results;
- exposes which engines produced each verdict;
- records whether different verdict classes disagree;
- treats at least two independent infected results with the same normalized detection name as corroborating research evidence;
- does not treat differently named detections as corroboration;
- does not allow corroboration to erase simultaneous clean/unknown/error evidence.

## AmiGuard research boundary

`Corroborated` is deliberately a research-evidence property only. It can increase confidence in an AAA signature candidate and can therefore support the AAA → AmiGuard research bridge, but it must never by itself promote an AmiGuard signature to `verified` or otherwise bypass AmiGuard sample/pattern qualification.

The aggregate preserves the exact per-engine evidence needed to audit why a candidate was considered corroborated.

## Runtime boundary

Ordinary CI uses synthetic normalized results. M8.5 does not by itself prove that multiple historical scanner binaries can yet be orchestrated under real AmigaOS profiles on the target appliance.

Runtime qualification still requires actual user-supplied scanner/OS environments, the M8.2 emulator lifecycle, controlled clean/infected samples and target-platform execution.

## Next gate

After green CI, M8.6 is target appliance qualification. Before calling M8 appliance-qualified, the intended scanner versions must be exercised on Orange Pi Zero 3 + DietPi and per-engine limitations, timings and resource behavior must be recorded.
