# M10.3 — Engine evidence cards

## Goal

Present the M10.2 `engine_results` contract as first-class, attributed evidence in the appliance Web UI without creating a second aggregation model.

## UI contract

Each engine result is rendered as its own card with the fields available in the common engine-evidence envelope:

- engine kind, ID and human-readable name;
- engine version;
- execution status and verdict;
- detection name when present;
- input SHA-256;
- database ID/version when available;
- AmigaOS profile for historical engines;
- scanner binary SHA-256 when available;
- raw-evidence SHA-256 when available;
- independently versioned support components, including M8.7 XVS/VirusZ support provenance.

The UI labels the three current engine kinds as AAA Native, ClamAV and Historical Amiga. Historical scanner names remain engine-specific, so VirusZ, VirusExecutor and other adapters appear by their recorded engine identity rather than being collapsed into one anonymous historical result.

## Disagreement semantics

The browser computes a display-only disagreement indicator from completed engine verdicts. If two or more distinct completed verdict values are present, the UI shows an explicit `Engine disagreement` warning and retains every engine card.

This indicator does not change the persisted aggregate verdict and is not a new policy engine. Error results are shown separately and do not silently become clean/unknown evidence.

## Compatibility

M10.3 consumes the additive `engine_results` array introduced by M10.2. Existing native analysis cards, archive-member presentation and raw API JSON remain available.

Scans created before M10.2 may have no `engine_results`; the UI handles that state explicitly rather than fabricating attribution.

## Security and dependency boundary

M10.3 remains embedded in the existing Go binary. It adds no npm/Node runtime, CDN, remote JavaScript, external fonts, analytics or additional network origin. Existing M9.4/M10.0 CSP and localhost-default exposure rules remain unchanged.

## Qualification gate

M10.3 is code-qualified when:

1. `engine_results` is rendered as individual engine cards;
2. native, ClamAV and historical-Amiga engine kinds have explicit UI labels;
3. engine/database/OS/binary/raw-evidence provenance fields are represented;
4. support components are represented;
5. completed verdict disagreement is visible without hiding per-engine records;
6. scans without engine evidence remain renderable;
7. the raw API result remains available for audit/debug;
8. `gofmt`, module metadata, `go vet`, `go test ./...`, linux/amd64 and linux/arm64 builds pass in CI.

Visual browser qualification and target Orange Pi Zero 3/DietPi qualification remain runtime gates.
