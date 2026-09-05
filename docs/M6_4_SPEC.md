# M6.4 — Preservation disk-image formats

## Goal

Add read-only antivirus analysis for preservation-oriented floppy images that cannot always be represented faithfully as a sector-only ADF.

M6.4 starts with two formats:

- M6.4a: IPF (Interchangeable Preservation Format / CAPS/SPS)
- M6.4b: FDI (Formatted Disk Image)

Support is preservation-first: AAA never rewrites, normalizes, repairs, or converts the submitted original in place.

## Status

Both initial preservation paths are now code-qualified:

- M6.4a IPF: bounded optional helper adapter, candidate identification, preservation provenance, derived-sector hashing, native ADF scanner integration, deterministic fake-helper tests, and fail-closed error handling are implemented and CI-qualified.
- M6.4b FDI: equivalent bounded helper adapter and scanner integration are implemented and CI-qualified.

The code qualification does **not** claim end-to-end runtime support for arbitrary real IPF or FDI media. Real provenance-safe fixtures, a compatible real decoder/parser, and Orange Pi Zero 3/DietPi runtime qualification remain required. In particular, AAA does not bundle CAPS/SPS decoder code.

## Why this belongs in AAA

Commercial Amiga software and some protected disks use track layouts, weak data, non-standard sectors, or other low-level structures that a normal ADF cannot preserve. Antivirus inspection must therefore be able to consume preservation images without pretending that conversion to a normal ADF is always lossless.

The submitted IPF/FDI image remains the primary evidence object and retains its own SHA-256. Any sector stream or derived ADF-compatible view used for filesystem scanning is secondary derived evidence and must be identified as such in the report.

## Common safety contract

- read-only input;
- no execution of data from the image;
- no modification of the submitted image;
- bounded decoder output and bounded processing time;
- no host-path extraction based on image metadata;
- malformed, unsupported, encrypted, decoder-missing, or over-limit inputs fail closed;
- derived data is transient unless an operator explicitly requests preservation/export later;
- the original image hash and format are always retained in the scan result;
- a derived sector image must never replace the original evidence identity.

## M6.4a — IPF

IPF decoding requires the CAPS/SPS decoder model because IPF preserves track-level information that cannot be parsed safely by treating the file as a normal block image.

AAA uses an adapter boundary rather than link CAPS code into the MIT-licensed Go core. The adapter is designed for Linux/arm64 because Orange Pi Zero 3 is the reference appliance.

The implementation uses a bounded helper process selected with `AAA_IPF_HELPER`. The helper is optional and separately installed/licensed. AAA itself does not vendor or silently download the CAPS/SPS library.

The adapter contract is:

`IPF → bounded CAPS decoder helper → Amiga track/sector view → native AAA analysis`

The helper must positively confirm `format: "ipf"`. Its metadata and stderr are bounded, execution has a timeout, and any derived sector image is bounded and hashed by AAA. A lossless derived sector view is passed to the existing ADF/filesystem/bootblock pipeline while the original IPF hash remains the primary evidence identity.

For tracks that cannot be reduced losslessly to normal AmigaDOS sectors, AAA must retain/report the preservation metadata and must not infer a clean verdict from an absent sector view.

### IPF dependency policy

CAPS/SPS decoder implementations use licensing terms separate from AAA's MIT license. They therefore remain optional external components. The appliance installer may detect and qualify an already installed compatible decoder but must not bundle it as though it were MIT project code.

## M6.4b — FDI

FDI uses the same preservation-first helper boundary, selected with `AAA_FDI_HELPER`. The helper must positively confirm `format: "fdi"`; output, metadata, stderr and processing time are bounded, and any derived lossless sector image is hashed independently before native ADF analysis.

The FDI path is:

`FDI → bounded parser/helper → Amiga track/sector view → native AAA analysis`

As with IPF, any ADF-compatible sector image is a derived scan view, not a replacement for the original evidence. A real redistributable FDI backend remains a runtime-integration decision; the current helper protocol deliberately keeps that dependency outside the core scanner.

## Result model

M6.4 adds preservation-image metadata without overloading the existing ADF object. The implemented result shape follows this model:

```json
{
  "format": "ipf",
  "sha256": "<original image sha256>",
  "preservation_image": {
    "format": "ipf",
    "decoder": "...",
    "decoder_version": "...",
    "platform": "amiga",
    "tracks": 160,
    "derived_sector_image": {
      "size": 901120,
      "sha256": "...",
      "lossless_for_sector_scan": true
    }
  },
  "adf": { "...": "native AAA analysis of derived sectors" }
}
```

Provenance between original and derived data is mandatory.

## Format identification

File suffixes `.ipf` and `.fdi` are candidates only. Identification by extension alone is insufficient for a successful scan. The selected decoder/parser must confirm the input format before AAA claims it was decoded.

## Qualification

M6.4a code qualification requires:

- IPF candidate identification;
- deterministic adapter/helper tests using a fake decoder;
- bounded output, timeout, and error paths;
- a synthetic adapter result feeding a valid derived ADF into the existing native scanner;
- missing decoder and malformed decoder output failing closed;
- gofmt, vet, tests, linux/amd64 build and linux/arm64 build passing.

These code gates are complete. CI #117 qualified the IPF scanner integration.

M6.4b receives the equivalent qualification. These code gates are also complete. CI #121 qualified the FDI scanner integration.

Runtime qualification remains open and requires:

- a provenance-safe real Amiga IPF fixture plus a CAPS-compatible decoder;
- a provenance-safe real Amiga FDI fixture plus the selected compatible parser/helper;
- execution on the Orange Pi Zero 3/DietPi reference appliance;
- verification that original and derived hashes/provenance remain distinct;
- confirmation that unsupported/non-lossless preservation structures never become a false clean result.

## Exit state

M6.4 is **code-qualified, runtime-pending**. Development can proceed to M7 without treating the outstanding hardware/real-fixture qualification as completed.

## Non-goals

M6.4 does not write IPF/FDI files, repair copy-protected disks, emulate the original software, or claim that every protected track can be represented as ADF. Flux formats such as SCP and KryoFlux streams are future preservation extensions and are not part of the initial M6.4 exit gate.
