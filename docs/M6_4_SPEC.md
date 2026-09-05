# M6.4 — Preservation disk-image formats

## Goal

Add read-only antivirus analysis for preservation-oriented floppy images that cannot always be represented faithfully as a sector-only ADF.

M6.4 starts with two formats:

- M6.4a: IPF (Interchangeable Preservation Format / CAPS/SPS)
- M6.4b: FDI (Formatted Disk Image)

Support is preservation-first: AAA never rewrites, normalizes, repairs, or converts the submitted original in place.

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

AAA will use an adapter boundary rather than link CAPS code into the MIT-licensed Go core. The adapter must support Linux/arm64 because Orange Pi Zero 3 is the reference appliance.

The preferred implementation is a small bounded helper process that uses a user-installed CAPSImage-compatible decoder library. The helper is optional and separately licensed. AAA itself will not vendor or silently download the CAPS/SPS library.

The adapter contract is:

`IPF → bounded CAPS decoder helper → Amiga track/sector view → native AAA analysis`

For standard readable AmigaDOS sectors, AAA may construct a transient sector image and pass it to the existing ADF/filesystem/bootblock pipeline. The report must mark that image as derived from IPF and record its SHA-256 separately.

For tracks that cannot be reduced losslessly to normal AmigaDOS sectors, AAA must still retain/report low-level track metadata and return an explicit partial/unsupported analysis state rather than declaring the disk clean.

### IPF dependency policy

CAPS/SPS decoder implementations use licensing terms separate from AAA's MIT license. They therefore remain optional external components. The appliance installer may detect and qualify an already installed compatible decoder but must not bundle it as though it were MIT project code.

## M6.4b — FDI

FDI is a documented low-level floppy-image format. AAA will prefer an independently auditable parser/adapter whose license permits redistribution with the appliance. If the selected implementation is not suitable for direct inclusion, FDI will use the same bounded external-helper pattern as IPF.

The FDI path is:

`FDI → bounded parser/helper → Amiga track/sector view → native AAA analysis`

As with IPF, any ADF-compatible sector image is a derived scan view, not a replacement for the original evidence.

## Result model

M6.4 should add preservation-image metadata without overloading the existing ADF object. The expected shape is conceptually:

```json
{
  "format": "ipf",
  "sha256": "<original image sha256>",
  "preservation_image": {
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

Exact fields may evolve during implementation, but provenance between original and derived data is mandatory.

## Format identification

File suffixes `.ipf` and `.fdi` are candidates only. Identification by extension alone is insufficient for a successful scan. The selected decoder/parser must confirm the input format before AAA claims it was decoded.

## Qualification

M6.4a is code-qualified when:

- IPF candidate identification exists;
- the adapter/helper boundary is covered by deterministic tests using a fake decoder;
- output, timeout, and error paths are bounded;
- a synthetic adapter result can feed a valid derived ADF into the existing native scanner;
- missing decoder and malformed decoder output fail closed;
- gofmt, vet, tests, linux/amd64 build and linux/arm64 build pass.

Runtime qualification additionally requires a provenance-safe real Amiga IPF fixture and a CAPS-compatible decoder on the Orange Pi/DietPi reference appliance.

M6.4b receives the equivalent qualification with a provenance-safe FDI fixture and the selected FDI parser/helper.

## Non-goals

M6.4 does not write IPF/FDI files, repair copy-protected disks, emulate the original software, or claim that every protected track can be represented as ADF. Flux formats such as SCP and KryoFlux streams are future preservation extensions and are not part of the initial M6.4 exit gate.
