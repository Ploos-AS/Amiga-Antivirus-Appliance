# M13.4 — Detached evidence-bundle signatures

Status: IMPLEMENTED — code qualification pending CI

## Purpose

M13.4 adds cryptographic publisher authentication to the portable evidence ZIP introduced by M13.3 without changing the ZIP bytes themselves.

The signature is detached. A signed evidence package consists of:

- the unchanged deterministic M13.3 evidence ZIP;
- a separate signature document, normally `BUNDLE.sig`;
- a trusted Ed25519 public key obtained through an independent trust channel.

The signature proves that the exact bundle bytes were signed by the holder of the private key corresponding to the trusted public key. It does not identify a human or organization unless that key identity has been mapped externally, and it does not by itself assert that a bundled sample is malware.

## Signature schema

Schema identifier:

`aaa-evidence-signature-v1`

Algorithm:

`ed25519`

The detached JSON signature document contains:

- `schema`;
- `algorithm`;
- `bundle_sha256` — SHA-256 of the complete evidence ZIP bytes;
- `signer_key_id` — SHA-256 of the raw 32-byte Ed25519 public key;
- `signature` — 64 raw Ed25519 signature bytes encoded as lowercase hexadecimal.

The document is serialized deterministically with a trailing newline. Unknown fields, unsupported schema/algorithm values and trailing JSON data are rejected.

## Signed statement

AAA signs a domain-separated statement rather than raw ambiguous concatenation:

```text
aaa-evidence-signature-v1
ed25519
<BUNDLE_SHA256>
<SIGNER_KEY_ID>
```

Each line ends with LF, including the final line.

This binds the signature to both the exact bundle identity and the signer key identity, while separating the evidence-signature domain from other Ed25519 uses in AAA.

## Key format

M13.4 uses the same strict raw-key encoding convention as AAA signature distribution while maintaining a separate evidence-signature protocol:

- private key file: exactly 64 raw Ed25519 private-key bytes encoded as 128 lowercase hexadecimal characters plus LF;
- public key file: exactly 32 raw Ed25519 public-key bytes encoded as 64 lowercase hexadecimal characters plus LF.

AAA does not generate, publish, retain or escrow private keys in M13.4. Key generation, storage, rotation, revocation and mapping of key IDs to publisher identities remain operator responsibilities.

The detached signature never carries a public key that can make itself trusted. Verification requires a public key supplied independently by the operator.

## CLI

Sign an already valid M13.3 bundle:

```text
aaa evidence sign --private-key <private-key-file> [--output <bundle.sig>] <bundle.zip>
```

When `--output` is omitted, the output is `<bundle.zip>.sig`.

Verify a signed bundle offline:

```text
aaa evidence verify-signed --trusted-key <public-key-file> [--signature <bundle.sig>] <bundle.zip>
```

When `--signature` is omitted, AAA reads `<bundle.zip>.sig`.

Signature output is write-once and will not replace an existing file.

## Signing gate

Before signing, AAA performs the complete M13.3 `VerifyArchive` gate. Invalid evidence bundles are not signed.

Signing then computes the SHA-256 of the exact ZIP bytes and produces the detached Ed25519 signature. The bundle itself is never modified, preserving M13.3 deterministic archive identity.

## Verification gate

Signed verification is entirely offline and must succeed only when all of the following hold:

1. the detached signature document is structurally valid;
2. the supplied trusted public key is valid and its derived key ID equals `signer_key_id`;
3. the M13.3 archive structure, manifest and all declared evidence hashes validate;
4. the SHA-256 of the complete ZIP matches `bundle_sha256`;
5. the Ed25519 signature verifies over the domain-separated signed statement.

A failure in any gate is a verification failure. No bundled content is extracted or executed.

## Security boundaries

M13.4 provides cryptographic integrity and possession-of-key authentication. It does not provide timestamp authority, certificate-chain identity, transparency logging, key revocation, archival notarization or malware-classification authority.

A recipient must establish trust in the public key separately. A valid signature means that the exact evidence bundle was signed by the corresponding private-key holder; it does not elevate submitted or unknown evidence to verified malware.

Private keys and detached signature files are required to be ordinary regular files for CLI consumption. Symbolic-link key/signature paths are rejected.

## Qualification

No physical hardware is required for M13.4 code qualification.

Automated qualification covers:

- deterministic detached signature serialization;
- valid sign and offline verify flow;
- exact bundle SHA-256 binding;
- signer key-ID binding;
- wrong trusted-key rejection;
- bundle-tampering rejection;
- unknown/trailing signature JSON rejection;
- strict lowercase key-file format;
- write-once detached signature output;
- symbolic-link key/signature rejection;
- existing M13.3 archive validation before signing and during verification.

Hardware/runtime qualification may later exercise the same mechanism on a bundle containing real M12 acquisition evidence, but that is not required to code-qualify M13.4.
