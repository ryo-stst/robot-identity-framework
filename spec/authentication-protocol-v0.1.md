# Robot Identity Authentication Protocol v0.1

Status: **Experimental design draft**. This document is not an interoperability commitment, production security claim, certification, or recognized standard.

## 1. Objective

Define a minimal protocol through which two or more Physical AI endpoints can verify key possession and authenticated attributes, in one or both directions, without requiring continuous access to a central service.

## 2. Scope

The protocol covers:

- discovery metadata;
- fresh challenge and response;
- proof of identity-key possession;
- arbitrary authenticated attribute envelopes;
- offline/local trust material;
- a verification report;
- replaceable bearer, key, and physical-binding adapters.

It does not define authorization, action decisions, robot commands, operational safety decisions, or the business meaning of domain-specific attributes.

## 3. Architectural boundaries

### 3.1 Bearer independence

Authentication messages and the signed transcript are independent of the transport. A bearer profile maps discovery and message delivery to BLE, local Wi-Fi, vehicle communications, simulation, or another medium. The bearer is not the robot identity.

The initial reference SDK uses in-memory object delivery. No BLE or Internet connection is required.

### 3.2 No global identity database

The verifier receives trust material through local configuration or a separately defined distribution mechanism. This protocol does not require a globally shared database or hosted control plane.

### 3.3 Authentication only

A successful report means that defined authentication evidence was verified. Another system decides whether any operation is permitted.

### 3.4 Endpoint and physical body are separate

A valid cryptographic proof authenticates an endpoint. It does not by itself establish which visible robot body produced the radio signal. A physical-binding adapter may add ranging, direction, optical, or multi-modal evidence. Without such evidence, the result is `endpoint-only`.

## 4. One-way exchange

1. The presenter emits a `DiscoveryAdvertisement` through a bearer.
2. The verifier creates an `AuthenticationInitiation` with a fresh session identifier and nonce.
3. The presenter signs a transcript containing the advertisement, initiation, and unsigned presentation.
4. The verifier checks binding, freshness, signature, replay state, and locally supplied trust material.
5. The verifier produces a `VerificationReport`.

Mutual authentication consists of two separately accountable verification results bound to shared session context. It does not imply permission for a joint action.

## 5. Logical messages

### 5.1 `DiscoveryAdvertisement`

- protocol identifier and version;
- short-lived rotating handle;
- supported authentication modes;
- supported bearer/profile identifiers;
- issue and expiry time.

It must not broadcast a permanent identity, owner, position, or credential body. The advertisement is untrusted discovery input; authenticity is established by the later signed transcript.

### 5.2 `AuthenticationInitiation`

- protocol and profile version;
- unique session identifier;
- unpredictable verifier nonce;
- hash of the observed advertisement;
- requested attribute schema identifiers;
- critical extensions;
- issue and expiry time.

### 5.3 `AuthenticationPresentation`

- session identifier and verifier nonce;
- fresh presenter nonce;
- advertisement hash;
- presenter key identifier and public-key material or reference;
- zero or more attribute envelopes;
- issue and expiry time;
- proof over the complete transcript.

### 5.4 `VerificationReport`

- peer identifier visible in this context;
- proof-of-possession result;
- trust-binding result;
- freshness and replay result;
- per-attribute result;
- physical-binding result;
- transcript hash and reason codes.

The report must not contain `permit`, `deny`, a safety verdict, or a robot command.

## 6. Attribute envelope

Domain owners define their own schema and semantics. The core carries provenance and verification data without interpreting business meaning.

```json
{
  "schema": "https://domain.example/schema/v1",
  "subject": "pairwise:subject-reference",
  "issuer": "issuer-reference",
  "issuedAt": "2026-08-08T00:00:00Z",
  "expiresAt": "2026-08-08T00:05:00Z",
  "content": {},
  "proof": {},
  "statusReference": null
}
```

Inline content and a content reference are mutually exclusive.

## 7. Alpha implementation profile

The TypeScript alpha uses:

- deterministic, recursively key-sorted JSON for local demonstration;
- SHA-256 transcript hashes;
- Ed25519 signatures;
- locally configured public-key bindings;
- a process-local replay guard.

This profile is not yet a normative wire format. A production profile must complete review of established IETF building blocks, credential/status formats, durable replay handling, algorithm agility, privacy properties, and conformance vectors.

## 8. Required negative tests

Implementations should cover wrong keys, modified transcripts, replay, wrong sessions, expired material, revoked credentials, stale status data, unknown critical extensions, attribute-subject mismatch, relay without physical binding, ambiguous physical targets, and stable discovery identifiers.

## 9. Security and privacy limits

- Self-presented public keys prove possession but not trusted identity. Without a trusted binding, the result is `unresolved`.
- Fresh nonces and expiry windows do not replace durable replay handling.
- Discovery radio metadata may still enable tracking; bearer profiles need privacy analysis.
- Physical proximity cannot be inferred from a valid signature alone.
- No production deployment should rely on this alpha without independent security review.

## 10. Licensing

This specification is licensed under Apache License 2.0 together with the repository. The project name does not imply certification, endorsement, or trademark permission.
