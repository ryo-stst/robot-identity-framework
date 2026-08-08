/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import { keyIdFor, signObject, verifyObject, type IdentityKeyPair } from "./crypto.js";
import { randomBase64Url, sameJson, sha256Base64Url } from "./encoding.js";
import {
  PROTOCOL_ID,
  PROTOCOL_VERSION,
  type AttributeEnvelope,
  type AuthenticationInitiation,
  type AuthenticationPresentation,
  type DiscoveryAdvertisement,
  type TrustedKeySet,
  type UnsignedAuthenticationPresentation,
  type VerificationReport,
  type VerificationStatus,
} from "./model.js";
import type { ReplayGuard } from "./replay.js";

const DEFAULT_TTL_MS = 30_000;

function addMilliseconds(now: Date, milliseconds: number): string {
  return new Date(now.getTime() + milliseconds).toISOString();
}

function validAt(issuedAt: string, expiresAt: string, now: Date): boolean {
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  return Number.isFinite(issued)
    && Number.isFinite(expires)
    && issued <= now.getTime()
    && now.getTime() <= expires
    && issued < expires;
}

export function createDiscoveryAdvertisement(options: {
  profiles?: string[];
  modes?: Array<"one-way" | "mutual">;
  now?: Date;
  ttlMs?: number;
} = {}): DiscoveryAdvertisement {
  const now = options.now ?? new Date();
  return {
    type: "discovery-advertisement",
    protocol: PROTOCOL_ID,
    version: PROTOCOL_VERSION,
    handle: randomBase64Url(16),
    modes: options.modes ?? ["one-way"],
    profiles: options.profiles ?? ["in-memory-1"],
    issuedAt: now.toISOString(),
    expiresAt: addMilliseconds(now, options.ttlMs ?? DEFAULT_TTL_MS),
  };
}

export function createAuthenticationInitiation(
  advertisement: DiscoveryAdvertisement,
  options: {
    requestedSchemas?: string[];
    criticalExtensions?: string[];
    extensions?: Record<string, unknown>;
    now?: Date;
    ttlMs?: number;
  } = {},
): AuthenticationInitiation {
  const now = options.now ?? new Date();
  if (!validAt(advertisement.issuedAt, advertisement.expiresAt, now)) {
    throw new Error("Cannot initiate authentication from a stale advertisement");
  }

  return {
    type: "authentication-initiation",
    protocol: PROTOCOL_ID,
    version: PROTOCOL_VERSION,
    sessionId: randomBase64Url(16),
    verifierNonce: randomBase64Url(32),
    advertisementHash: sha256Base64Url(advertisement),
    requestedSchemas: options.requestedSchemas ?? [],
    criticalExtensions: options.criticalExtensions ?? [],
    extensions: options.extensions ?? {},
    issuedAt: now.toISOString(),
    expiresAt: addMilliseconds(now, options.ttlMs ?? DEFAULT_TTL_MS),
  };
}

function unsignedPresentation(
  initiation: AuthenticationInitiation,
  identity: IdentityKeyPair,
  attributes: AttributeEnvelope[],
  now: Date,
  ttlMs: number,
): UnsignedAuthenticationPresentation {
  return {
    type: "authentication-presentation",
    protocol: PROTOCOL_ID,
    version: PROTOCOL_VERSION,
    sessionId: initiation.sessionId,
    verifierNonce: initiation.verifierNonce,
    presenterNonce: randomBase64Url(32),
    advertisementHash: initiation.advertisementHash,
    presenterKeyId: identity.keyId,
    presenterPublicKey: identity.publicKey,
    attributes,
    criticalExtensions: [],
    extensions: {},
    issuedAt: now.toISOString(),
    expiresAt: addMilliseconds(now, ttlMs),
  };
}

export function authenticationTranscript(
  advertisement: DiscoveryAdvertisement,
  initiation: AuthenticationInitiation,
  presentation: UnsignedAuthenticationPresentation,
): Record<string, unknown> {
  return { advertisement, initiation, presentation };
}

export function createAuthenticationPresentation(
  advertisement: DiscoveryAdvertisement,
  initiation: AuthenticationInitiation,
  identity: IdentityKeyPair,
  options: {
    attributes?: AttributeEnvelope[];
    now?: Date;
    ttlMs?: number;
  } = {},
): AuthenticationPresentation {
  const now = options.now ?? new Date();
  if (sha256Base64Url(advertisement) !== initiation.advertisementHash) {
    throw new Error("Initiation is not bound to this advertisement");
  }
  if (!validAt(initiation.issuedAt, initiation.expiresAt, now)) {
    throw new Error("Cannot present against a stale initiation");
  }

  const unsigned = unsignedPresentation(
    initiation,
    identity,
    options.attributes ?? [],
    now,
    options.ttlMs ?? DEFAULT_TTL_MS,
  );
  const transcript = authenticationTranscript(advertisement, initiation, unsigned);
  return {
    ...unsigned,
    proof: {
      algorithm: "Ed25519",
      transcriptHash: sha256Base64Url(transcript),
      signature: signObject(transcript, identity.privateKey),
    },
  };
}

function withoutProof(
  presentation: AuthenticationPresentation,
): UnsignedAuthenticationPresentation {
  const { proof: _proof, ...unsigned } = presentation;
  return unsigned;
}

function failedReport(
  presentation: AuthenticationPresentation,
  transcriptHash: string,
  reasonCodes: string[],
  freshness: VerificationStatus = "failed",
): VerificationReport {
  return {
    protocol: PROTOCOL_ID,
    version: PROTOCOL_VERSION,
    sessionId: presentation.sessionId,
    peerKeyId: presentation.presenterKeyId,
    overall: "failed",
    proofOfPossession: {
      status: "failed",
      detail: "The transcript proof could not be accepted.",
    },
    trustBinding: {
      status: "unresolved",
      detail: "Trust was not evaluated after a failed proof.",
    },
    freshness: {
      status: freshness,
      detail: freshness === "failed" ? "Freshness validation failed." : "Freshness was valid.",
    },
    physicalBinding: {
      status: "endpoint-only",
      detail: "No physical-entity binding evidence was supplied.",
    },
    attributes: presentation.attributes.map((attribute) => ({
      schema: attribute.schema,
      subject: attribute.subject,
      status: "unresolved",
      detail: "Attribute issuer-proof verification is not implemented in this alpha.",
    })),
    transcriptHash,
    reasonCodes,
  };
}

export function verifyAuthenticationPresentation(
  advertisement: DiscoveryAdvertisement,
  initiation: AuthenticationInitiation,
  presentation: AuthenticationPresentation,
  options: {
    trustedKeys?: TrustedKeySet;
    supportedCriticalExtensions?: string[];
    replayGuard?: ReplayGuard;
    now?: Date;
  } = {},
): VerificationReport {
  const now = options.now ?? new Date();
  const unsigned = withoutProof(presentation);
  const transcript = authenticationTranscript(advertisement, initiation, unsigned);
  const transcriptHash = sha256Base64Url(transcript);
  const supported = new Set(options.supportedCriticalExtensions ?? []);

  const stale = !validAt(initiation.issuedAt, initiation.expiresAt, now)
    || !validAt(presentation.issuedAt, presentation.expiresAt, now);
  if (stale) {
    return failedReport(presentation, transcriptHash, ["STALE_SESSION"], "failed");
  }

  if (options.replayGuard?.has(presentation.sessionId)) {
    return failedReport(presentation, transcriptHash, ["REPLAY_DETECTED"], "verified");
  }

  const unknownCritical = [
    ...initiation.criticalExtensions,
    ...presentation.criticalExtensions,
  ].filter((extension) => !supported.has(extension));
  if (unknownCritical.length > 0) {
    return failedReport(
      presentation,
      transcriptHash,
      unknownCritical.map((extension) => `UNKNOWN_CRITICAL_EXTENSION:${extension}`),
      "verified",
    );
  }

  const bindingMatches = initiation.protocol === PROTOCOL_ID
    && initiation.version === PROTOCOL_VERSION
    && advertisement.protocol === PROTOCOL_ID
    && advertisement.version === PROTOCOL_VERSION
    && validAt(
      advertisement.issuedAt,
      advertisement.expiresAt,
      new Date(initiation.issuedAt),
    )
    && presentation.protocol === PROTOCOL_ID
    && presentation.version === PROTOCOL_VERSION
    && sha256Base64Url(advertisement) === initiation.advertisementHash
    && presentation.advertisementHash === initiation.advertisementHash
    && presentation.sessionId === initiation.sessionId
    && presentation.verifierNonce === initiation.verifierNonce
    && presentation.presenterKeyId === keyIdFor(presentation.presenterPublicKey)
    && presentation.proof.algorithm === "Ed25519"
    && presentation.proof.transcriptHash === transcriptHash;

  const signatureValid = bindingMatches && verifyObject(
    transcript,
    presentation.proof.signature,
    presentation.presenterPublicKey,
  );
  if (!signatureValid) {
    return failedReport(presentation, transcriptHash, ["INVALID_TRANSCRIPT_PROOF"], "verified");
  }

  options.replayGuard?.consume(presentation.sessionId);

  const trustedKey = options.trustedKeys?.[presentation.presenterKeyId];
  let overall: VerificationStatus;
  let trustBinding: VerificationReport["trustBinding"];
  const reasonCodes: string[] = [];
  if (trustedKey === undefined) {
    overall = "unresolved";
    trustBinding = {
      status: "unresolved",
      detail: "Proof is valid, but no trusted key binding was supplied locally.",
    };
    reasonCodes.push("TRUST_BINDING_UNRESOLVED");
  } else if (!sameJson(trustedKey, presentation.presenterPublicKey)) {
    overall = "failed";
    trustBinding = {
      status: "failed",
      detail: "The presented public key does not match the locally trusted binding.",
    };
    reasonCodes.push("TRUST_KEY_MISMATCH");
  } else {
    overall = "verified";
    trustBinding = {
      status: "verified",
      detail: "The presented key matches locally supplied trust material.",
    };
  }

  return {
    protocol: PROTOCOL_ID,
    version: PROTOCOL_VERSION,
    sessionId: presentation.sessionId,
    peerKeyId: presentation.presenterKeyId,
    overall,
    proofOfPossession: {
      status: "verified",
      detail: "The Ed25519 signature covers the advertisement, initiation, and presentation.",
    },
    trustBinding,
    freshness: {
      status: "verified",
      detail: "Initiation and presentation are inside their validity windows.",
    },
    physicalBinding: {
      status: "endpoint-only",
      detail: "The cryptographic endpoint is authenticated; no visible-body binding is claimed.",
    },
    attributes: presentation.attributes.map((attribute) => ({
      schema: attribute.schema,
      subject: attribute.subject,
      status: "unresolved",
      detail: "Attribute issuer-proof verification is not implemented in this alpha.",
    })),
    transcriptHash,
    reasonCodes,
  };
}
