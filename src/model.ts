/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import type { JsonWebKey as NodeJsonWebKey } from "node:crypto";

export const PROTOCOL_ID = "org.robot-identity.authentication" as const;
export const PROTOCOL_VERSION = "0.1" as const;

export type AuthenticationMode = "one-way" | "mutual";
export type VerificationStatus = "verified" | "failed" | "unresolved";
export type PublicKeyJwk = NodeJsonWebKey;

export interface AttributeEnvelope {
  schema: string;
  subject: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  content?: Record<string, unknown>;
  contentReference?: string;
  proof?: Record<string, unknown>;
  statusReference?: string;
}

export interface DiscoveryAdvertisement {
  type: "discovery-advertisement";
  protocol: typeof PROTOCOL_ID;
  version: typeof PROTOCOL_VERSION;
  handle: string;
  modes: AuthenticationMode[];
  profiles: string[];
  issuedAt: string;
  expiresAt: string;
}

export interface AuthenticationInitiation {
  type: "authentication-initiation";
  protocol: typeof PROTOCOL_ID;
  version: typeof PROTOCOL_VERSION;
  sessionId: string;
  verifierNonce: string;
  advertisementHash: string;
  requestedSchemas: string[];
  criticalExtensions: string[];
  extensions: Record<string, unknown>;
  issuedAt: string;
  expiresAt: string;
}

export interface UnsignedAuthenticationPresentation {
  type: "authentication-presentation";
  protocol: typeof PROTOCOL_ID;
  version: typeof PROTOCOL_VERSION;
  sessionId: string;
  verifierNonce: string;
  presenterNonce: string;
  advertisementHash: string;
  presenterKeyId: string;
  presenterPublicKey: PublicKeyJwk;
  attributes: AttributeEnvelope[];
  criticalExtensions: string[];
  extensions: Record<string, unknown>;
  issuedAt: string;
  expiresAt: string;
}

export interface AuthenticationProof {
  algorithm: "Ed25519";
  transcriptHash: string;
  signature: string;
}

export interface AuthenticationPresentation
  extends UnsignedAuthenticationPresentation {
  proof: AuthenticationProof;
}

export interface VerificationCheck {
  status: VerificationStatus;
  detail: string;
}

export interface AttributeVerificationResult {
  schema: string;
  subject: string;
  status: VerificationStatus;
  detail: string;
}

export interface VerificationReport {
  protocol: typeof PROTOCOL_ID;
  version: typeof PROTOCOL_VERSION;
  sessionId: string;
  peerKeyId: string;
  overall: VerificationStatus;
  proofOfPossession: VerificationCheck;
  trustBinding: VerificationCheck;
  freshness: VerificationCheck;
  physicalBinding: {
    status: "endpoint-only" | "secure-range" | "direction" | "optical" | "multi-modal" | "ambiguous";
    detail: string;
  };
  attributes: AttributeVerificationResult[];
  transcriptHash: string;
  reasonCodes: string[];
}

export type TrustedKeySet = Readonly<Record<string, PublicKeyJwk>>;
