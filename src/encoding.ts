/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import { createHash, randomBytes } from "node:crypto";

function normalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Canonical JSON does not accept non-finite numbers");
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(normalize);
  }

  if (typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const member = (value as Record<string, unknown>)[key];
      if (member === undefined) {
        continue;
      }
      output[key] = normalize(member);
    }
    return output;
  }

  throw new TypeError(`Canonical JSON does not accept ${typeof value}`);
}

/** Alpha-only deterministic JSON mapping. It is not yet a normative wire format. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function sha256Base64Url(value: unknown): string {
  return createHash("sha256").update(canonicalBytes(value)).digest("base64url");
}

export function randomBase64Url(bytes = 16): string {
  return randomBytes(bytes).toString("base64url");
}

export function sameJson(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}
