/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

export interface ReplayGuard {
  has(sessionId: string): boolean;
  consume(sessionId: string): void;
}

/** Demonstration-only process-local replay guard. Production adapters need durable policy. */
export class InMemoryReplayGuard implements ReplayGuard {
  readonly #sessions = new Set<string>();

  has(sessionId: string): boolean {
    return this.#sessions.has(sessionId);
  }

  consume(sessionId: string): void {
    this.#sessions.add(sessionId);
  }
}
