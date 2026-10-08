export type AuthLifetime = {
  readonly identity: string;
  readonly generation: number;
  readonly signal: AbortSignal;
};

let current: AuthLifetime | null = null;
let controller: AbortController | null = null;
let generation = 0;
const listeners = new Set<() => void>();

export function getAuthLifetime(): AuthLifetime | null {
  return current;
}

export function subscribeAuthLifetime(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// A session, principal or authorization change invalidates outstanding work before
// publishing the next identity. Query-cache removal alone does not cancel mutations.
export function synchronizeAuthLifetime(identity: string | null): boolean {
  if ((current?.identity ?? null) === identity) return false;
  controller?.abort();
  controller = identity === null ? null : new AbortController();
  current =
    identity !== null && controller !== null
      ? { identity, generation: ++generation, signal: controller.signal }
      : null;
  for (const listener of listeners) listener();
  return true;
}
