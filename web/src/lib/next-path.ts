// SPDX-License-Identifier: Apache-2.0

// Where to go after sign-in. Only a same-origin console path is accepted:
// never a scheme, another host ("//host"), a backslash form, the sign-in page
// itself or a server-handled /auth endpoint.
export function safeNextPath(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 2048) return undefined;
  if (!value.startsWith("/") || value.startsWith("//") || /[\\\s]/.test(value)) return undefined;
  let url: URL;
  try {
    url = new URL(value, window.location.origin);
  } catch {
    return undefined;
  }
  if (url.origin !== window.location.origin) return undefined;
  if (url.pathname === "/" || url.pathname === "/enroll" || url.pathname.startsWith("/auth/"))
    return undefined;
  return `${url.pathname}${url.search}${url.hash}`;
}

// Organization sign-in leaves the console and returns to "/", so the
// destination waits in this tab's session storage for that round trip.
const pendingKey = "lindm-next-path";

export function rememberNextPath(path: string | undefined): void {
  try {
    if (path) sessionStorage.setItem(pendingKey, path);
    else sessionStorage.removeItem(pendingKey);
  } catch {
    // Without storage the console opens the dashboard after sign-in.
  }
}

export function pendingNextPath(): string | undefined {
  try {
    return safeNextPath(sessionStorage.getItem(pendingKey));
  } catch {
    return undefined;
  }
}
