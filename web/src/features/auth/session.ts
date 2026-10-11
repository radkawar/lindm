import { fromJson, type JsonValue } from "@bufbuild/protobuf";
import { SessionPrincipalSchema, type SessionPrincipal } from "../../../gen/lindm/auth/v1/auth_pb";

export type { SessionPrincipal };

export const loginHref = "/auth/login";

export async function fetchSession(signal?: AbortSignal): Promise<SessionPrincipal | null> {
  const response = await fetch("/auth/session", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
    signal,
  });
  if (response.status === 401) return null;
  if (!response.ok) throw new Error(await readError(response));
  const principal = fromJson(SessionPrincipalSchema, (await response.json()) as JsonValue);
  if (principal.csrfToken === "") {
    throw new Error("Couldn't start your session. Reload the page.");
  }
  return principal;
}

export async function postLogout(csrfToken: string): Promise<void> {
  const response = await fetch("/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "manual",
    headers: {
      Accept: "application/json",
      "X-CSRF-Token": csrfToken,
    },
  });
  if (response.status === 401 || response.ok) return;
  if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
    return;
  }
  throw new Error(await readError(response));
}

export function accountLabel(principal: SessionPrincipal): string {
  const name = principal.displayName.trim();
  if (name !== "") return name;
  const subject = principal.subject.trim();
  return subject === "" ? "Signed-in user" : subject;
}

async function readError(response: Response): Promise<string> {
  let text: string;
  try {
    text = await response.text();
  } catch {
    return `Request failed (${response.status}).`;
  }
  const trimmed = text.trim();
  if (trimmed === "" || trimmed.startsWith("<")) return `Request failed (${response.status}).`;
  return trimmed.length > 300 ? `${trimmed.slice(0, 300)}…` : trimmed;
}
