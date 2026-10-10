import { createContext, useContext } from "react";
import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";

export const PrincipalContext = createContext<SessionPrincipal | null>(null);

export function usePrincipal(): SessionPrincipal {
  const principal = useContext(PrincipalContext);
  if (!principal) throw new Error("Principal context is required.");
  return principal;
}
