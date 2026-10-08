import { createContext, useContext } from "react";
import type { AuthLifetime } from "@/lib/auth-lifetime";

export const AuthLifetimeContext = createContext<AuthLifetime | null>(null);

export function useAuthLifetime(): AuthLifetime {
  const lifetime = useContext(AuthLifetimeContext);
  if (lifetime === null) throw new Error("Authenticated content requires an active session.");
  return lifetime;
}
