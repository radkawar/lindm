import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";

// The server supplies effective permissions, including emergency-policy intersections.
// Visibility is only a convenience; every operation is authorized again by the server.
export function canPermission(
  principal: SessionPrincipal,
  permission: string,
  unrestricted = false,
): boolean {
  if (!principal.permissions.includes(permission)) return false;
  return (
    !unrestricted ||
    principal.bindings.some(
      (binding) => binding.permissions.includes(permission) && binding.scopes.length === 0,
    )
  );
}
