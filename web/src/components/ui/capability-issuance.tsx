import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const DELEGATED_CAPABILITY = "agent.capability-policy.v1";

// Why the server can't sign capability policies for devices, in the owner's terms.
// The raw reason stays in the caller's Details.
export function CapabilityIssuanceAlert({ reason }: { reason: string }) {
  if (!reason) return null;
  return (
    <Alert className="border-warning/25 bg-warning/10">
      <AlertTitle>Devices cannot receive capability changes</AlertTitle>
      <AlertDescription>
        <p>
          {reason === "execution_authority_unconfigured"
            ? "This server has no execution authority. It cannot sign capability policies. "
            : reason === "capability_policy_not_delegated"
              ? "The execution delegation does not allow this server to sign capability policies. "
              : "The server cannot sign capability policies. Details contain the recorded reason. "}
          Changes do not reach devices until the owner delegates{" "}
          <code className="font-mono text-xs">{DELEGATED_CAPABILITY}</code>.
        </p>
        <details>
          <summary>Details</summary>
          <p>
            Delegate the capability in the execution delegation. Sign it offline with{" "}
            <code className="font-mono text-xs">lindmctl execution delegation sign</code>.
          </p>
        </details>
        <p>Ask the owner to configure signing authority.</p>
      </AlertDescription>
    </Alert>
  );
}
