import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const DELEGATED_CAPABILITY = "agent.capability-policy.v1";

// Why the server can't sign capability policies for devices, in the owner's terms.
// The raw reason stays in the caller's Details.
export function CapabilityIssuanceAlert({ reason }: { reason: string }) {
  if (!reason) return null;
  return (
    <Alert className="border-warning/25 bg-warning/10">
      <AlertTitle>Devices aren't receiving capability changes</AlertTitle>
      <AlertDescription>
        <p>
          {reason === "execution_authority_unconfigured"
            ? "This server has no execution authority yet, so it can't sign capability policies. "
            : reason === "capability_policy_not_delegated"
              ? "The execution delegation doesn't let this server sign capability policies. "
              : "The server can't sign capability policies for a reason this console doesn't describe yet. "}
          The owner must delegate <code className="font-mono text-xs">{DELEGATED_CAPABILITY}</code>{" "}
          in the execution delegation, signed offline with{" "}
          <code className="font-mono text-xs">lindmctl execution delegation sign</code>. Until then,
          changes here don&apos;t reach devices.
        </p>
      </AlertDescription>
    </Alert>
  );
}
