import { createContext, useContext } from "react";
import { TriangleAlert } from "lucide-react";
import {
  CollectionStatus,
  type NativeToolCustody,
} from "../../../gen/lindm/inventory/v1/observation_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

/** The unprotected tool ancestry the device reported, or undefined when none. */
export function unprotectedToolPath(custody: NativeToolCustody | undefined) {
  return custody?.status === CollectionStatus.SUCCESS && custody.unprotectedPath
    ? custody
    : undefined;
}

/** Native command failures on a device whose tool ancestry is unprotected are
 * agent refusals; observation labels name that cause instead of "Command failed". */
export const ToolCustodyContext = createContext<NativeToolCustody | undefined>(undefined);

export function useUnprotectedToolPath() {
  return unprotectedToolPath(useContext(ToolCustodyContext));
}

export function NativeToolCustodyAlert({ custody }: { custody: NativeToolCustody | undefined }) {
  const unsafe = unprotectedToolPath(custody);
  if (!unsafe) return null;
  const path = unsafe.unprotectedPath;
  return (
    <Alert variant="destructive" data-review-state="tool-custody">
      <TriangleAlert aria-hidden="true" />
      <AlertTitle>The agent refuses to run native tools on this device</AlertTitle>
      <AlertDescription>
        <p>
          <code>{path}</code> is mode <code>{unsafe.mode.toString(8).padStart(4, "0")}</code>, owner
          UID {unsafe.ownerUid}: it is writable by a group or other users, so anyone in that group
          could replace the system tools. Until it is fixed, inventory, settings, updates and
          actions that use system tools fail.
        </p>
        <p>
          As root on the device, run <code>chmod go-w {path}</code>. On Fedora and other RPM systems{" "}
          <code>rpm --restore filesystem</code> restores the packaged mode. The next inventory
          clears this message.
        </p>
      </AlertDescription>
    </Alert>
  );
}
