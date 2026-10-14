// SPDX-License-Identifier: Apache-2.0

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
          <code>{path}</code> has mode <code>{unsafe.mode.toString(8).padStart(4, "0")}</code> and
          owner UID {unsafe.ownerUid}. A group or other users can write to this path and replace
          system tools. The agent refuses inventory, settings, updates and actions that use these
          tools.
        </p>
        <p>
          Run <code>chmod go-w {path}</code> as root on the device. On RPM systems, run{" "}
          <code>rpm --restore filesystem</code> to restore the packaged mode. The next inventory
          clears this message.
        </p>
      </AlertDescription>
    </Alert>
  );
}
