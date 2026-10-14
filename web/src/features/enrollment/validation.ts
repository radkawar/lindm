// SPDX-License-Identifier: Apache-2.0

import { Code, ConnectError } from "@connectrpc/connect";
import { toRpcFailure } from "@/lib/errors";

export function enrollmentFailure(error: unknown, submitted: boolean) {
  return toRpcFailure(
    submitted
      ? error
      : new ConnectError(
          error instanceof Error ? error.message : "Invalid enrollment input.",
          Code.InvalidArgument,
          undefined,
          undefined,
          error,
        ),
  );
}
