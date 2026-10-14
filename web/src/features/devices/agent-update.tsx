// SPDX-License-Identifier: Apache-2.0

import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { AgentUpdateStatus } from "../../../gen/lindm/agent/v1/update_pb";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { TechnicalDetails } from "@/components/ui/technical-details";
import { Fact, ObservedTime } from "./observations";

export function DeviceAgentUpdate({
  status,
  receivedAt,
}: {
  status: AgentUpdateStatus | undefined;
  receivedAt: Timestamp | undefined;
}) {
  const diagnostic = status?.nativeDiagnostic;
  const errorLines = diagnostic?.errorLines.slice(-8).map((line) => line.slice(0, 512)) ?? [];
  const truncated =
    diagnostic?.truncated ||
    (diagnostic !== undefined &&
      (diagnostic.errorLines.length > 8 ||
        diagnostic.errorLines.slice(-8).some((line) => line.length > 512)));

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>Agent updates</CardTitle>
        <CardDescription>The last update attempt the agent reported.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!status ? (
          <p className="text-sm text-muted-foreground">No update reports yet.</p>
        ) : (
          <>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Automatic updates">{status.enabled ? "On" : "Off"}</Fact>
              <Fact label="Version">{status.version || "Not reported"}</Fact>
              <Fact label="Phase">{status.phase || "Unknown"}</Fact>
              <Fact label="Last result">{status.lastOutcome || "Unknown"}</Fact>
              <Fact label="Reported">
                <ObservedTime value={status.observedAt} />
              </Fact>
              <Fact label="Started">
                <ObservedTime value={status.attemptStartedAt} />
              </Fact>
              <Fact label="Finished">
                <ObservedTime value={status.attemptFinishedAt} />
              </Fact>
              <Fact label="Last checked for updates">
                <ObservedTime value={status.lastMetadataAt} />
              </Fact>
              <Fact label="Reason">{status.reason || "Not reported"}</Fact>
            </dl>
            <TechnicalDetails items={[{ label: "Transaction ID", value: status.transactionId }]} />
            {diagnostic ? (
              <section className="space-y-3" aria-label="Last update failure">
                <h4 className="text-sm font-medium">Last update failure</h4>
                <dl className="grid gap-4 sm:grid-cols-3">
                  <Fact label="Package manager">{diagnostic.manager || "Unknown"}</Fact>
                  <Fact label="Failed step">{diagnostic.phase || "Unknown"}</Fact>
                  <Fact label="Exit code">
                    {diagnostic.exitCode === -1 ? "Not available" : diagnostic.exitCode}
                  </Fact>
                </dl>
                {errorLines.length ? (
                  <div>
                    <p className="mb-2 text-sm text-muted-foreground">Last error lines</p>
                    <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted p-3 text-xs">
                      {errorLines.join("\n")}
                    </pre>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No error output reported.</p>
                )}
                {truncated ? (
                  <p className="text-sm text-muted-foreground">
                    Output shortened to the last 8 lines.
                  </p>
                ) : null}
              </section>
            ) : null}
          </>
        )}
        <dl>
          <Fact label="Received">
            <ObservedTime value={receivedAt} server />
          </Fact>
        </dl>
      </CardContent>
    </Card>
  );
}
