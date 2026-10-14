// SPDX-License-Identifier: Apache-2.0

import type { StatusTone } from "@/components/ui/status-badge";
import type { Destination, DeliverySummary } from "../../../gen/lindm/integrations/v1/delivery_pb";

// Delivery failure reasons recorded by the server (internal/integrations transport
// and worker). The raw reason stays in Details.
const FAILURE_TEXT: Record<string, string> = {
  webhook_transport_failed: "Couldn't connect to the receiver",
  webhook_response_failed: "The receiver did not send a complete response",
  syslog_transport_failed: "Couldn't send to the syslog server",
  invalid_destination_trust: "The server cannot load the pinned CA certificate",
  invalid_destination_endpoint: "The destination address isn't valid",
  invalid_destination_kind: "The destination type isn't supported",
  destination_secret_unreadable: "The server cannot read the signing secret. Rotate it",
  destination_disabled: "An administrator paused the destination",
  destination_deleted: "An administrator removed the destination",
  lease_expired: "Sending timed out on every attempt",
};

export function deliveryFailureText(reason: string): string {
  const status = /^webhook_http_(\d{3})$/.exec(reason);
  if (status) return `The receiver refused the event (HTTP ${status[1]})`;
  return FAILURE_TEXT[reason] ?? "Delivery failed for a reason this console doesn't recognize";
}

export function plural(count: bigint | number, noun: string, nouns = `${noun}s`) {
  return `${count.toString()} ${count === 1 || count === 1n ? noun : nouns}`;
}

export type DestinationHealth = { tone: StatusTone; label: string; detail?: string };

/** One health statement per destination from the server's delivery summary. */
export function destinationHealth(
  destination: Destination,
  summary: DeliverySummary | undefined,
): DestinationHealth {
  if (!destination.config?.enabled) {
    return {
      tone: "neutral",
      label: "Paused",
      detail: "Events recorded while paused aren't sent.",
    };
  }
  if (!summary) return { tone: "neutral", label: "Health unknown" };
  const reason = summary.lastError ? deliveryFailureText(summary.lastError) : "";
  if (summary.failed > 0n) {
    return {
      tone: "destructive",
      label: "Failing",
      detail: `${plural(summary.failed, "failed delivery", "failed deliveries")} to retry. ${reason}.`,
    };
  }
  if (summary.retrying > 0n) {
    return {
      tone: "warning",
      label: "Retrying",
      detail: `${plural(summary.retrying, "delivery", "deliveries")} retrying. ${reason}.`,
    };
  }
  if (summary.delivered > 0n) return { tone: "success", label: "Delivering" };
  if (summary.queued > 0n) {
    return {
      tone: "info",
      label: "Sending",
      detail: `${plural(summary.queued, "event")} waiting.`,
    };
  }
  return {
    tone: "neutral",
    label: summary.lastDeliveredAt ? "Idle" : "No deliveries yet",
    detail: summary.lastDeliveredAt ? undefined : "Nothing has been sent to it yet.",
  };
}
