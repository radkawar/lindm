// SPDX-License-Identifier: Apache-2.0

import type { CapabilityField } from "./capabilities";

export const limitedLabels: Record<CapabilityField, string> = {
  clipboard: "Send text only",
  keyboard: "Text only",
  display: "Current display only",
  messages: "One message at a time",
  files: "Send files only",
  reconnect: "Admin sends a new request",
  recording: "User may choose recording",
  unattended: "Approved time window",
  elevation: "Guide and pause input",
  annotation: "Pointer only",
  audio: "Selected output only",
};

export const onLabels: Record<CapabilityField, string> = {
  clipboard: "Send and read text",
  keyboard: "Text and physical keys",
  display: "Select shared displays",
  messages: "Sequential messages",
  files: "Send and request files",
  reconnect: "New request sent automatically",
  recording: "Recording required",
  unattended: "Approved weekly schedule",
  elevation: "Guide and pause input",
  annotation: "Pointer and marks",
  audio: "Output and microphone",
};

export type EnabledMode = "limited" | "on";

// Password-prompt guidance behaves the same when limited or on (product
// specification), so it offers one choice. Two options with one label were
// indistinguishable to people and ambiguous to the lab's driver
// (layers-fedora44-tier3-06).
const singleModeFields: Partial<Record<CapabilityField, true>> = { elevation: true };

// enabledModes lists the non-off choices a field offers. A single-mode field
// keeps a stored "on" representable instead of silently rewriting it.
export function enabledModes(field: CapabilityField, current: "off" | EnabledMode): EnabledMode[] {
  if (singleModeFields[field]) return [current === "on" ? "on" : "limited"];
  return ["limited", "on"];
}
