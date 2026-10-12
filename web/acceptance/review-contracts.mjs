// DOM contracts establish structural coverage, never design quality or approval.
// Every generated route must have an explicit entry; new routes fail closed.
const structural = { mode: "structural", page: "", minimumMetrics: 0 };
export const routeContracts = {
  "/": structural,
  "/enroll": structural,
  "/accounts": structural,
  "/advisories": structural,
  "/approvals": structural,
  "/audit": structural,
  "/authorization": structural,
  "/dashboard": { mode: "semantic", page: "dashboard", minimumMetrics: 1 },
  "/devices": structural,
  "/enrollment": structural,
  "/groups": structural,
  "/integrations": structural,
  "/profiles": structural,
  "/profiles/new": structural,
  "/profiles/$profileId": structural,
  "/rollouts": structural,
  "/secrets": structural,
  "/secrets/$secretId": structural,
  "/settings": structural,
  "/devices/$deviceId": { mode: "semantic", page: "device", minimumMetrics: 0 },
  "/devices/$deviceId/assistance/$sessionId": {
    mode: "semantic",
    page: "assistance",
    minimumMetrics: 0,
  },
  "/devices/$deviceId/actions/$actionId": structural,
  "/devices/$deviceId/actions/new/$kind": structural,
  "/devices/$deviceId/recovery/$actionId": structural,
  "/devices/$deviceId/recovery-enrollment": structural,
  // An unknown address names what was not found and offers a way on.
  "/$": { mode: "semantic", page: "not-found", minimumMetrics: 0 },
};

// Pages whose job is a list: at 390px their first row must be on the first screen.
export const listRoutes = ["/accounts", "/audit", "/devices", "/profiles", "/secrets"];

export const requiredDestructiveCoverage = [
  { id: "revoke-device", routes: ["/devices", "/devices/$deviceId"] },
];

export function destructiveCoverage(results, themes, viewports) {
  return requiredDestructiveCoverage.flatMap((required) =>
    themes.flatMap((theme) =>
      viewports.map(({ name: viewport }) => ({
        ...required,
        theme,
        viewport,
        observed: results.some(
          (entry) =>
            required.routes.includes(entry.route) &&
            entry.theme === theme &&
            entry.viewport === viewport &&
            entry.checks.dialogs?.destructive?.includes(required.id),
        ),
      })),
    ),
  );
}
