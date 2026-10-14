// SPDX-License-Identifier: Apache-2.0

import { describe, it } from "node:test";

import { RuleTester } from "eslint";

import { freeformInput } from "./freeform-input.mjs";

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const tester = new RuleTester({
  languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } },
});

tester.run("lindm/freeform-input", freeformInput, {
  valid: [
    '<Input data-freeform="new group name" aria-label="Group name" />',
    '<Textarea data-freeform="audit reason" id="reason" />',
    '<input type="checkbox" checked />',
    '<Input type="datetime-local" />',
    '<Input type={secret ? "password" : "hidden"} />',
    '<Input type="password" autoComplete="current-password" />',
    "<Textarea readOnly value={snippet} />",
    "<Input readOnly={true} value={secret} />",
    '<Input type="search" data-freeform="hostname prefix search" placeholder="Hostname starts with" />',
    '<Input data-freeform="search across devices" aria-label="Search devices and packages" />',
    '<><Label htmlFor="name">Profile name</Label><Input id="name" data-freeform="new profile name" /></>',
    '<Input data-freeform={"numeric threshold"} type="number" />',
    "<Input data-freeform={freeformReason(field)} />",
    '<Input data-freeform={external ? "issued reference" : mode ? "octal mode" : freeformReason(field)} />',
    // A computed id names a label only within the same component.
    'function A({ id }) { return <><Label htmlFor={id}>Architecture</Label><SelectField id={id} /></>; } function B({ id }) { return <Input id={id} data-freeform="file mode" />; }',
    '<SelectField id="os" />',
  ],
  invalid: [
    {
      code: '<><Label htmlFor="package-manager">Package manager</Label><Input id="package-manager" placeholder="All managers" /></>',
      errors: [{ messageId: "domain", data: { element: "Input", label: "package manager" } }],
    },
    {
      code: '<><Label htmlFor="pm">Package manager</Label><Input id="pm" data-freeform="manager name" /></>',
      errors: [{ messageId: "domain" }],
    },
    {
      code: '<label>Operating system <Input value={os} data-freeform="os" /></label>',
      errors: [{ messageId: "domain" }],
    },
    {
      code: "<><Label htmlFor={`${prefix}-arch`}>Architecture (optional)</Label><Input id={`${prefix}-arch`} /></>",
      errors: [{ messageId: "domain" }],
    },
    { code: '<Input name="os" data-freeform="os id" />', errors: [{ messageId: "domain" }] },
    { code: '<Input aria-label="Event type" />', errors: [{ messageId: "domain" }] },
    { code: '<Input aria-label="Group" />', errors: [{ messageId: "domain" }] },
    { code: '<Input placeholder="Package name" />', errors: [{ messageId: "domain" }] },
    { code: "<Input value={value} />", errors: [{ messageId: "undeclared" }] },
    { code: '<textarea name="notes" />', errors: [{ messageId: "undeclared" }] },
    { code: '<Input type="number" />', errors: [{ messageId: "undeclared" }] },
    { code: "<Input type={kind} />", errors: [{ messageId: "undeclared" }] },
    { code: "<Input readOnly={locked} />", errors: [{ messageId: "undeclared" }] },
    { code: "<InputGroupInput />", errors: [{ messageId: "undeclared" }] },
    { code: '<Input data-freeform="" />', errors: [{ messageId: "empty" }] },
    { code: "<Input data-freeform={reason} />", errors: [{ messageId: "empty" }] },
    { code: "<Input data-freeform />", errors: [{ messageId: "empty" }] },
    { code: '<Input data-freeform={x ? "reason" : " "} />', errors: [{ messageId: "empty" }] },
  ],
});
