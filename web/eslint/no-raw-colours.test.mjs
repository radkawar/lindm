import { describe, it } from "node:test";
import { RuleTester } from "eslint";
import tseslint from "typescript-eslint";
import { noRawColours } from "./no-raw-colours.mjs";

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const tester = new RuleTester({
  languageOptions: { parser: tseslint.parser, parserOptions: { ecmaFeatures: { jsx: true } } },
});

const invalid = [
  '<path stroke="#abc" />',
  '<path fill={"#12345678"} />',
  '<div style={{ color: "red" }} />',
  '<div style={{ backgroundColor: "rebeccapurple" }} />',
  '<div style={{ border: "1px solid navy" }} />',
  '<div style={{ boxShadow: "0 0 3px #1234" }} />',
  '<div style={{ filter: "drop-shadow(0 0 3px red)" }} />',
  '<div style={{ color: "rgb(1 2 3)" }} />',
  '<div style={{ color: "rgba(1, 2, 3, .5)" }} />',
  '<div style={{ color: "hsl(20 30% 40%)" }} />',
  '<div style={{ color: "oklch(.5 .2 200)" }} />',
  'const chartColours: string[] = ["#aabbcc"];',
  'const ink = "red"; const icon = <path fill={ink} />;',
  'const inks = ["#aabbcc"]; const icon = <path fill={inks[0]} />;',
  'node.style.color = "blue";',
  'node.style.setProperty("color", "green");',
  'node.setAttribute("stroke", "white");',
  '<div className="dark:hover:bg-blue-600/50" />',
  '<div className="text-white border-gray-200" />',
  '<div className="ring-offset-black" />',
  '<div className="bg-neutral-950" />',
  '<div className="[&_svg]:fill-[#123456]" />',
  '<div className="text-[rgb(1_2_3)]" />',
  '<div className="bg-[hsl(20_30%_40%)]" />',
  '<div className="ring-[oklch(.5_.2_200)]" />',
  '<div className="text-[red]" />',
  '<div className="[color:navy]" />',
  '<div className="[--local-ink:#abc]" />',
  '<div className="shadow-[0_0_3px_red]" />',
  '<div className="[filter:drop-shadow(0_0_3px_red)]" />',
  `const selector = '[stroke="#abc"]';`,
  `const selector = '[fill="red"]';`,
  'const classes = `bg-red-500 ${active ? "px-2" : "px-3"}`;',
  'const style = { color: active ? "red" : "var(--foreground)" };',
];

tester.run("lindm/no-raw-colours", noRawColours, {
  valid: [
    '<div className="bg-background text-foreground border-border hover:bg-selection hover:text-selection-foreground" />',
    '<div className="bg-neutral/10 text-neutral ring-ring/50 stroke-chart-1" />',
    '<div className="text-[var(--success)] bg-[color-mix(in_srgb,var(--primary)_10%,transparent)]" />',
    '<div className="[color:var(--foreground)] [--local-ink:var(--neutral)]" />',
    '<div className="w-[3px] text-[length:14px] outline-[2px]" />',
    '<path stroke="currentColor" fill="none" />',
    '<div style={{ color: "inherit", backgroundColor: "transparent", fill: "none" }} />',
    '<div style={{ color: "var(--warning)", boxShadow: "0 0 2px var(--ring)" }} />',
    'const chartColours = ["var(--chart-1)", "var(--chart-2)"];',
    'const red = "Red devices"; const white = { label: "white", id: "#abc" };',
    'const colorLabel = "red"; const paletteLabel = "white";',
    'const text = "rgb(1 2 3) is a CSS value"; const hash = "#deadbeef";',
    '<span title="red" data-id="#abc">red #abc rgb(1 2 3)</span>',
    `const selector = '#abc [data-label="red"]';`,
    'node.setAttribute("title", "red");',
    `<div style={{ backgroundImage: 'url("red.svg#abc")' }} />`,
  ],
  invalid: invalid.map((code) => ({
    code,
    errors: [{ messageId: "raw" }],
  })),
});
