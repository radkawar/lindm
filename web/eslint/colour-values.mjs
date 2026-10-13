// Shared by the TypeScript ESLint rule and the standalone CSS scanner.
// Inspect style syntax, not prose or identifiers that happen to name a colour.
const namedColours = new Set(
  `aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue
  blueviolet brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk
  crimson cyan darkblue darkcyan darkgoldenrod darkgray darkgreen darkgrey darkkhaki
  darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon darkseagreen
  darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue
  dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite
  gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki
  lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow
  lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray
  lightslategrey lightsteelblue lightyellow lime limegreen linen magenta maroon mediumaquamarine
  mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen
  mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy
  oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise
  palevioletred papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red
  rosybrown royalblue saddlebrown salmon sandybrown seagreen seashell sienna silver skyblue
  slateblue slategray slategrey snow springgreen steelblue tan teal thistle tomato turquoise
  violet wheat white whitesmoke yellow yellowgreen`.split(/\s+/),
);

export function colourProperty(name) {
  return (
    name.startsWith("--") ||
    /^(?:color|background(?:Color|Image)?|border(?:Top|Right|Bottom|Left|Block|Inline|BlockStart|BlockEnd|InlineStart|InlineEnd)?(?:Color)?|borderImage(?:Source)?|outline(?:Color)?|boxShadow|textShadow|textFillColor|textStroke(?:Color)?|fill|stroke|stopColor|floodColor|lightingColor|caretColor|accentColor|textDecoration(?:Color)?|columnRule(?:Color)?|mask(?:Image)?|filter|backdropFilter)$/i.test(
      name
        .replace(/^(?:-?(?:webkit|moz|ms|o)-)/i, "")
        .replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()),
    )
  );
}

// Comments, quoted content and URLs are not colour values. Preserve offsets so
// CSS diagnostics point at the original token. CSS escapes are decoded first.
export function cssUnescape(value) {
  return value.replace(/\\([\da-f]{1,6}\s?|[^\n\r\f])/gi, (_, escape) =>
    /^[\da-f]/i.test(escape)
      ? String.fromCodePoint(Math.min(parseInt(escape.trim(), 16) || 0xfffd, 0x10ffff))
      : escape,
  );
}

export function rawColour(value, { named = true } = {}) {
  const text = cssUnescape(value)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/url\((?:[^()"']|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')*\)/gi, " ")
    .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, " ");
  const literal = text.match(
    /#[\da-f]{8}(?![\w-])|#[\da-f]{6}(?![\w-])|#[\da-f]{4}(?![\w-])|#[\da-f]{3}(?![\w-])|\b(?:rgba?|hsla?|oklch|oklab|lch|lab|hwb|color)\s*\(/i,
  );
  if (literal) return literal[0];
  if (!named) return null;
  // A variable such as --neutral or --red is an identifier, not a named value.
  for (const match of text.matchAll(/(?<![\w-])[a-z]+(?![\w-])/gi))
    if (namedColours.has(match[0].toLowerCase())) return match[0];
  return null;
}

export function rawSelectorColour(value) {
  for (const match of cssUnescape(value).matchAll(
    /\[\s*(?:color|fill|stroke|stop-color|flood-color|background-color|style)\s*[*^$|~]?=\s*(["']?)([^\]]*?)\1\s*\]/gi,
  )) {
    const colour = rawColour(match[2]);
    if (colour) return colour;
  }
  return null;
}

export function rawTailwindColour(value) {
  const text = cssUnescape(value);
  const palette = text.match(
    /(?:^|[\s:!.])(?:bg|text|border(?:-[trblxyse])?|divide|ring(?:-offset)?|outline|shadow|decoration|placeholder|caret|accent|fill|stroke|from|via|to)-(?:black|white|(?:slate|gray|grey|zinc|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)(?:-\d{1,3})?|neutral-\d{1,3})(?=$|[\s/!:\]])/i,
  );
  if (palette) return palette[0].replace(/^[\s:!.]+/, "");
  // Balanced brackets let variants such as [&_svg]:fill-[rgb(1_2_3)] and
  // arbitrary properties share the same check, without flagging size-[3px].
  for (let start = 0; start < text.length; start += 1) {
    if (text[start] !== "[") continue;
    let end = start + 1;
    let depth = 1;
    for (; end < text.length && depth; end += 1) {
      if (text[end] === "[") depth += 1;
      if (text[end] === "]") depth -= 1;
    }
    if (depth) continue;
    const body = text.slice(start + 1, end - 1).replaceAll("_", " ");
    const utility = text
      .slice(0, start)
      .match(
        /(?:^|[\s:!.])(?:bg|text|border(?:-[trblxyse])?|divide|ring(?:-offset)?|outline|shadow|decoration|placeholder|caret|accent|fill|stroke|from|via|to)-$/i,
      );
    const property = body.match(/^([\w-]+)\s*:(.*)$/s);
    if (utility || (property && colourProperty(property[1]))) {
      const colour = rawColour(property ? property[2] : body);
      if (colour) return colour;
    }
    // Do not skip nested brackets: an arbitrary variant may contain a selector.
  }
  return rawSelectorColour(text);
}
