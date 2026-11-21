// Tailwind plugin: `lucide-<name>` classes for every Lucide icon, rendered as a
// CSS mask so the icon takes the current text color. Icons come from the
// `lucide-static` npm package (installed with bun). Tailwind only emits the
// classes that are actually used in templates.
const plugin = require("tailwindcss/plugin")
const fs = require("fs")
const path = require("path")

module.exports = plugin(function ({matchComponents}) {
  const iconsDir = path.join(__dirname, "../node_modules/lucide-static/icons")
  const values = {}

  for (const file of fs.readdirSync(iconsDir)) {
    if (!file.endsWith(".svg")) continue
    const name = path.basename(file, ".svg")
    values[name] = {name, fullPath: path.join(iconsDir, file)}
  }

  matchComponents(
    {
      lucide: ({name, fullPath}) => {
        const svg = fs
          .readFileSync(fullPath, "utf8")
          .replace(/<!--[\s\S]*?-->/g, "")
          .replace(/\s+class="[^"]*"/, "")
          .replace(/\s+/g, " ")
          .trim()

        return {
          [`--lucide-${name}`]: `url('data:image/svg+xml;utf8,${encodeURIComponent(svg)}')`,
          "-webkit-mask": `var(--lucide-${name})`,
          mask: `var(--lucide-${name})`,
          "mask-repeat": "no-repeat",
          "mask-size": "100% 100%",
          "background-color": "currentColor",
          "vertical-align": "middle",
          display: "inline-block",
          "flex-shrink": "0",
          width: "1.25rem",
          height: "1.25rem",
        }
      },
    },
    {values},
  )
})
