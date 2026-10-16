// Copies vendored runtime assets into static/dist and extracts the Lucide icons
// referenced by templates ({{icon "name"}}) so the binary only embeds what it uses.
import fs from "node:fs";
import path from "node:path";

const dist = "static/dist";
fs.mkdirSync(path.join(dist, "icons"), { recursive: true });
fs.mkdirSync(path.join(dist, "fonts"), { recursive: true });

const copies = {
  "node_modules/htmx.org/dist/htmx.min.js": "htmx.min.js",
  "node_modules/alpinejs/dist/cdn.min.js": "alpine.min.js",
  "node_modules/chart.js/dist/chart.umd.min.js": "chart.min.js",
  "node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2": "fonts/inter.woff2",
};
for (const [src, dst] of Object.entries(copies)) fs.copyFileSync(src, path.join(dist, dst));

const used = new Set(["citrus", "x", "check", "circle-alert", "info", "triangle-alert"]);
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
const sources = [...walk("templates"), ...walk("../internal").filter((f) => f.endsWith(".go")), ...walk("static/js")];
const re = /icon\s+"([a-z0-9-]+)"|data-icon="([a-z0-9-]+)"|[iI]con\("([a-z0-9-]+)"|"Icon"\s+"([a-z0-9-]+)"/g;
for (const f of sources) {
  for (const m of fs.readFileSync(f, "utf8").matchAll(re)) used.add(m[1] || m[2] || m[3] || m[4]);
}
let missing = [];
for (const name of used) {
  const src = `node_modules/lucide-static/icons/${name}.svg`;
  if (!fs.existsSync(src)) { missing.push(name); continue; }
  fs.copyFileSync(src, path.join(dist, "icons", `${name}.svg`));
}
if (missing.length) console.warn("missing icons:", missing.join(", "));
console.log(`assets copied, ${used.size - missing.length} icons`);
