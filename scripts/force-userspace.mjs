import fs from "node:fs";

const target = process.argv[2];
if (!target) throw new Error("Expected the pinned awg-quick path");
const original = fs.readFileSync(target, "utf8");
const anchor = "add_if() {\n\tlocal ret\n";
if (original.split(anchor).length !== 2) {
  throw new Error("Pinned awg-quick add_if changed; refusing an unsafe patch");
}
const patched = original.replace(
  anchor,
  `${anchor}\tif [[ \${AWG_FORCE_USERSPACE:-false} == true ]]; then
\t\tcmd "\${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE"
\t\treturn
\tfi
`,
);
fs.writeFileSync(target, patched);
