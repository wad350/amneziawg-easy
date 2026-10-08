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
  `${anchor}\tcase "\${AWG_BACKEND:-userspace}" in
\t\tuserspace)
\t\t\tcmd "\${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE"
\t\t\treturn
\t\t\t;;
\t\tkernel)
\t\t\t[[ -d /sys/module/amneziawg ]] || die "Kernel AWG requires an already loaded amneziawg module"
\t\t\tcmd ip link add "$INTERFACE" type amneziawg || return $?
\t\t\treturn
\t\t\t;;
\t\t*) die "AWG_BACKEND must be userspace or kernel" ;;
\tesac
`,
);
fs.writeFileSync(target, patched);
