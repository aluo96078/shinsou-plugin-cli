// Bundles the CLI into dist/cli.js. Runtime dependencies stay external (installed by npm).
import { build } from "esbuild";
import { readFileSync, chmodSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
await build({
  entryPoints: ["src/cli.ts"],
  outfile: "dist/cli.js",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  packages: "external",
  banner: { js: "#!/usr/bin/env node" },
  define: { __CLI_VERSION__: JSON.stringify(pkg.version) },
});
chmodSync("dist/cli.js", 0o755);
