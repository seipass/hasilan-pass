import { readFile, writeFile } from "node:fs/promises";

const manifestUrl = new URL("../dist/manifest.json", import.meta.url);
const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));

// Firefox MV3 still uses background scripts; Chromium ignores this packaged variant.
delete manifest.background.service_worker;

await writeFile(manifestUrl, `${JSON.stringify(manifest, null, 2)}\n`);
