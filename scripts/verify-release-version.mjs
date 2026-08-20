#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import process from "node:process";

const jsonVersion = async (path) => {
  const document = JSON.parse(await readFile(path, "utf8"));
  if (typeof document.version !== "string") {
    throw new Error(`${path} does not contain a string version`);
  }
  return document.version;
};

const cargo = await readFile("Cargo.toml", "utf8");
const workspacePackage = cargo.match(
  /\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m,
);
if (!workspacePackage) {
  throw new Error("Cargo.toml does not declare workspace.package.version");
}

const versions = new Map([
  ["Cargo workspace", workspacePackage[1]],
  ["root package", await jsonVersion("package.json")],
  ["Web Vault", await jsonVersion("web/package.json")],
  ["browser extension package", await jsonVersion("extension/package.json")],
  ["browser extension manifest", await jsonVersion("extension/manifest.json")],
  ["desktop package", await jsonVersion("desktop/package.json")],
  ["Tauri bundle", await jsonVersion("desktop/src-tauri/tauri.conf.json")],
]);

const uniqueVersions = new Set(versions.values());
if (uniqueVersions.size !== 1) {
  const detail = [...versions]
    .map(([surface, version]) => `  ${surface}: ${version}`)
    .join("\n");
  throw new Error(`release versions do not match:\n${detail}`);
}

const [version] = uniqueVersions;
const requestedTag = process.argv[2];
if (requestedTag !== undefined && requestedTag !== `v${version}`) {
  throw new Error(
    `release tag ${JSON.stringify(requestedTag)} must exactly match v${version}`,
  );
}

process.stdout.write(`${version}\n`);
