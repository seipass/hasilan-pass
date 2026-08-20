#!/usr/bin/env node

import { copyFile, mkdir, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const [, , platform, version, signing = "unsigned-smoke"] = process.argv;
const policies = {
  linux: {
    accepted: [".appimage", ".deb", ".rpm", ".sig"],
    required: [[".appimage"], [".deb"], [".rpm"]],
  },
  macos: {
    accepted: [".dmg", ".pkg", ".sig"],
    required: [[".dmg"]],
  },
  windows: {
    accepted: [".exe", ".msi", ".msix", ".sig"],
    required: [[".exe"], [".msi"]],
  },
};

if (!(platform in policies)) {
  throw new Error("platform must be linux, macos, or windows");
}
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  throw new Error("a valid release version is required");
}
if (!["verified", "unsigned-smoke", "not-applicable"].includes(signing)) {
  throw new Error(
    "signing state must be verified, unsigned-smoke, or not-applicable",
  );
}

const source = path.resolve("target/release/bundle");
const packageDirectory = path.resolve("release/packages");
const metadataDirectory = path.resolve("release/metadata");

const walk = async (directory) => {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(entryPath)));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
};

const policy = policies[platform];
let candidates;
try {
  candidates = (await walk(source))
    .filter((file) => {
      const lower = file.toLowerCase();
      return policy.accepted.some((suffix) => lower.endsWith(suffix));
    })
    .sort();
} catch (error) {
  throw new Error(`Tauri bundle directory is unavailable: ${error.message}`);
}

for (const alternatives of policy.required) {
  const found = candidates.some((file) => {
    const lower = file.toLowerCase();
    return alternatives.some((suffix) => lower.endsWith(suffix));
  });
  if (!found) {
    throw new Error(
      `${platform} bundle is missing required format ${alternatives.join(" or ")}`,
    );
  }
}

await mkdir(packageDirectory, { recursive: true });
await mkdir(metadataDirectory, { recursive: true });
const copied = [];
const names = new Set();
for (const candidate of candidates) {
  const safeBase = path.basename(candidate).replace(/[^0-9A-Za-z._+-]+/g, "-");
  const name = `hasilan-pass-${version}-${platform}-${safeBase}`;
  if (names.has(name)) {
    throw new Error(`two Tauri bundles would overwrite ${name}`);
  }
  names.add(name);
  await copyFile(candidate, path.join(packageDirectory, name));
  copied.push(name);
}

const metadata = {
  schemaVersion: 1,
  product: "Hasilan Pass Desktop",
  version,
  platform,
  architecture: process.arch,
  sourceCommit: process.env.GITHUB_SHA ?? null,
  nativeCodeSigning: signing,
  packages: copied,
};
await writeFile(
  path.join(metadataDirectory, `desktop-${platform}.json`),
  `${JSON.stringify(metadata, null, 2)}\n`,
  "utf8",
);

process.stdout.write(`${copied.join("\n")}\n`);
