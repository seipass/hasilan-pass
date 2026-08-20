#!/usr/bin/env node

import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const [, , source, name] = process.argv;
if (!source || !/^[0-9A-Za-z._-]+\.sigstore\.json$/.test(name ?? "")) {
  throw new Error("usage: copy-attestation-bundle.mjs SOURCE NAME.sigstore.json");
}

const metadataDirectory = path.resolve("release/metadata");
await mkdir(metadataDirectory, { recursive: true });
await copyFile(source, path.join(metadataDirectory, name));
