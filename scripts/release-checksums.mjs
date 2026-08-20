#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.argv[2] ?? "release");
const checksumPath = path.join(root, "SHA256SUMS");

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

const digest = (file) =>
  new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(file);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });

const files = [
  ...(await walk(path.join(root, "packages"))),
  ...(await walk(path.join(root, "metadata"))),
].sort((left, right) => path.basename(left).localeCompare(path.basename(right)));

const byName = new Map();
for (const file of files) {
  const name = path.basename(file);
  if (byName.has(name)) {
    throw new Error(
      `release assets must have unique base names: ${byName.get(name)} and ${file}`,
    );
  }
  byName.set(name, file);
}

const lines = [];
for (const [name, file] of byName) {
  lines.push(`${await digest(file)}  ${name}`);
}
await writeFile(checksumPath, `${lines.join("\n")}\n`, "utf8");

const parsed = (await readFile(checksumPath, "utf8"))
  .trimEnd()
  .split("\n")
  .map((line) => {
    const match = /^([0-9a-f]{64}) {2}([^/\\]+)$/.exec(line);
    if (!match) {
      throw new Error(`invalid checksum line: ${line}`);
    }
    return { expected: match[1], name: match[2] };
  });

for (const { expected, name } of parsed) {
  const actual = await digest(byName.get(name));
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${name}`);
  }
}

process.stdout.write(`verified ${parsed.length} release assets\n`);
