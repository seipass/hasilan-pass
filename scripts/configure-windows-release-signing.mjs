#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import readline from "node:readline";
import { URL } from "node:url";

const DEFAULT_ENVIRONMENT = "release";

const usage = `Usage:
  node scripts/configure-windows-release-signing.mjs \\
    --pfx <path> \\
    --timestamp-url <https-rfc3161-url> \\
    [--repo <owner/name>] [--environment <name>] [--dry-run]

This script reads an existing code-signing PFX locally, Base64-encodes it in memory,
and stores it in the selected GitHub Actions environment using gh. It never accepts
the PFX password as a command-line argument or writes a Base64 temporary file.
`;

const fail = (message) => {
  throw new Error(message);
};

const requireValue = (argv, index, option) => {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("--")) {
    fail(`${option} requires a value`);
  }
  return value;
};

const parseArgs = (argv) => {
  const options = {
    dryRun: false,
    environment: DEFAULT_ENVIRONMENT,
    pfx: undefined,
    repo: undefined,
    timestampUrl: undefined,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case "--help":
      case "-h":
        options.help = true;
        break;
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--environment":
        options.environment = requireValue(argv, index, argument);
        index += 1;
        break;
      case "--pfx":
        options.pfx = requireValue(argv, index, argument);
        index += 1;
        break;
      case "--repo":
        options.repo = requireValue(argv, index, argument);
        index += 1;
        break;
      case "--timestamp-url":
        options.timestampUrl = requireValue(argv, index, argument);
        index += 1;
        break;
      default:
        fail(`unknown option: ${argument}\n\n${usage}`);
    }
  }

  if (options.help) {
    return options;
  }
  if (!options.pfx) {
    fail(`--pfx is required\n\n${usage}`);
  }
  if (!options.timestampUrl) {
    fail(`--timestamp-url is required\n\n${usage}`);
  }

  return options;
};

const inferRepository = () => {
  const result = spawnSync("git", ["remote", "get-url", "origin"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.status !== 0) {
    return undefined;
  }

  const remote = result.stdout.trim();
  const match = remote.match(/github\.com[/:]([^/]+\/[^/]+?)(?:\.git)?$/i);
  return match?.[1];
};

const validateOptions = async (options) => {
  const pfxPath = resolve(options.pfx);
  let pfxStats;
  try {
    pfxStats = await stat(pfxPath);
  } catch {
    fail(`PFX file was not found: ${pfxPath}`);
  }
  if (!pfxStats.isFile() || pfxStats.size === 0) {
    fail(`PFX path is not a non-empty file: ${pfxPath}`);
  }

  if (!options.repo) {
    options.repo = inferRepository();
  }
  if (!options.repo || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(options.repo)) {
    fail("GitHub repository must be supplied as owner/name with --repo");
  }
  if (!options.environment || /[\r\n]/.test(options.environment)) {
    fail("GitHub environment must be a non-empty single-line value");
  }

  let timestamp;
  try {
    timestamp = new URL(options.timestampUrl);
  } catch {
    fail("--timestamp-url must be an absolute HTTPS URL");
  }
  if (timestamp.protocol !== "https:" || !timestamp.hostname) {
    fail("--timestamp-url must be an absolute HTTPS URL");
  }

  if (spawnSync("gh", ["--version"], { stdio: "ignore" }).status !== 0) {
    fail("GitHub CLI (gh) is required: https://cli.github.com/");
  }

  return { pfxPath, pfxSize: pfxStats.size };
};

const promptVisible = (question) => {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    fail("an interactive terminal is required for this operation");
  }

  const interfaceHandle = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolvePrompt) => {
    interfaceHandle.question(question, (answer) => {
      interfaceHandle.close();
      resolvePrompt(answer);
    });
  });
};

const promptHidden = (question) => {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    fail("an interactive terminal is required to enter the PFX password");
  }

  readline.emitKeypressEvents(process.stdin);
  const wasRaw = process.stdin.isRaw ?? false;

  return new Promise((resolvePrompt, rejectPrompt) => {
    let answer = "";
    let finished = false;

    const finish = (error) => {
      if (finished) {
        return;
      }
      finished = true;
      process.stdin.off("keypress", onKeypress);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stdout.write("\n");
      if (error) {
        rejectPrompt(error);
      } else {
        resolvePrompt(answer);
      }
    };

    const onKeypress = (character, key) => {
      if (key?.ctrl && key.name === "c") {
        finish(new Error("cancelled"));
      } else if (key?.name === "return" || key?.name === "enter") {
        finish();
      } else if (key?.name === "backspace" || key?.name === "delete") {
        answer = answer.slice(0, -1);
      } else if (character && !key?.ctrl && !key?.meta) {
        answer += character;
      }
    };

    process.stdout.write(question);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on("keypress", onKeypress);
  });
};

const runGhWithInput = (argumentsList, input) =>
  new Promise((resolveRun, rejectRun) => {
    const child = spawn("gh", argumentsList, {
      stdio: ["pipe", "inherit", "inherit"],
    });
    child.once("error", (error) => {
      rejectRun(new Error(`failed to start gh: ${error.message}`));
    });
    child.once("close", (code) => {
      if (code === 0) {
        resolveRun();
      } else {
        rejectRun(new Error(`gh exited with status ${code}`));
      }
    });
    child.stdin.end(input);
  });

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(usage);
    return;
  }

  const { pfxPath, pfxSize } = await validateOptions(options);
  const commonArguments = [
    "--repo",
    options.repo,
    "--env",
    options.environment,
  ];

  process.stdout.write(
    [
      "Planned GitHub Actions environment update:",
      `  repository:  ${options.repo}`,
      `  environment: ${options.environment}`,
      `  PFX file:    ${pfxPath} (${pfxSize} bytes)`,
      `  timestamp:   ${options.timestampUrl}`,
      "  secrets:     WINDOWS_CERTIFICATE, WINDOWS_CERTIFICATE_PASSWORD",
      "  variable:    WINDOWS_TIMESTAMP_URL",
    ].join("\n") + "\n",
  );

  if (options.dryRun) {
    process.stdout.write("Dry run: no GitHub values were changed.\n");
    return;
  }

  const confirmation = await promptVisible(
    "This overwrites the release environment signing values. Continue? [y/N] ",
  );
  if (!/^y(?:es)?$/i.test(confirmation.trim())) {
    process.stdout.write("Cancelled; no GitHub values were changed.\n");
    return;
  }

  const pfxBase64 = (await readFile(pfxPath)).toString("base64");
  let password = await promptHidden("PFX password (input is hidden): ");
  if (password.length === 0) {
    fail("PFX password must not be empty");
  }
  const passwordConfirmation = await promptHidden(
    "Repeat PFX password (input is hidden): ",
  );
  if (password !== passwordConfirmation) {
    fail("PFX passwords did not match; no GitHub values were changed");
  }

  try {
    process.stdout.write("Uploading WINDOWS_CERTIFICATE...\n");
    await runGhWithInput(
      ["secret", "set", "WINDOWS_CERTIFICATE", ...commonArguments],
      pfxBase64,
    );
    process.stdout.write("Uploading WINDOWS_CERTIFICATE_PASSWORD...\n");
    await runGhWithInput(
      ["secret", "set", "WINDOWS_CERTIFICATE_PASSWORD", ...commonArguments],
      password,
    );
    process.stdout.write("Setting WINDOWS_TIMESTAMP_URL...\n");
    await runGhWithInput(
      ["variable", "set", "WINDOWS_TIMESTAMP_URL", ...commonArguments],
      options.timestampUrl,
    );
  } finally {
    // Drop references as soon as the gh subprocesses have consumed the values.
    // JavaScript cannot guarantee zeroization, but no secret is written to disk
    // or passed as a command-line argument by this script.
    password = "";
  }

  process.stdout.write(
    "Registration completed. Re-run the release workflow after confirming any Environment approvals.\n",
  );
};

try {
  await main();
} catch (error) {
  process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
