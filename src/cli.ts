#!/usr/bin/env node

import { OpenCodeFilter, LegacyFilterConfig } from "./index.js";
import { readFileSync, writeFileSync } from "fs";
import { parseArgs } from "util";
import { getAuditLogger, formatAuditEntry, formatLogStats } from "./audit.js";
import { runWizard } from "./wizard.js";

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  options: {
    input: { type: "string", short: "i" },
    output: { type: "string", short: "o" },
    config: { type: "string", short: "c" },
    help: { type: "boolean", short: "h" },
    version: { type: "boolean", short: "v" },
    tail: { type: "boolean", short: "t" },
    clear: { type: "boolean" },
    stats: { type: "boolean" },
    limit: { type: "string", short: "n" },
  },
  allowPositionals: true,
});

const command = positionals[0];

if (values.help || (!command && !values.input && !values.output && !values.config)) {
  console.log(`
OpenCode Filter CLI

Usage: opencode-filter <command> [options]

Commands:
  init                Run interactive configuration wizard
  filter              Filter secrets from input to output (default)
  logs                View audit logs
  stats               Show audit log statistics
  clear-logs          Clear all audit logs

Options:
  -i, --input <file>     Input file path
  -o, --output <file>    Output file path
  -c, --config <file>    Config file path
  -h, --help             Show help
  -v, --version          Show version
  -t, --tail             Follow/tail logs (for logs command)
  -n, --limit <num>      Limit number of entries (for logs command)
  --clear                Clear logs (for logs command)
  --stats                Show log statistics

Examples:
  npx opencode-filter init             # Run setup wizard
  opencode-filter -i input.txt -o output.txt
  opencode-filter logs --tail
  opencode-filter logs --limit 50
  opencode-filter logs --clear
`);
  process.exit(0);
}

if (values.version) {
  console.log("opencode-filter v0.1.0");
  process.exit(0);
}

async function handleLogs() {
  const auditLogger = getAuditLogger();

  if (values.clear) {
    const result = auditLogger.clearLogs();
    if (result.success) {
      console.log(`✅ Cleared ${result.deleted} log file(s)`);
    } else {
      console.error(`❌ Failed to clear logs: ${result.error}`);
      process.exit(1);
    }
    return;
  }

  if (values.stats) {
    const stats = auditLogger.getStats();
    console.log(formatLogStats(stats));
    return;
  }

  const limit = values.limit ? parseInt(values.limit, 10) : 50;
  const tail = values.tail || false;

  const result = auditLogger.viewLogs({ limit, tail });

  if (result.entries.length === 0) {
    console.log("No audit log entries found.");
    return;
  }

  console.log(formatLogStats(auditLogger.getStats()));
  console.log("\nRecent entries:\n");
  console.log("Timestamp            | Action     | Category        | Placeholder                    | Conf");
  console.log("-".repeat(120));

  for (const entry of result.entries) {
    console.log(formatAuditEntry(entry));
  }
}

async function handleFilter() {
  try {
    let config: LegacyFilterConfig = {};

    if (values.config) {
      const configData = readFileSync(values.config, "utf-8");
      config = JSON.parse(configData);
    }

    if (values.input) {
      config.input = values.input;
    }

    if (values.output) {
      config.output = values.output;
    }

    const filter = new OpenCodeFilter(config);

    if (config.input && config.output) {
      const inputData = readFileSync(config.input, "utf-8");
      const lines = inputData.split('\n');
      const processed = await filter.process(lines);
      const output = processed.join('\n');
      writeFileSync(config.output, output, "utf-8");
      console.log(`✅ Filtered ${config.input} -> ${config.output}`);
    } else {
      console.log("✅ OpenCode Filter initialized");
      console.log("Config:", config);
    }

  } catch (error) {
    console.error("❌ Error:", error);
    process.exit(1);
  }
}

async function handleStats() {
  const auditLogger = getAuditLogger();
  const stats = auditLogger.getStats();
  console.log(formatLogStats(stats));
}

async function handleClearLogs() {
  const auditLogger = getAuditLogger();
  const result = auditLogger.clearLogs();
  if (result.success) {
    console.log(`✅ Cleared ${result.deleted} log file(s)`);
  } else {
    console.error(`❌ Failed to clear logs: ${result.error}`);
    process.exit(1);
  }
}

async function handleInit() {
  await runWizard();
}

async function main() {
  switch (command) {
    case "init":
      await handleInit();
      break;
    case "logs":
      await handleLogs();
      break;
    case "stats":
      await handleStats();
      break;
    case "clear-logs":
      await handleClearLogs();
      break;
    case "filter":
    default:
      await handleFilter();
      break;
  }
}

main();
