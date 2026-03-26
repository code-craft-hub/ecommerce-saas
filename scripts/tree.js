#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const ROOT = process.cwd();
const OUTPUT_FILE = path.join(ROOT, "project-structure.txt");

// directories to ignore (enterprise-level hygiene)
const IGNORE = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  ".turbo",
  ".cache",
]);

function walk(dir, prefix = "") {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  return entries
    .filter((e) => !IGNORE.has(e.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .flatMap((entry, index, arr) => {
      const isLast = index === arr.length - 1;
      const connector = isLast ? "└── " : "├── ";
      const nextPrefix = prefix + (isLast ? "    " : "│   ");

      const fullPath = path.join(dir, entry.name);
      const line = `${prefix}${connector}${entry.name}`;

      if (entry.isDirectory()) {
        return [line, ...walk(fullPath, nextPrefix)];
      }

      return [line];
    });
}

function main() {
  const tree = walk(ROOT);
  const output = tree.join("\n");

  console.log(output);
  fs.writeFileSync(OUTPUT_FILE, output, "utf8");

  console.log(`\n✔ Structure saved to: ${OUTPUT_FILE}`);
}

main();