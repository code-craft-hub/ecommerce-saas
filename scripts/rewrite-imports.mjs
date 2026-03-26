#!/usr/bin/env node
/**
 * Rewrites all relative imports (../../../) inside src/ to @/ aliases.
 *
 * Algorithm:
 *   For each .ts / .tsx file under src/:
 *     For each import/export/require with a relative specifier:
 *       1. Resolve the specifier to an absolute path
 *       2. Compute the path relative to the src/ root
 *       3. Replace with @/<relative-from-src>
 *
 * Only rewrites cross-directory relative paths (those with ..).
 * Same-directory imports (./foo) are left alone.
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs'
import { resolve, relative, dirname, join } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dirname, '..')
const SRC = join(ROOT, 'src')

// TS extensions to try when resolving (no extension in specifier)
const EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '/index.ts', '/index.tsx']

function collectFiles(dir, results = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      collectFiles(full, results)
    } else if (/\.(ts|tsx)$/.test(entry) && !entry.endsWith('.d.ts')) {
      results.push(full)
    }
  }
  return results
}

/**
 * Resolve a relative specifier from a source file to an absolute path.
 * Returns null if the file cannot be found (e.g. node_modules).
 */
function resolveSpecifier(specifier, fromFile) {
  if (!specifier.startsWith('.')) return null           // node_modules, keep
  if (!specifier.startsWith('..')) return null          // same-directory, keep

  const fromDir = dirname(fromFile)
  const base = resolve(fromDir, specifier)

  // Try as-is first (may already have extension)
  try { statSync(base); return base } catch {}

  // Try with common extensions
  for (const ext of EXTENSIONS) {
    try { statSync(base + ext); return base + ext } catch {}
  }

  return null
}

/**
 * Convert an absolute file path to an @/ alias specifier.
 */
function toAlias(absPath) {
  const rel = relative(SRC, absPath).replace(/\\/g, '/')
  // Strip extension for TS imports (TS convention: no extension)
  const noExt = rel
    .replace(/\/index\.(ts|tsx)$/, '')   // foo/bar/index.ts → foo/bar
    .replace(/\.(ts|tsx)$/, '')          // foo/bar.ts → foo/bar
  return `@/${noExt}`
}

// Regex that matches the specifier in:
//   import ... from 'specifier'
//   export ... from 'specifier'
//   import('specifier')
//   require('specifier')
// Captures: [quote][specifier][quote]
const IMPORT_RE = /(?:from|import|require)\s*\(\s*(['"])(\.\.[\w./\-@]+)\1\s*\)|(?:from)\s+(['"])(\.\.[\w./\-@]+)\3/g

let totalFiles = 0
let totalRewrites = 0

for (const file of collectFiles(SRC)) {
  const original = readFileSync(file, 'utf8')
  let changed = false

  const rewritten = original.replace(IMPORT_RE, (match, q1, spec1, q2, spec2) => {
    const quote = q1 ?? q2
    const specifier = spec1 ?? spec2

    const resolved = resolveSpecifier(specifier, file)
    if (!resolved) return match

    // Only rewrite if the resolved path is inside src/
    if (!resolved.startsWith(SRC)) return match

    const alias = toAlias(resolved)
    const newMatch = match.replace(`${quote}${specifier}${quote}`, `'${alias}'`)
    if (newMatch !== match) changed = true
    return newMatch
  })

  if (changed) {
    writeFileSync(file, rewritten, 'utf8')
    const count = (original.match(IMPORT_RE) ?? []).length
    console.log(`  ✓ ${relative(ROOT, file).replace(/\\/g, '/')}`)
    totalRewrites++
  }
  totalFiles++
}

console.log(`\nDone. Scanned ${totalFiles} files, rewrote ${totalRewrites}.`)
