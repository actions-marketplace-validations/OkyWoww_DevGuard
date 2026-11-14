import {
  damerauLevenshtein,
  isCommentOrEmptyLine,
  type AuditAnalyzeOptions,
  type InlineFinding,
  type LineFinding,
} from './lexicalMasker.js';

export const POPULAR_NPM_PACKAGES = [
  'express', 'lodash', 'axios', 'zod', 'jsonwebtoken', 'stripe', 'prisma',
  '@prisma/client', 'mongoose', 'bcrypt', 'bcryptjs', 'dotenv', 'cors', 'uuid',
  'moment', 'dayjs', 'chalk', 'commander', 'ws', 'pg', 'mysql2', 'redis',
  'ioredis', 'bullmq', 'next', 'react', 'vue', 'svelte', 'vite', 'vitest',
  'jest', 'typescript', 'tsx', 'openai', '@google/genai',
] as const;

const POPULAR_NPM_SET = new Set<string>(POPULAR_NPM_PACKAGES);

const DEFAULT_BUILTIN_NODE_MODULES = [
  'assert', 'assert/strict', 'async_hooks', 'buffer', 'child_process', 'cluster',
  'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns',
  'dns/promises', 'domain', 'events', 'fs', 'fs/promises', 'http', 'http2',
  'https', 'inspector', 'inspector/promises', 'module', 'net', 'os', 'path',
  'path/posix', 'path/win32', 'perf_hooks', 'process', 'punycode', 'querystring',
  'readline', 'readline/promises', 'repl', 'sqlite', 'stream', 'stream/consumers',
  'stream/promises', 'stream/web', 'string_decoder', 'sys', 'test',
  'test/reporters', 'timers', 'timers/promises', 'tls', 'trace_events', 'tty',
  'url', 'util', 'util/types', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
];

function getNodeBuiltinModuleSet(extraBuiltins?: readonly string[]): Set<string> {
  const set = new Set<string>(DEFAULT_BUILTIN_NODE_MODULES);
  if (extraBuiltins) {
    for (const mod of extraBuiltins) set.add(mod.replace(/^node:/, ''));
  }
  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  if (proc && typeof proc.getBuiltinModule === 'function') {
    try {
      const mod = proc.getBuiltinModule('node:module') as { builtinModules?: string[] } | undefined;
      if (mod?.builtinModules) {
        for (const item of mod.builtinModules) {
          set.add(item.replace(/^node:/, ''));
        }
      }
    } catch {
      return set;
    }
  }
  return set;
}

function getBasePackageName(specifier: string): string {
  if (specifier.startsWith('@')) {
    const parts = specifier.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
  }
  return specifier.split('/')[0];
}

function resolveDeclaredDependencies(options?: AuditAnalyzeOptions): ReadonlySet<string> | undefined {
  if (options?.declaredDependencies !== undefined) {
    return options.declaredDependencies instanceof Set
      ? options.declaredDependencies
      : new Set(options.declaredDependencies);
  }
  if (!options?.filePath || typeof options.filePath !== 'string') return undefined;

  const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
  if (!proc || typeof proc.getBuiltinModule !== 'function') return undefined;

  try {
    const fsMod = proc.getBuiltinModule('node:fs') as {
      existsSync: (p: string) => boolean;
      readFileSync: (p: string, enc: string) => string;
    };
    const pathMod = proc.getBuiltinModule('node:path') as {
      resolve: (...parts: string[]) => string;
      dirname: (p: string) => string;
      join: (...parts: string[]) => string;
    };

    let currentDir = pathMod.dirname(pathMod.resolve(options.filePath));
    while (true) {
      const pkgPath = pathMod.join(currentDir, 'package.json');
      if (fsMod.existsSync(pkgPath)) {
        const parsed = JSON.parse(fsMod.readFileSync(pkgPath, 'utf-8')) as {
          dependencies?: Record<string, unknown>;
          devDependencies?: Record<string, unknown>;
          peerDependencies?: Record<string, unknown>;
        };
        return new Set<string>([
          ...Object.keys(parsed.dependencies || {}),
          ...Object.keys(parsed.devDependencies || {}),
          ...Object.keys(parsed.peerDependencies || {}),
        ]);
      }
      const parentDir = pathMod.dirname(currentDir);
      if (parentDir === currentDir) break;
      currentDir = parentDir;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/** DG004: Detects typosquatted and undeclared phantom package imports. */
export function detectHallucinatedPackages(
  execLines: Array<{ num: number; text: string }>,
  maskedLines: string[],
  options: AuditAnalyzeOptions | undefined,
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  const builtinSet = getNodeBuiltinModuleSet(options?.builtinModules);
  const declaredDeps = resolveDeclaredDependencies(options);
  const staticImportRe = /^\s*(?:import\b[^'"]*\bfrom\s+|import\s+|\}\s*from\s+)['"]([^'"]+)['"]/;
  const dynamicOrRequireRe = /(?:^|[^\w.'"`])\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  const maskedImportOrRequireRe = /^\s*(?:import\b|\}\s*from\b)|(?:^|[^\w.'"`])\b(?:require|import)\s*\(/;

  for (const { num, text } of execLines) {
    if (!maskedImportOrRequireRe.test(maskedLines[num - 1] ?? '')) continue;

    const specs: string[] = [];
    const staticMatch = text.match(staticImportRe);
    if (staticMatch?.[1]) specs.push(staticMatch[1]);
    for (const m of text.matchAll(dynamicOrRequireRe)) {
      if (m[1]) specs.push(m[1]);
    }

    for (const rawSpec of specs) {
      if (
        !rawSpec ||
        rawSpec.startsWith('.') ||
        rawSpec.startsWith('/') ||
        rawSpec.startsWith('@/') ||
        rawSpec.startsWith('~/') ||
        rawSpec.startsWith('#') ||
        (/^[a-z]+:/i.test(rawSpec) && !rawSpec.startsWith('node:'))
      ) {
        continue;
      }

      const strippedNode = rawSpec.startsWith('node:') ? rawSpec.slice(5) : rawSpec;
      const baseStripped = getBasePackageName(strippedNode);
      if (builtinSet.has(strippedNode) || builtinSet.has(baseStripped)) continue;

      const basePkg = getBasePackageName(rawSpec);

      if (!POPULAR_NPM_SET.has(basePkg)) {
        let bestCandidate: string | undefined;
        let bestDist = Number.POSITIVE_INFINITY;

        for (const popular of POPULAR_NPM_PACKAGES) {
          const dist = damerauLevenshtein(basePkg, popular);
          const isMatch = (dist === 1 && basePkg.length >= 5) || (dist === 2 && basePkg.length >= 8);
          if (isMatch && dist < bestDist) {
            bestDist = dist;
            bestCandidate = popular;
          }
        }

        if (bestCandidate) {
          const replacementPkg = rawSpec === basePkg ? bestCandidate : rawSpec.replace(basePkg, bestCandidate);
          const suggestion = text.replace(rawSpec, replacementPkg);
          const msg = `Potensi slopsquatting / typosquatting pada paket '${rawSpec}' (jarak edit ${bestDist} dari '${bestCandidate}').`;
          findings.push({
            line: num,
            category: 'security',
            penalty: 40,
            shortReason: `-40 [DG004] Typosquatting paket '${rawSpec}' -> '${bestCandidate}' (baris ${num})`,
            detailedReason: msg,
            isCritical: true,
          });
          inlineFindings.push({
            ruleId: 'DG004',
            line: num,
            severity: 'error',
            message: msg,
            suggestion,
          });
          continue;
        }
      }

      if (declaredDeps && !declaredDeps.has(basePkg)) {
        const msg = `Phantom dependency '${basePkg}' diimpor pada baris ${num} namun tidak terdaftar di package.json.`;
        findings.push({
          line: num,
          category: 'security',
          penalty: 35,
          shortReason: `-35 [DG004] Phantom dependency '${basePkg}' absen dari package.json (baris ${num})`,
          detailedReason: msg,
          isCritical: true,
        });
        inlineFindings.push({
          ruleId: 'DG004',
          line: num,
          severity: 'error',
          message: msg,
        });
      }
    }
  }
}

function stripBalancedConsoleCalls(body: string): string {
  let out = body;
  const consoleRe = /\bconsole\s*\.\s*(?:log|warn|error|info|debug)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = consoleRe.exec(out)) !== null) {
    let idx = match.index + match[0].length;
    let depth = 1;
    let quote: string | null = null;
    while (idx < out.length && depth > 0) {
      const ch = out[idx];
      if (quote) {
        if (ch === '\\') idx++;
        else if (ch === quote) quote = null;
      } else if (ch === '\'' || ch === '"' || ch === '`') {
        quote = ch;
      } else if (ch === '(') {
        depth++;
      } else if (ch === ')') {
        depth--;
      }
      idx++;
    }
    out = out.slice(0, match.index) + out.slice(idx);
    consoleRe.lastIndex = match.index;
  }
  return out;
}

function stripCommentsFromSnippet(snippet: string): string {
  return snippet
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:\\])\/\/[^\n]*/g, '$1');
}

function extractBraceBlock(source: string, openBraceIdx: number): { body: string; endIdx: number } | null {
  let depth = 1;
  let idx = openBraceIdx + 1;
  let quote: string | null = null;
  let inLineComment = false;
  let inBlockComment = false;

  while (idx < source.length && depth > 0) {
    const ch = source[idx];
    const next = source[idx + 1];

    if (inLineComment) {
      if (ch === '\n') inLineComment = false;
    } else if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        idx++;
      }
    } else if (quote) {
      if (ch === '\\') idx++;
      else if (ch === quote) quote = null;
    } else {
      if (ch === '/' && next === '/') {
        inLineComment = true;
        idx++;
      } else if (ch === '/' && next === '*') {
        inBlockComment = true;
        idx++;
      } else if (ch === '\'' || ch === '"' || ch === '`') {
        quote = ch;
      } else if (ch === '{') {
        depth++;
      } else if (ch === '}' && --depth === 0) {
        return { body: source.slice(openBraceIdx + 1, idx), endIdx: idx };
      }
    }
    idx++;
  }
  return null;
}

/** DG005: Detects empty or console-only catch blocks that swallow runtime failures. */
export function detectSwallowedExceptions(
  rawCode: string,
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  const tryRe = /\btry\s*\{/g;
  const criticalFlowRe =
    /(?:^|[^a-z])(?:payment|balance|wallet|ledger|transfer|charge|refund|deduct|invoice|auth|token|jwt|password|execute|query|transaction|writeFileSync)/i;
  const cleanupCallRe = /\b(?:unlink|unlinkSync|rm|rmSync|rmdir|close|closeSync|destroy)\s*\(/;
  const jsonParseRe = /\bJSON\.parse\s*\(/;
  const recoveryRe = /\b(?:throw|return|reject|process\.exit|rollback|abort)\b/;

  let match: RegExpExecArray | null;
  while ((match = tryRe.exec(rawCode)) !== null) {
    const tryOpenBrace = rawCode.indexOf('{', match.index);
    if (tryOpenBrace === -1) continue;
    const tryBlock = extractBraceBlock(rawCode, tryOpenBrace);
    if (!tryBlock) continue;

    const afterTry = rawCode.slice(tryBlock.endIdx + 1);
    const catchHeaderMatch = afterTry.match(/^\s*catch\b(?:\s*\([^)]*\))?\s*\{/);
    if (!catchHeaderMatch) continue;

    const catchStartOffset = tryBlock.endIdx + 1 + catchHeaderMatch[0].length - 1;
    const catchBlock = extractBraceBlock(rawCode, catchStartOffset);
    if (!catchBlock) continue;

    const strippedTry = stripCommentsFromSnippet(tryBlock.body);
    const strippedCatch = stripCommentsFromSnippet(catchBlock.body);

    if (recoveryRe.test(strippedCatch)) continue;
    if (stripBalancedConsoleCalls(strippedCatch).replace(/[;\s]/g, '').length > 0) continue;

    const isCriticalContext = criticalFlowRe.test(strippedTry);
    if (!isCriticalContext && (cleanupCallRe.test(strippedTry) || jsonParseRe.test(strippedTry))) {
      continue;
    }

    const catchLine = rawCode.slice(0, catchStartOffset).split('\n').length;
    const catchEndLine = rawCode.slice(0, catchBlock.endIdx).split('\n').length;

    if (isCriticalContext) {
      const msg = `Swallowed exception pada alur transaksi/keamanan kritis (baris ${catchLine}): blok catch kosong atau hanya logging tanpa propagate/rollback.`;
      findings.push({
        line: catchLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 [DG005] Swallowed exception pada alur kritis (baris ${catchLine})`,
        detailedReason: msg,
        isCritical: true,
      });
      findings.push({
        line: catchLine,
        category: 'correctness',
        penalty: 15,
        shortReason: `-15 [DG005] Kegagalan transaksi kritis ditelan tanpa throw/rollback (baris ${catchLine})`,
        detailedReason: msg,
      });
      inlineFindings.push({
        ruleId: 'DG005',
        line: catchLine,
        endLine: catchEndLine > catchLine ? catchEndLine : undefined,
        severity: 'error',
        message: msg,
        suggestion: `} catch (err) {\n  console.error('Critical operation failed:', err);\n  throw err;\n}`,
      });
    } else {
      const msg = `Swallowed exception (baris ${catchLine}): blok catch kosong atau hanya memanggil console.* tanpa penanganan eksplisit.`;
      findings.push({
        line: catchLine,
        category: 'maintainability',
        penalty: 10,
        shortReason: `-10 [DG005] Swallowed exception tanpa penanganan/return eksplisit (baris ${catchLine})`,
        detailedReason: msg,
      });
      inlineFindings.push({
        ruleId: 'DG005',
        line: catchLine,
        endLine: catchEndLine > catchLine ? catchEndLine : undefined,
        severity: 'warning',
        message: msg,
      });
    }
  }
}

/** DG006: Detects check-then-act TOCTOU race conditions on balance/stock across await boundaries. */
export function detectNonAtomicBalanceMutations(
  rawLines: string[],
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  const entityCompareRe = /\b((?:\w+\.)?(?:balance|saldo|credits?|wallet|stock|inventory|quota|points))\b\s*(?:>=|<=|>|<)/i;
  const reverseCompareRe = /(?:>=|<=|>|<)\s*\b((?:\w+\.)?(?:balance|saldo|credits?|wallet|stock|inventory|quota|points))\b/i;
  const atomicGuardRe =
    /\$transaction|FOR\s+UPDATE|SERIALIZABLE|\batomic\b|\bmutex\b|\block\b|\$inc|WHERE\s+[\w.]*\b(?:balance|saldo|credits?|wallet|stock|inventory|quota|points)\b\s*>=/i;

  const flaggedMutationLines = new Set<number>();

  for (let i = 0; i < rawLines.length; i++) {
    const line1 = rawLines[i];
    if (isCommentOrEmptyLine(line1)) continue;
    if (/\b(?:SELECT|UPDATE|WHERE)\b/i.test(line1)) continue;

    const cmpMatch = line1.match(entityCompareRe) || line1.match(reverseCompareRe);
    if (!cmpMatch?.[1]) continue;

    const entityFull = cmpMatch[1];
    const entityBase = entityFull.includes('.') ? entityFull.split('.').pop()! : entityFull;
    const escapedEntity = entityBase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const mutationRe = new RegExp(
      `\\b(?:\\w+\\.)?${escapedEntity}\\b\\s*(?:[-+]=|=\\s*[^;\\n]*\\b(?:\\w+\\.)?${escapedEntity}\\b\\s*[-+]|:\\s*[^;\\n]*\\b(?:\\w+\\.)?${escapedEntity}\\b\\s*[-+])`,
      'i'
    );

    let sawAwait = false;
    const windowEnd = Math.min(rawLines.length - 1, i + 25);

    for (let j = i + 1; j <= windowEnd; j++) {
      const line2 = rawLines[j];
      if (isCommentOrEmptyLine(line2)) continue;
      if (/\bawait\b/.test(line2)) sawAwait = true;

      if (sawAwait && mutationRe.test(line2) && !flaggedMutationLines.has(j + 1)) {
        const contextSlice = rawLines.slice(Math.max(0, i - 15), Math.min(rawLines.length, j + 10)).join('\n');
        if (atomicGuardRe.test(contextSlice)) break;

        const mutLineNum = j + 1;
        flaggedMutationLines.add(mutLineNum);
        const msg = `Non-atomic check-then-act TOCTOU race condition pada '${entityFull}' melintasi boundary await (cek baris ${i + 1}, mutasi baris ${mutLineNum}) tanpa transaksi atomik.`;

        findings.push({
          line: mutLineNum,
          extraLines: [i + 1],
          category: 'security',
          penalty: 35,
          shortReason: `-35 [DG006] Non-atomic TOCTOU race condition pada '${entityFull}' (baris ${i + 1} -> ${mutLineNum})`,
          detailedReason: msg,
          isCritical: true,
        });
        findings.push({
          line: mutLineNum,
          category: 'correctness',
          penalty: 25,
          shortReason: `-25 [DG006] Risiko double-spend / overdraft akibat mutasi '${entityFull}' di luar transaksi atomik (baris ${mutLineNum})`,
          detailedReason: msg,
        });
        inlineFindings.push({
          ruleId: 'DG006',
          line: mutLineNum,
          severity: 'error',
          message: msg,
          suggestion: `await db.$transaction(async (tx) => {\n  const updated = await tx.account.updateMany({ where: { id: account.id, ${entityBase}: { gte: amount } }, data: { ${entityBase}: { decrement: amount } } });\n  if (updated.count === 0) throw new Error('Insufficient ${entityBase}');\n});`,
        });
        break;
      }
    }
  }
}

