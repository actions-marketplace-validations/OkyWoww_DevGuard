import {
  calculateShannonEntropy,
  type ExtractedStringLiteral,
  type InlineFinding,
  type LineFinding,
} from './lexicalMasker.js';

export const DG007_PROVIDER_PATTERNS: ReadonlyArray<{
  label: string;
  envFallback: string;
  re: RegExp;
}> = [
  { label: 'Anthropic Claude API Key', envFallback: 'ANTHROPIC_API_KEY', re: /\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{20,}\b/ },
  { label: 'Google Gemini / GCP API Key', envFallback: 'GEMINI_API_KEY', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { label: 'Stripe Live Secret Key', envFallback: 'STRIPE_SECRET_KEY', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/ },
  { label: 'GitHub Personal / App Token', envFallback: 'GITHUB_TOKEN', re: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/ },
  { label: 'AWS Access Key ID', envFallback: 'AWS_ACCESS_KEY_ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'Slack Bot / Webhook Token', envFallback: 'SLACK_BOT_TOKEN', re: /\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b/ },
  { label: 'OpenAI / DeepSeek API Key', envFallback: 'OPENAI_API_KEY', re: /\bsk-(?:proj-|live-|None-)?[A-Za-z0-9_\-]{20,}\b/ },
];

const DG007_SENSITIVE_IDENT_RE =
  /(?:api_?key|api_?secret|secret_?key|private_?key|client_?secret|access_?token|auth_?token|jwt_?secret|webhook_?secret|signing_?secret|gemini_?(?:api_)?key|openai_?(?:api_)?key|anthropic_?(?:api_)?key|stripe_?(?:secret_)?key|aws_?secret(?:_access_key)?|password|passwd)$/i;

const DG007_DUMMY_RE =
  /(?:YOUR_|REPLACE_ME|PLACEHOLDER|CHANGEME|INSERT_|DUMMY|SAMPLE|EXAMPLE|TEST_KEY|MOCK_|FAKE_|^sk_test_|^pk_test_|^pk_live_|_HERE\b)/i;

function toUpperSnakeEnvName(identifier: string): string {
  const leaf = identifier.includes('.') ? identifier.split('.').pop()! : identifier;
  return leaf.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
}

/** DG007: Detects hardcoded provider-prefixed secrets and high-entropy credential assignments. */
export function detectHardcodedSecrets(
  rawCode: string,
  rawLines: string[],
  stringLiterals: ExtractedStringLiteral[],
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): Set<number> {
  if (typeof rawCode !== 'string' || !Array.isArray(stringLiterals)) {
    throw new TypeError('detectHardcodedSecrets expects string code and extracted literals');
  }
  const flaggedLines = new Set<number>();

  try {
    for (const lit of stringLiterals) {
      if (flaggedLines.has(lit.line) || lit.hasInterpolation) continue;

      const lineStartOffset = rawCode.lastIndexOf('\n', lit.startOffset - 1) + 1;
      const rawLine = rawLines[lit.line - 1] ?? '';

      if (/\bRegExp\s*\(/i.test(rawLine)) continue;
      const val = lit.value;
      if (val.length < 20 || val.startsWith('data:')) continue;

      const prefixBeforeLiteral = rawCode.slice(lineStartOffset, lit.startOffset);
      const assignMatch = prefixBeforeLiteral.match(
        /(?:^|[\s,{;(])(?:(?:export\s+)?(?:const|let|var)\s+|(?:public|private|readonly)\s+)?([A-Za-z_$][A-Za-z0-9_$.]*)\s*(?::\s*[^=]+)?[:=]\s*$/
      );
      const assignedIdent = assignMatch?.[1];
      const leafIdent = assignedIdent?.includes('.') ? assignedIdent.split('.').pop() : assignedIdent;

      let matchedProvider: { label: string; envFallback: string } | undefined;
      if (!DG007_DUMMY_RE.test(val)) {
        for (const pat of DG007_PROVIDER_PATTERNS) {
          if (pat.re.test(val)) {
            matchedProvider = { label: pat.label, envFallback: pat.envFallback };
            break;
          }
        }
      }

      const readsEnv = /\b(?:process\.env\.|import\.meta\.env\.|Deno\.env\.get\s*\()/i.test(rawLine);

      let detectionDetail: string | undefined;
      let envVarName = assignedIdent ? toUpperSnakeEnvName(assignedIdent) : 'API_SECRET_KEY';

      if (matchedProvider) {
        detectionDetail = `Hardcoded ${matchedProvider.label} terdeteksi pada baris ${lit.line}.`;
        envVarName = assignedIdent ? toUpperSnakeEnvName(assignedIdent) : matchedProvider.envFallback;
      } else if (
        !readsEnv &&
        val.length <= 256 &&
        !/\s/.test(val) &&
        !/^(?:https?|wss?):\/\//i.test(val) &&
        !/^(?:\.{0,2}\/)/.test(val) &&
        !DG007_DUMMY_RE.test(val) &&
        !/^(.)\1{5,}$/.test(val) &&
        !/^(?:x+|0+|12345|abcde)/i.test(val) &&
        leafIdent &&
        DG007_SENSITIVE_IDENT_RE.test(leafIdent)
      ) {
        const entropy = calculateShannonEntropy(val);
        if (entropy >= 3.8) {
          detectionDetail = `Kredensial ber-entropi tinggi (${entropy.toFixed(2)} bits/char) ditugaskan ke '${leafIdent}' secara hardcoded pada baris ${lit.line}.`;
          envVarName = toUpperSnakeEnvName(leafIdent);
        }
      }

      if (!detectionDetail) continue;

      flaggedLines.add(lit.line);
      const colStart = lit.startOffset - lineStartOffset;
      const colEnd = lit.endLine === lit.line ? lit.endOffset - lineStartOffset : rawLine.length;
      const suggestion =
        rawLine.slice(0, colStart) + `process.env.${envVarName} ?? ''` + rawLine.slice(colEnd);

      const msg = `${detectionDetail} Pindahkan secret ke environment variable (process.env.${envVarName}) dan segera rotasi kunci jika pernah tercommit.`;
      findings.push({
        line: lit.line,
        category: 'security',
        penalty: 40,
        shortReason: `-40 [DG007] Hardcoded API/cloud secret pada baris ${lit.line}`,
        detailedReason: msg,
        isCritical: true,
      });
      inlineFindings.push({
        ruleId: 'DG007',
        line: lit.line,
        severity: 'error',
        message: msg,
        suggestion,
      });
    }
  } catch {
    return flaggedLines;
  }

  return flaggedLines;
}

function findMatchingDelim(maskedCode: string, openIdx: number, openChar: string, closeChar: string): number {
  let depth = 1;
  for (let i = openIdx + 1; i < maskedCode.length; i++) {
    if (maskedCode[i] === openChar) depth++;
    else if (maskedCode[i] === closeChar && --depth === 0) return i;
  }
  return -1;
}

function findEnclosingBlockRange(maskedCode: string, pos: number): { start: number; end: number } {
  let depth = 0;
  let start = -1;
  for (let i = pos - 1; i >= 0; i--) {
    if (maskedCode[i] === '}') depth++;
    else if (maskedCode[i] === '{') {
      if (depth === 0) {
        start = i;
        break;
      }
      depth--;
    }
  }
  if (start >= 0) {
    const closeIdx = findMatchingDelim(maskedCode, start, '{', '}');
    if (closeIdx > start) return { start, end: closeIdx };
  }
  return { start: Math.max(0, pos - 600), end: Math.min(maskedCode.length, pos + 600) };
}

/** DG008: Detects unbounded async loops and external fetch() calls lacking AbortSignal timeouts. */
export function detectMissingTimeoutsAndLoops(
  rawCode: string,
  maskedCode: string,
  rawLines: string[],
  findings: LineFinding[],
  inlineFindings: InlineFinding[]
): void {
  if (typeof rawCode !== 'string' || typeof maskedCode !== 'string') {
    throw new TypeError('detectMissingTimeoutsAndLoops requires string sources');
  }
  const flaggedLines = new Set<number>();

  const loopRe = /\b(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\))\s*\{/g;
  const boundedExitRe = /\b(?:break|return|throw|process\.exit)\b|\b(?:maxRetries|maxAttempts|MAX_ATTEMPTS|attempts?|retries)\s*(?:<|<=|>|>=|===|!==)/i;

  let loopMatch: RegExpExecArray | null;
  while ((loopMatch = loopRe.exec(maskedCode)) !== null) {
    const openBraceIdx = loopMatch.index + loopMatch[0].length - 1;
    const closeBraceIdx = findMatchingDelim(maskedCode, openBraceIdx, '{', '}');
    if (closeBraceIdx === -1) continue;

    const maskedBody = maskedCode.slice(openBraceIdx + 1, closeBraceIdx);
    if (!/\bawait\b/.test(maskedBody) || boundedExitRe.test(maskedBody)) continue;

    const startLine = maskedCode.slice(0, loopMatch.index).split('\n').length;
    const endLine = maskedCode.slice(0, closeBraceIdx).split('\n').length;
    flaggedLines.add(startLine);

    const rawLine = rawLines[startLine - 1] ?? '';
    const lineStart = rawCode.lastIndexOf('\n', loopMatch.index - 1) + 1;
    const localMatchOffset = loopMatch.index - lineStart;
    const loopHeaderEnd = loopMatch[0].lastIndexOf('{');
    const suggestion =
      localMatchOffset >= 0 && localMatchOffset + loopHeaderEnd <= rawLine.length
        ? rawLine.slice(0, localMatchOffset) +
          'for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) ' +
          rawLine.slice(localMatchOffset + loopHeaderEnd)
        : 'for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {';

    const msg = `Unbounded async loop tanpa kondisi keluar eksplisit pada baris ${startLine} berisiko menggantungkan worker dan membengkakkan kuota API.`;
    findings.push({
      line: startLine,
      category: 'correctness',
      penalty: 25,
      shortReason: `-25 [DG008] Unbounded async loop tanpa break/return/batas iterasi (baris ${startLine})`,
      detailedReason: msg,
      isCritical: true,
    });
    inlineFindings.push({
      ruleId: 'DG008',
      line: startLine,
      endLine: endLine > startLine ? endLine : undefined,
      severity: 'error',
      message: msg,
      suggestion,
    });
  }

  const fetchRe = /(?:^|[^.\w$]|\b(?:globalThis|window)\.)fetch\s*\(/g;
  const criticalGatewayRe =
    /(?:openai|gemini|generativelanguage|anthropic|deepseek|radeon|stripe|payment|webhook|charge|verify)/i;
  const localMockHostRe = /(?:127\.0\.0\.1|localhost|\[::1\])/i;

  let fetchMatch: RegExpExecArray | null;
  while ((fetchMatch = fetchRe.exec(maskedCode)) !== null) {
    const openParenIdx = maskedCode.indexOf('(', fetchMatch.index);
    if (openParenIdx === -1) continue;
    const closeParenIdx = findMatchingDelim(maskedCode, openParenIdx, '(', ')');
    if (closeParenIdx === -1) continue;

    const fetchKeywordIdx = maskedCode.indexOf('fetch', fetchMatch.index);
    const fetchLine = maskedCode.slice(0, fetchKeywordIdx).split('\n').length;
    const fetchEndLine = maskedCode.slice(0, closeParenIdx).split('\n').length;
    if (flaggedLines.has(fetchLine)) continue;

    const maskedArgs = maskedCode.slice(openParenIdx + 1, closeParenIdx);
    const rawArgs = rawCode.slice(openParenIdx + 1, closeParenIdx);

    if (/\bsignal\b|\bAbortSignal\.timeout\b|\bAbortController\b/.test(maskedArgs)) continue;
    if (localMockHostRe.test(rawArgs)) continue;

    const enclosing = findEnclosingBlockRange(maskedCode, fetchKeywordIdx);
    if (/\bnew\s+AbortController\b|\bAbortSignal\.timeout\b/.test(maskedCode.slice(enclosing.start, enclosing.end))) {
      continue;
    }

    const isCriticalGateway =
      criticalGatewayRe.test(rawArgs) || criticalGatewayRe.test(rawCode.slice(enclosing.start, enclosing.end));
    flaggedLines.add(fetchLine);

    const rawLine = rawLines[fetchLine - 1] ?? '';
    let suggestion = 'fetch(url, { signal: AbortSignal.timeout(15_000) })';
    if (fetchEndLine === fetchLine && !maskedArgs.includes(',')) {
      const lineStart = rawCode.lastIndexOf('\n', fetchKeywordIdx - 1) + 1;
      const localClose = closeParenIdx - lineStart;
      if (localClose > 0 && localClose <= rawLine.length) {
        suggestion =
          rawLine.slice(0, localClose) +
          ', { signal: AbortSignal.timeout(15_000) }' +
          rawLine.slice(localClose);
      }
    }

    if (isCriticalGateway) {
      const msg = `Pemanggilan fetch() ke gateway kritis pada baris ${fetchLine} tidak menyertakan signal AbortSignal.timeout() sehingga worker dapat macet permanen.`;
      findings.push({
        line: fetchLine,
        category: 'security',
        penalty: 20,
        shortReason: `-20 [DG008] fetch() gateway kritis tanpa AbortSignal.timeout() (baris ${fetchLine})`,
        detailedReason: msg,
        isCritical: true,
      });
      inlineFindings.push({
        ruleId: 'DG008',
        line: fetchLine,
        endLine: fetchEndLine > fetchLine ? fetchEndLine : undefined,
        severity: 'error',
        message: msg,
        suggestion,
      });
    } else {
      const msg = `Pemanggilan fetch() pada baris ${fetchLine} tidak menyertakan signal AbortSignal.timeout() sebagai batas waktu jaringan.`;
      findings.push({
        line: fetchLine,
        category: 'correctness',
        penalty: 10,
        shortReason: `-10 [DG008] fetch() tanpa signal AbortSignal.timeout() (baris ${fetchLine})`,
        detailedReason: msg,
      });
      inlineFindings.push({
        ruleId: 'DG008',
        line: fetchLine,
        endLine: fetchEndLine > fetchLine ? fetchEndLine : undefined,
        severity: 'warning',
        message: msg,
        suggestion,
      });
    }
  }
}

