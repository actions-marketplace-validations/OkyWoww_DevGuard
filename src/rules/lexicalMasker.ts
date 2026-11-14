export type DevGuardRuleId =
  | 'DG001' | 'DG002' | 'DG003' | 'DG004'
  | 'DG005' | 'DG006' | 'DG007' | 'DG008';

export interface InlineFinding {
  ruleId: DevGuardRuleId;
  line: number;
  endLine?: number;
  severity: 'error' | 'warning';
  message: string;
  suggestion?: string;
}

export interface AuditAnalyzeOptions {
  filePath?: string;
  declaredDependencies?: ReadonlySet<string> | readonly string[];
  builtinModules?: readonly string[];
}

export interface LineFinding {
  line: number;
  extraLines?: number[];
  category: 'security' | 'correctness' | 'maintainability';
  penalty: number;
  shortReason: string;
  detailedReason: string;
  isCritical?: boolean;
}

export interface ExtractedStringLiteral {
  value: string;
  quote: string;
  line: number;
  endLine: number;
  startOffset: number;
  endOffset: number;
  hasInterpolation: boolean;
}

const REGEX_PRECEDING_CHARS = new Set([
  '', '\n', '(', '[', '{', ',', ';', '=', ':', '?', '!', '&', '|', '^', '~', '+', '-', '*', '%', '<', '>',
]);
const REGEX_PRECEDING_KEYWORDS = new Set([
  'return', 'typeof', 'void', 'delete', 'await', 'throw', 'case', 'in', 'of', 'instanceof', 'new', 'else', 'do', 'yield', 'export', 'default',
]);

function skipQuotedLiteral(
  rawCode: string,
  out: string[],
  startIdx: number,
  startLine: number
): { nextIdx: number; endLine: number; literal: ExtractedStringLiteral } {
  const quote = rawCode[startIdx];
  let line = startLine;
  let hasInterpolation = false;
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
  while (i < rawCode.length) {
    const ch = rawCode[i];
    if (ch === '\\' && i + 1 < rawCode.length) {
      if (out[i] !== '\n') out[i] = ' ';
      i++;
      if (rawCode[i] === '\n') line++;
      else if (out[i] !== '\n') out[i] = ' ';
      i++;
      continue;
    }
    if (quote === '`' && ch === '$' && rawCode[i + 1] === '{') hasInterpolation = true;
    if (ch === quote) {
      if (out[i] !== '\n') out[i] = ' ';
      break;
    }
    if (ch === '\n') {
      if (quote !== '`') break;
      line++;
    } else if (out[i] !== '\n') out[i] = ' ';
    i++;
  }
  const endOffset = Math.min(rawCode.length, i + 1);
  return {
    nextIdx: i,
    endLine: line,
    literal: {
      value: rawCode.slice(startIdx + 1, rawCode[endOffset - 1] === quote ? endOffset - 1 : endOffset),
      quote,
      line: startLine,
      endLine: line,
      startOffset: startIdx,
      endOffset,
      hasInterpolation,
    },
  };
}

function skipRegexLiteral(rawCode: string, out: string[], startIdx: number): number {
  if (out[startIdx] !== '\n') out[startIdx] = ' ';
  let i = startIdx + 1;
  let inClass = false;
  while (i < rawCode.length && rawCode[i] !== '\n') {
    const ch = rawCode[i];
    if (out[i] !== '\n') out[i] = ' ';
    if (ch === '\\' && i + 1 < rawCode.length && rawCode[i + 1] !== '\n') {
      i++;
      if (out[i] !== '\n') out[i] = ' ';
    } else if (ch === '[' && !inClass) inClass = true;
    else if (ch === ']' && inClass) inClass = false;
    else if (ch === '/' && !inClass) {
      while (i + 1 < rawCode.length && /[a-z]/i.test(rawCode[i + 1])) {
        i++;
        if (out[i] !== '\n') out[i] = ' ';
      }
      break;
    }
    i++;
  }
  return i;
}

/** Masks comments, regexes, and string literals while keeping 1:1 line/offset mapping. */
export function analyzeLexicalStructure(
  rawCode: string,
  allowHashComments: boolean
): { maskedCode: string; stringLiterals: ExtractedStringLiteral[] } {
  if (typeof rawCode !== 'string') throw new TypeError('rawCode must be a string');
  const out = rawCode.split('');
  const stringLiterals: ExtractedStringLiteral[] = [];
  let line = 1;
  let prevNonWs = '';
  let currentWord = '';
  let lastWord = '';

  try {
    for (let i = 0; i < rawCode.length; i++) {
      const ch = rawCode[i];
      const next = rawCode[i + 1];
      if (ch === '\n') {
        line++;
        lastWord = currentWord || lastWord;
        currentWord = '';
        prevNonWs = '\n';
      } else if ((ch === '/' && next === '/') || ((allowHashComments || (i === 0 && next === '!')) && ch === '#')) {
        while (i < rawCode.length && rawCode[i] !== '\n') out[i++] = ' ';
        if (rawCode[i] === '\n') { line++; prevNonWs = '\n'; }
        currentWord = '';
      } else if (!allowHashComments && ch === '/' && next === '*') {
        out[i] = ' ';
        out[i + 1] = ' ';
        for (i += 2; i < rawCode.length; i++) {
          if (rawCode[i] === '*' && rawCode[i + 1] === '/') { out[i] = ' '; out[++i] = ' '; break; }
          if (rawCode[i] === '\n') line++; else out[i] = ' ';
        }
        currentWord = '';
      } else if (!allowHashComments && ch === '/' && (REGEX_PRECEDING_KEYWORDS.has(currentWord || lastWord) || (!currentWord && REGEX_PRECEDING_CHARS.has(prevNonWs)))) {
        i = skipRegexLiteral(rawCode, out, i);
        prevNonWs = ')';
        currentWord = '';
        lastWord = '';
      } else if (ch === '\'' || ch === '"' || ch === '`') {
        const res = skipQuotedLiteral(rawCode, out, i, line);
        stringLiterals.push(res.literal);
        i = res.nextIdx;
        line = res.endLine;
        prevNonWs = res.literal.quote;
        currentWord = '';
        lastWord = '';
      } else if (/[A-Za-z0-9_$]/.test(ch)) {
        currentWord += ch;
        prevNonWs = ch;
      } else {
        if (currentWord) { lastWord = currentWord; currentWord = ''; }
        if (!/\s/.test(ch)) { prevNonWs = ch; lastWord = ''; }
      }
    }
  } catch {
    return { maskedCode: rawCode, stringLiterals: [] };
  }
  return { maskedCode: out.join(''), stringLiterals };
}

export function calculateShannonEntropy(input: string): number {
  if (typeof input !== 'string' || !input) return 0;
  const freq = new Map<string, number>();
  for (let i = 0; i < input.length; i++) freq.set(input[i], (freq.get(input[i]) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Optimal String Alignment (Damerau-Levenshtein) distance treating adjacent swaps as 1 edit. */
export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, dp[i - 2][j - 2] + 1);
      }
      dp[i][j] = val;
    }
  }
  return dp[m][n];
}

export function isCommentOrEmptyLine(line: string): boolean {
  const t = line.trim();
  return !t || t.startsWith('//') || t.startsWith('#') || t.startsWith('/*') || t.startsWith('*') || t.startsWith('"""') || t.startsWith("'''");
}
