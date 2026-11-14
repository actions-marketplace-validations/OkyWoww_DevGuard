import * as fs from 'node:fs';
import * as path from 'node:path';
import type { InlineFinding } from './devguardAnalyzer.js';

export interface FileAuditSummary {
  filePath: string;
  security: number;
  correctness: number;
  maintainability: number;
  overall: number;
  passed: boolean;
  fatalFlaws: string[];
  defenseInDepth: string[];
  inlineFindings?: InlineFinding[];
}

export const COMMENT_SIGNATURE = '<!-- devguard-adversarial-audit-sticky-comment -->';

interface PrContext {
  token: string;
  repo: string;
  prNumber: number;
  apiBase: string;
  headers: Record<string, string>;
}

function escapeTableCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/`/g, '\\`').replace(/[\r\n]+/g, ' ');
}

function normalizePosixRepoPath(filePath: string): string {
  const relPath = path.isAbsolute(filePath) ? path.relative(process.cwd(), filePath) : filePath;
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '');
}

function resolvePrContext(): PrContext | null {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!token || !repo || !eventPath || !fs.existsSync(eventPath)) {
    return null;
  }

  let prNumber: number | undefined;
  try {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf-8')) as {
      pull_request?: { number?: number };
    };
    prNumber = eventData.pull_request?.number;
  } catch (err) {
    console.warn('⚠️ Gagal membaca payload event GitHub:', err);
    return null;
  }

  if (!prNumber) {
    return null;
  }

  const apiBase = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'DevGuard-Action-Bot',
  };

  return { token, repo, prNumber, apiBase, headers };
}

export async function postPullRequestComment(
  summaries: FileAuditSummary[],
  minScore: number,
  mode: 'HYBRID' | 'OFFLINE_AST'
): Promise<void> {
  const ctx = resolvePrContext();
  if (!ctx) {
    console.log('ℹ️  Bukan konteks Pull Request GitHub atau GITHUB_TOKEN tidak tersedia. Melewati Auto-PR Comment.');
    return;
  }

  const { repo, prNumber, apiBase, headers } = ctx;
  const allPassed = summaries.every((summary) => summary.passed);
  const badgeStatus = allPassed ? '✅ PASSED (READY TO MERGE)' : '🚫 REJECTED (SECURITY GATE FAILED)';
  const engineLabel = mode === 'HYBRID'
    ? 'Hybrid Dual-Layer (Deterministic AST + Gemini 3.8 Flash)'
    : '100% Offline Deterministic AST Engine';

  const tableRows = summaries.map((summary) => {
    const icon = summary.passed ? '🟢' : '🔴';
    return `| ${icon} \`${escapeTableCell(summary.filePath)}\` | **${summary.overall}/100** | ${summary.security} | ${summary.correctness} | ${summary.maintainability} |`;
  }).join('\n');

  let detailsSection = '';
  for (const summary of summaries) {
    if (summary.fatalFlaws.length > 0 || summary.defenseInDepth.length > 0) {
      detailsSection += `\n#### 🔍 Detail Audit: \`${summary.filePath.replace(/`/g, '\\`').replace(/[\r\n]+/g, ' ')}\`\n`;
      if (summary.fatalFlaws.length > 0) {
        detailsSection += '**💣 Celah Keamanan / Logika Terdeteksi:**\n';
        summary.fatalFlaws.forEach((flaw) => {
          detailsSection += `- ❌ ${flaw}\n`;
        });
      }
      if (summary.defenseInDepth.length > 0) {
        detailsSection += '\n**🛡️ Catatan Defense-in-Depth (Alasan Skor Tidak 100/100):**\n';
        summary.defenseInDepth.forEach((note) => {
          detailsSection += `- ⚠️ ${note}\n`;
        });
      }
    }
  }

  const markdownBody = `${COMMENT_SIGNATURE}
## 🛡️ DevGuard Adversarial Security Gatekeeper

| Status Gerbang | Ambang Batas Skor | Mode Mesin |
| :--- | :--- | :--- |
| **${badgeStatus}** | \`${minScore}/100\` | \`${engineLabel}\` |

### 📊 Skor Evaluasi Berkas
| Berkas | Skor Akhir | Security | Correctness | Maintainability |
| :--- | :---: | :---: | :---: | :---: |
${tableRows || '| Tidak ada berkas yang diaudit | — | — | — | — |'}
${detailsSection}

---
*Diinspeksi secara otomatis oleh [DevGuard Zero-Leniency Auditor](https://github.com/marketplace/actions/devguard-adversarial-code-auditor).*`;

  const commentsUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments`;

  try {
    // Read every comments page so an older sticky comment is not missed on busy PRs.
    let botComment: { id: number; body?: string } | undefined;
    for (let page = 1; page <= 10; page++) {
      const listResp = await fetch(`${commentsUrl}?per_page=100&page=${page}`, {
        headers,
        signal: AbortSignal.timeout(15_000),
      });
      if (!listResp.ok) {
        console.warn(`⚠️ Gagal membaca komentar PR (HTTP ${listResp.status}); komentar laporan tidak dibuat untuk menghindari duplikasi.`);
        return;
      }

      const existingComments = await listResp.json() as Array<{ id: number; body?: string }>;
      botComment = existingComments.find((comment) => comment.body?.includes(COMMENT_SIGNATURE));
      if (botComment || existingComments.length < 100) break;
    }

    if (botComment) {
      const updateUrl = `${apiBase}/repos/${repo}/issues/comments/${botComment.id}`;
      const updateResp = await fetch(updateUrl, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ body: markdownBody }),
        signal: AbortSignal.timeout(15_000),
      });
      if (updateResp.ok) {
        console.log(`💬 Berhasil memperbarui komentar laporan DevGuard pada PR #${prNumber}.`);
      } else {
        console.warn(`⚠️ Gagal memperbarui komentar PR (HTTP ${updateResp.status}).`);
      }
      return;
    }

    const createResp = await fetch(commentsUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ body: markdownBody }),
      signal: AbortSignal.timeout(15_000),
    });

    if (createResp.ok) {
      console.log(`💬 Berhasil mengirim komentar laporan DevGuard ke PR #${prNumber}.`);
    } else {
      console.warn(`⚠️ Gagal mengirim komentar PR (HTTP ${createResp.status}): Pastikan workflow memiliki izin 'pull-requests: write'.`);
    }
  } catch (error) {
    console.warn('⚠️ Terjadi kesalahan jaringan saat menghubungi GitHub API:', error);
    return;
  }
}

export async function postInlineReviewComments(summaries: FileAuditSummary[]): Promise<void> {
  const pending: Array<{ path: string; line: number; body: string; ruleId: string }> = [];

  for (const summary of summaries) {
    if (!summary.inlineFindings || summary.inlineFindings.length === 0) continue;
    const normalizedPath = normalizePosixRepoPath(summary.filePath);

    for (const finding of summary.inlineFindings) {
      const targetLine = Math.max(1, finding.line);
      let body = `🛡️ **[DevGuard ${finding.ruleId}]** (${finding.severity.toUpperCase()}): ${finding.message}`;
      if (finding.suggestion) {
        body += `\n\n\`\`\`suggestion\n${finding.suggestion}\n\`\`\``;
      }
      pending.push({ path: normalizedPath, line: targetLine, body, ruleId: finding.ruleId });
    }
  }

  if (pending.length === 0) return;

  const ctx = resolvePrContext();
  if (!ctx) return;

  const { repo, prNumber, apiBase, headers } = ctx;
  const reviewCommentsUrl = `${apiBase}/repos/${repo}/pulls/${prNumber}/comments`;

  try {
    // Deduplicate against existing inline PR review comments matching path, line, and [DevGuard DGxxx] / [DGxxx]
    const existingKeys = new Set<string>();
    for (let page = 1; page <= 10; page++) {
      const listResp = await fetch(`${reviewCommentsUrl}?per_page=100&page=${page}`, {
        headers,
        signal: AbortSignal.timeout(15_000),
      });
      if (!listResp.ok) {
        console.warn(`⚠️ Gagal membaca komentar review PR (HTTP ${listResp.status}); melewati inline review untuk menghindari spam.`);
        return;
      }

      const existing = await listResp.json() as Array<{
        path?: string;
        line?: number | null;
        original_line?: number | null;
        body?: string;
      }>;

      for (const item of existing) {
        const commentLine = item.line ?? item.original_line;
        if (!item.path || !commentLine || !item.body) continue;
        const ruleMatch = item.body.match(/\[(?:DevGuard\s+)?(DG\d{3})\]/);
        if (ruleMatch?.[1]) {
          existingKeys.add(`${item.path}:${commentLine}:${ruleMatch[1]}`);
        }
      }

      if (existing.length < 100) break;
    }

    const dedupedComments = pending
      .filter((item) => !existingKeys.has(`${item.path}:${item.line}:${item.ruleId}`))
      .map(({ path: filePath, line, body }) => ({
        path: filePath,
        line,
        side: 'RIGHT' as const,
        body,
      }));

    if (dedupedComments.length === 0) {
      console.log(`ℹ️  Seluruh ${pending.length} temuan inline PR #${prNumber} sudah terpasang sebelumnya.`);
      return;
    }

    const createReviewUrl = `${apiBase}/repos/${repo}/pulls/${prNumber}/reviews`;
    const reviewResp = await fetch(createReviewUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        event: 'COMMENT',
        comments: dedupedComments,
      }),
      signal: AbortSignal.timeout(15_000),
    });

    if (reviewResp.status === 422) {
      console.warn(`⚠️ GitHub PR Review API mengembalikan HTTP 422 (baris di luar diff hunk); inline comment dilewati secara aman.`);
      return;
    }

    if (reviewResp.ok) {
      console.log(`📌 Berhasil menyematkan ${dedupedComments.length} inline PR review comment pada PR #${prNumber}.`);
    } else {
      console.warn(`⚠️ Gagal mengirim inline PR review comment (HTTP ${reviewResp.status}); melanjutkan pipeline secara fail-open.`);
    }
  } catch (error) {
    console.warn('⚠️ Terjadi kesalahan jaringan saat mengirim inline PR review comment:', error);
    return;
  }
}
