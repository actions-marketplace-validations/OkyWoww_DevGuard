import * as fs from 'node:fs';

export interface FileAuditSummary {
  filePath: string;
  security: number;
  correctness: number;
  maintainability: number;
  overall: number;
  passed: boolean;
  fatalFlaws: string[];
  defenseInDepth: string[];
}

export const COMMENT_SIGNATURE = '<!-- devguard-adversarial-audit-sticky-comment -->';

function escapeTableCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/`/g, '\\`').replace(/[\r\n]+/g, ' ');
}

export async function postPullRequestComment(
  summaries: FileAuditSummary[],
  minScore: number,
  mode: 'HYBRID' | 'OFFLINE_AST'
): Promise<void> {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;

  if (!token || !repo || !eventPath || !fs.existsSync(eventPath)) {
    console.log('ℹ️  Bukan konteks Pull Request GitHub atau GITHUB_TOKEN tidak tersedia. Melewati Auto-PR Comment.');
    return;
  }

  let prNumber: number | undefined;
  try {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf-8'));
    prNumber = eventData.pull_request?.number;
  } catch (err) {
    console.warn('⚠️ Gagal membaca payload event GitHub:', err);
    return;
  }

  if (!prNumber) {
    console.log('ℹ️  Action berjalan pada event non-PR (misal: direct push). Melewati Auto-PR Comment.');
    return;
  }

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

  const apiBase = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  const commentsUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'DevGuard-Action-Bot',
  };

  try {
    // Read every comments page so an older sticky comment is not missed on busy PRs.
    let botComment: { id: number; body?: string } | undefined;
    for (let page = 1; page <= 10; page++) {
      const listResp = await fetch(`${commentsUrl}?per_page=100&page=${page}`, { headers });
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
    });

    if (createResp.ok) {
      console.log(`💬 Berhasil mengirim komentar laporan DevGuard ke PR #${prNumber}.`);
    } else {
      console.warn(`⚠️ Gagal mengirim komentar PR (HTTP ${createResp.status}): Pastikan workflow memiliki izin 'pull-requests: write'.`);
    }
  } catch (error) {
    console.warn('⚠️ Terjadi kesalahan jaringan saat menghubungi GitHub API:', error);
  }
}
