import * as fs from 'fs';
import * as path from 'path';
import type { FileAuditSummary } from './githubCommenter.js';

export interface SarifFindingLocation {
  filePath: string;
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: string;
  startLine?: number;
}

/**
 * Mencoba mengekstrak nomor baris jika pesan error mengandung pola "Line X", "baris X", atau "[Baris X]",
 * fallback ke baris 1 jika temuan bersifat arsitektural tingkat file.
 */
function extractLineNumber(text: string): number {
  const match = text.match(/(?:line|baris)\s*[:#\s]?\s*(\d+)/i);
  if (match && match[1]) {
    const parsed = parseInt(match[1], 10);
    return parsed > 0 ? parsed : 1;
  }
  return 1;
}

export function generateSarifReport(
  summaries: FileAuditSummary[],
  outputPath: string = 'devguard-results.sarif'
): string {
  const rulesMap = new Map<string, {
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    defaultConfiguration: { level: 'error' | 'warning' | 'note' };
    properties: { tags: string[]; 'security-severity': string };
  }>();

  // Rule 1: Fatal Security / Logic Flaw (Blocker)
  rulesMap.set('DG001', {
    id: 'DG001',
    name: 'AdversarialSecurityOrLogicFlaw',
    shortDescription: {
      text: 'Critical security vulnerability or exploitable logic flaw detected by DevGuard.'
    },
    fullDescription: {
      text: 'DevGuard Hybrid Auditor identified a deterministic AST sink, TOCTOU race condition, type bypass, or critical security risk that violates the quality gate.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['security', 'adversarial-audit', 'external/cwe/cwe-693'],
      'security-severity': '8.5'
    }
  });

  // Rule 2: Defense-in-Depth Hardening Note (Warning/Note)
  rulesMap.set('DG002', {
    id: 'DG002',
    name: 'DefenseInDepthRecommendation',
    shortDescription: {
      text: 'Defense-in-Depth architectural hardening recommendation.'
    },
    fullDescription: {
      text: 'Zero-Leniency audit note explaining why code does not receive a 100/100 score and how to harden against secondary edge cases.'
    },
    defaultConfiguration: { level: 'warning' },
    properties: {
      tags: ['security', 'defense-in-depth', 'maintainability'],
      'security-severity': '4.0'
    }
  });

  // Rule 3: Threshold Gate Failure
  rulesMap.set('DG003', {
    id: 'DG003',
    name: 'OverallScoreBelowThreshold',
    shortDescription: {
      text: 'File overall DevGuard score fell below minimum CI threshold.'
    },
    fullDescription: {
      text: 'The combined Security, Correctness, and Maintainability score did not meet the configured minimum threshold for this repository.'
    },
    defaultConfiguration: { level: 'error' },
    properties: {
      tags: ['quality-gate', 'security'],
      'security-severity': '7.0'
    }
  });

  const results: Array<Record<string, unknown>> = [];

  for (const summary of summaries) {
    const relPath = path.isAbsolute(summary.filePath)
      ? path.relative(process.cwd(), summary.filePath)
      : summary.filePath;
    const normalizedUri = relPath.replace(/\\/g, '/').replace(/^\.\//, '');

    // 1. Masukkan semua Fatal Flaws sebagai SARIF 'error' (DG001)
    for (const flaw of summary.fatalFlaws) {
      const line = extractLineNumber(flaw);
      results.push({
        ruleId: 'DG001',
        level: 'error',
        message: { text: flaw },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: normalizedUri,
                uriBaseId: '%SRCROOT%'
              },
              region: {
                startLine: line,
                startColumn: 1
              }
            }
          }
        ]
      });
    }

    // 2. Jika skor gagal tapi fatalFlaws kosong, catat pelanggaran threshold (DG003)
    if (!summary.passed && summary.fatalFlaws.length === 0) {
      results.push({
        ruleId: 'DG003',
        level: 'error',
        message: {
          text: `DevGuard overall score (${summary.overall}/100) is below the required threshold. (Security: ${summary.security}, Correctness: ${summary.correctness}, Maintainability: ${summary.maintainability})`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: normalizedUri,
                uriBaseId: '%SRCROOT%'
              },
              region: {
                startLine: 1,
                startColumn: 1
              }
            }
          }
        ]
      });
    }

    // 3. Masukkan catatan Defense-in-Depth sebagai SARIF 'warning' (DG002)
    for (const note of summary.defenseInDepth) {
      const line = extractLineNumber(note);
      results.push({
        ruleId: 'DG002',
        level: 'warning',
        message: { text: note },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: normalizedUri,
                uriBaseId: '%SRCROOT%'
              },
              region: {
                startLine: line,
                startColumn: 1
              }
            }
          }
        ]
      });
    }
  }

  const sarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'DevGuard Adversarial Code Auditor',
            informationUri: 'https://github.com/OkyWoww/DevGuard',
            version: '1.1.0',
            rules: Array.from(rulesMap.values())
          }
        },
        results
      }
    ]
  };

  const resolvedPath = path.resolve(process.cwd(), outputPath);
  fs.writeFileSync(resolvedPath, JSON.stringify(sarifLog, null, 2), 'utf-8');
  console.log(`📄 Laporan SARIF v2.1.0 berhasil dibuat: ${resolvedPath} (${results.length} anotasi)`);

  return resolvedPath;
}
