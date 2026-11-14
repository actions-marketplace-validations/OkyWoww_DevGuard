#!/usr/bin/env node
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import {
  analyzeCodeDeterministically,
  ParsedDevGuardReport,
} from './devguardAnalyzer.js';
import { postPullRequestComment } from './githubCommenter.js';
import type { FileAuditSummary } from './githubCommenter.js';
import { generateSarifReport } from './sarifGenerator.js';

dotenv.config();

function writeGitHubOutput(outputFile: string | undefined, key: string, value: string | number): void {
  if (!outputFile || !fs.existsSync(outputFile)) return;
  const safeKey = String(key).replace(/[\r\n=]/g, '');
  const safeValue = String(value).replace(/[\r\n]+/g, ' ').trim();
  fs.appendFileSync(outputFile, `${safeKey}=${safeValue}\n`);
}

export interface CliAuditResult {
  mode: 'zero-api' | 'hybrid';
  isLiveApi: boolean;
  parsedReport: ParsedDevGuardReport;
}

export async function evaluateCodeHybrid(
  code: string,
  apiKey?: string,
  precomputedL1?: ParsedDevGuardReport
): Promise<CliAuditResult> {
  const l1Result = precomputedL1 || analyzeCodeDeterministically(code);
  const activeKey = apiKey || process.env.GEMINI_API_KEY;

  if (!activeKey || activeKey === 'MY_GEMINI_API_KEY' || !activeKey.startsWith('AIzaSy')) {
    return {
      mode: 'zero-api',
      isLiveApi: false,
      parsedReport: l1Result,
    };
  }

  try {
    const ai = new GoogleGenAI({ apiKey: activeKey });
    const prompt = [
      'Anda adalah Principal AppSec Engineer & Zero-Leniency Adversarial Code Auditor.',
      'Evaluasi kode di dalam <code_to_review> secara jujur, ketat, dan tanpa kompromi.',
      'DILARANG memberikan skor buta 100/100.',
      '',
      `Hasil deteksi Layer 1 AST Analyzer (wajib dihormati sebagai batas atas skor):`,
      `- Security=${l1Result.skor.security}, Correctness=${l1Result.skor.correctness}, Maintainability=${l1Result.skor.maintainability}`,
      `- Baris Temuan: ${l1Result.temuanUtama.line}`,
      `- Detail: ${l1Result.temuanUtama.description}`,
      '',
      '<code_to_review>',
      code,
      '</code_to_review>',
    ].join('\n');

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Gemini API timeout')), 6500)
    );

    const response: any = await Promise.race([
      ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              apresiasi: { type: Type.STRING },
              skor: {
                type: Type.OBJECT,
                properties: {
                  security: { type: Type.INTEGER },
                  securityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                  correctness: { type: Type.INTEGER },
                  correctnessDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                  maintainability: { type: Type.INTEGER },
                  maintainabilityDeductions: { type: Type.ARRAY, items: { type: Type.STRING } },
                },
                required: ['security', 'correctness', 'maintainability'],
              },
              temuanUtama: {
                type: Type.OBJECT,
                properties: {
                  line: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: ['line', 'description'],
              },
              temuanLain: { type: Type.ARRAY, items: { type: Type.STRING } },
              analogi: {
                type: Type.OBJECT,
                properties: {
                  story: { type: Type.STRING },
                  technicalTerm: { type: Type.STRING },
                },
                required: ['story', 'technicalTerm'],
              },
              perbaikanSummary: { type: Type.STRING },
            },
            required: ['apresiasi', 'skor', 'temuanUtama', 'analogi'],
          },
        },
      }),
      timeoutPromise,
    ]);

    const geminiData = JSON.parse(response.text.trim());

    // Ceilings enforced by Layer 1 zero-leniency rubric
    const reconciledSecurity = Math.min(l1Result.skor.security, geminiData.skor?.security ?? 100);
    const reconciledCorrectness = Math.min(l1Result.skor.correctness, geminiData.skor?.correctness ?? 100);
    const reconciledMaintainability = Math.min(l1Result.skor.maintainability, geminiData.skor?.maintainability ?? 100);
    const reconciledTotal = Math.round((reconciledSecurity + reconciledCorrectness + reconciledMaintainability) / 3);

    return {
      mode: 'hybrid',
      isLiveApi: true,
      parsedReport: {
        ...l1Result,
        apresiasi: geminiData.apresiasi || l1Result.apresiasi,
        skor: {
          security: reconciledSecurity,
          securityDeductions: geminiData.skor?.securityDeductions?.length
            ? geminiData.skor.securityDeductions
            : l1Result.skor.securityDeductions,
          correctness: reconciledCorrectness,
          correctnessDeductions: geminiData.skor?.correctnessDeductions?.length
            ? geminiData.skor.correctnessDeductions
            : l1Result.skor.correctnessDeductions,
          maintainability: reconciledMaintainability,
          maintainabilityDeductions: geminiData.skor?.maintainabilityDeductions?.length
            ? geminiData.skor.maintainabilityDeductions
            : l1Result.skor.maintainabilityDeductions,
          totalScore: reconciledTotal,
        },
        temuanUtama: {
          line: l1Result.temuanUtama.line !== '-' ? l1Result.temuanUtama.line : (geminiData.temuanUtama?.line || '-'),
          description: geminiData.temuanUtama?.description || l1Result.temuanUtama.description,
        },
        temuanLain: geminiData.temuanLain?.length ? geminiData.temuanLain : l1Result.temuanLain,
        analogi: {
          story: geminiData.analogi?.story || l1Result.analogi.story,
          technicalTerm: geminiData.analogi?.technicalTerm || l1Result.analogi.technicalTerm,
        },
      },
    };
  } catch (err: any) {
    console.warn(`⚠️  Gemini API error (${err.message}). Otomatis dialihkan ke Layer 1 AST Engine.`);
    return {
      mode: 'zero-api',
      isLiveApi: false,
      parsedReport: l1Result,
    };
  }
}

export async function runAction() {
  const apiKey = process.env.GEMINI_API_KEY;
  const minScore = parseInt(process.env.DEVGUARD_MIN_SCORE || '85', 10);
  const targetPattern = process.env.DEVGUARD_TARGET || 'modified';
  const args = process.argv.slice(2);
  const explicitFileArg = args.find((a) => !a.startsWith('--'));
  const engineMode: 'HYBRID' | 'OFFLINE_AST' =
    apiKey && apiKey !== 'MY_GEMINI_API_KEY' && apiKey.startsWith('AIzaSy') ? 'HYBRID' : 'OFFLINE_AST';

  console.log('======================================================================');
  console.log('           🛡️  DEVGUARD ADVERSARIAL CODE AUDITOR (CI GATE)            ');
  console.log('======================================================================');
  console.log(`Ambang Batas Kelulusan CI : Minimal ${minScore}/100`);

  if (engineMode === 'OFFLINE_AST') {
    console.log('Mode Eksekusi             : 🛡️  Zero-API (100% Offline AST Engine - Gratis)');
  } else {
    console.log('Mode Eksekusi             : 🤖 Hybrid Dual-Layer (AST + Gemini 3.8 Flash)');
  }

  // 1. Dapatkan daftar berkas target
  let filesToAudit: string[] = [];

  if (explicitFileArg && fs.existsSync(explicitFileArg)) {
    filesToAudit = [explicitFileArg];
  } else if (targetPattern === 'all') {
    // Scan recursively for py, ts, js excluding node_modules, dist, etc.
    const scanDir = (dir: string): string[] => {
      let results: string[] = [];
      const list = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of list) {
        if (
          item.name.startsWith('.') ||
          ['node_modules', 'dist', 'build', 'coverage', 'remotion', 'out'].includes(item.name) ||
          item.name.includes('.test.') ||
          item.name.includes('.spec.') ||
          item.name === 'devguardAnalyzer.ts' ||
          item.name === 'devguard_verify.py'
        ) {
          continue;
        }
        const full = path.join(dir, item.name);
        if (item.isDirectory()) {
          results = results.concat(scanDir(full));
        } else if (/\.(py|ts|js|jsx|tsx)$/.test(item.name) && !item.name.endsWith('.d.ts')) {
          results.push(full);
        }
      }
      return results;
    };
    filesToAudit = scanDir(process.cwd());
  } else {
    // Modified files via git diff
    try {
      const gitDiff = execSync('git diff --name-only HEAD~1 HEAD || git diff --name-only HEAD', {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      filesToAudit = gitDiff
        .split('\n')
        .map((f) => f.trim())
        .filter(
          (f) =>
            f &&
            /\.(py|ts|js|jsx|tsx)$/.test(f) &&
            !f.endsWith('.d.ts') &&
            !f.startsWith('remotion/') &&
            !f.includes('.test.') &&
            !f.includes('.spec.') &&
            !f.endsWith('devguardAnalyzer.ts') &&
            !f.endsWith('devguard_verify.py')
        );
    } catch {
      console.warn('⚠️  Git diff tidak menemukan riwayat commit; beralih ke pengecekan berkas lokal.');
      filesToAudit = [];
    }
  }

  if (filesToAudit.length === 0) {
    console.log('\n✅ Tidak ada berkas target (.py, .ts, .js) yang diubah. DevGuard quality check lolos.');
    const sarifFile = process.env.DEVGUARD_SARIF_OUTPUT || 'devguard-results.sarif';
    generateSarifReport([], sarifFile);
    const outputFile = process.env.GITHUB_OUTPUT;
    writeGitHubOutput(outputFile, 'overall_score', 100);
    writeGitHubOutput(outputFile, 'audit_status', 'PASS');
    writeGitHubOutput(outputFile, 'sarif_file', sarifFile);
    process.exit(0);
  }

  console.log(`\n📂 Jumlah berkas yang akan diaudit: ${filesToAudit.length}`);
  console.log('----------------------------------------------------------------------');

  let hasFatalFailure = false;
  let totalScoreSum = 0;
  let auditedCount = 0;
  const summaries: FileAuditSummary[] = [];

  for (const filePath of filesToAudit) {
    if (!fs.existsSync(filePath)) continue;

    const codeContent = fs.readFileSync(filePath, 'utf-8');
    auditedCount++;

    console.log(`\n🔍 Menganalisis: ${filePath}`);
    const result = await evaluateCodeHybrid(codeContent, apiKey);
    const report = result.parsedReport;
    const score = report.skor;
    const passed = !(score.totalScore < minScore || (!report.isHardened && score.security < 70));

    totalScoreSum += score.totalScore;
    summaries.push({
      filePath,
      security: score.security,
      correctness: score.correctness,
      maintainability: score.maintainability,
      overall: score.totalScore,
      passed,
      fatalFlaws: !passed && report.temuanUtama.description ? [report.temuanUtama.description] : [],
      defenseInDepth: report.residualNotes || [],
    });

    console.log(`   - Security        : ${score.security}/100`);
    console.log(`   - Correctness     : ${score.correctness}/100`);
    console.log(`   - Maintainability : ${score.maintainability}/100`);
    console.log(`   - Overall Guard   : ${score.totalScore}/100 [Target: ${minScore}]`);

    if (!passed) {
      console.error(`   ❌ GAGAL: ${filePath} mendapatkan skor ${score.totalScore}/100 (Batas: ${minScore})`);
      if (report.temuanUtama && report.temuanUtama.description) {
        console.error(`   💣 Temuan Fatal (${report.temuanUtama.line}): ${report.temuanUtama.description}`);
      }
      hasFatalFailure = true;
    } else {
      console.log(`   ✅ LOLOS: ${filePath} memenuhi standar keamanan dan mutu kode.`);
    }
  }

  const avgScore = auditedCount > 0 ? Math.round(totalScoreSum / auditedCount) : 100;
  console.log('\n======================================================================');
  console.log(`RATA-RATA SKOR KESELURUHAN: ${avgScore}/100`);

  // GitHub Actions Workflow Output Parameters
  const outputFile = process.env.GITHUB_OUTPUT;
  writeGitHubOutput(outputFile, 'overall_score', avgScore);
  writeGitHubOutput(outputFile, 'audit_status', hasFatalFailure ? 'FAIL' : 'PASS');

  // Comment before process.exit so the report is posted on both pass and failure.
  await postPullRequestComment(summaries, minScore, engineMode);

  // Generate SARIF v2.1.0 report before process.exit so findings are always exported
  const sarifFile = process.env.DEVGUARD_SARIF_OUTPUT || 'devguard-results.sarif';
  generateSarifReport(summaries, sarifFile);

  writeGitHubOutput(outputFile, 'sarif_file', sarifFile);

  if (hasFatalFailure) {
    console.error('🚫 DevGuard Quality Gate Rejected: Ditemukan celah keamanan atau regresi logika.');
    console.error('   Perbaiki celah di atas atau terapkan patch perbaikan sebelum melakukan merge PR.\n');
    process.exit(1);
  } else {
    console.log('🎉 Seluruh berkas yang diaudit lolos inspeksi DevGuard Quality Gate!\n');
    process.exit(0);
  }
}

// Check if run directly
const isMain = process.argv[1] && (
  process.argv[1].endsWith('cli.ts') ||
  process.argv[1].endsWith('cli.js') ||
  process.argv[1].includes('cli')
);

if (isMain) {
  runAction().catch((err) => {
    console.error('Fatal CLI Error:', err);
    process.exit(1);
  });
}
