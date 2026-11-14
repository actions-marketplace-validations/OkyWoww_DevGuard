# 🛡️ DevGuard v1.2.0 — The AI-Slop & Vibe-Coding Security Gatekeeper

[![Zero-Dependency Runtime](https://img.shields.io/badge/Runtime-100%25%20Zero--Dependency-emerald.svg)](#architecture)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0%20Compliant-blue.svg)](#github-code-scanning-sarif)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1.2.0-black.svg)](#quick-start-60-second-setup)

**DevGuard** is a deterministic CI/CD security gatekeeper engineered to catch silent failures, slopsquatting, leaked API keys, and financial race conditions hidden inside AI-generated (*Cursor, Windsurf, Copilot, Antigravity*) Pull Requests before they reach production.

Unlike generic LLM code reviewers that only leave probabilistic chat comments, DevGuard combines a **0-latency Deterministic AST/Heuristic Engine** with **Gemini Adversarial Reasoning**, posts **One-Click GitHub Suggested Changes** directly on offending diff lines, and uploads **OASIS SARIF v2.1.0** reports to GitHub Code Scanning.

---

## 🎯 Why DevGuard?

Modern AI coding assistants accelerate delivery, but frequently introduce subtle, high-impact defects ("AI-Slop") that pass traditional linters and unit tests:

* **Slopsquatting & Phantom Imports:** Hallucinated or typosquatted NPM packages (`lodahs`, `express-jwt-verify`) that expose your build to supply-chain attacks.
* **Silent Failure Slop:** Empty `catch (e) {}` or `console.log`-only error handlers swallowing critical payment, database, or authentication failures.
* **Check-Then-Act Financial Race Conditions (TOCTOU):** Non-atomic balance or inventory checks separated by `await` calls, enabling double-spending under concurrent load.
* **Hardcoded AI & Payment Keys:** Prototype API keys (`AIzaSy...`, `sk_live_...`, `ghp_...`) accidentally committed into Pull Requests.
* **Unbounded Async Loops & Hanging Fetches:** `while (true)` polling or `fetch()` calls missing `AbortSignal.timeout()`, leading to worker exhaustion and runaway API bills.

---

## 📋 Deterministic Gatekeeper Rules (`DG001`–`DG008`)

Layer 1 runs **100% offline with zero external runtime dependencies** and cannot be bypassed by prompt injection comments inside source files.

| Rule ID | Category | Detection Target | Default Severity | Auto-Fix Suggestion |
| :--- | :--- | :--- | :---: | :---: |
| **`DG001`** | Code Execution & Traversal | Arbitrary `eval()`, unsanitized shell execution, and uncontained path traversal sinks | `error` | Yes |
| **`DG002`** | Quality & Threshold Gate | Overall audit score falling below configured repository quality threshold | `warning` | — |
| **`DG003`** | Adversarial Audit Gate | Deep semantic, architectural, or defense-in-depth flaws flagged by Layer 2 Gemini reasoning | `error` | Yes |
| **`DG004`** | Supply Chain / Slopsquatting | Typosquatted NPM imports (Damerau-Levenshtein check) & phantom dependencies missing from `package.json` | `error` | Yes |
| **`DG005`** | Silent Failure Slop | Swallowed exceptions (empty or `console.*`-only `catch` blocks) in payment, auth, or DB flows | `error` / `warning` | — |
| **`DG006`** | Financial Concurrency | Non-atomic balance/stock mutations (`check-then-act` TOCTOU across `await` boundaries without locks) | `error` | Yes |
| **`DG007`** | Credential & Secret Leak | Hardcoded AI, cloud, & payment keys (`AIza...`, `sk_live_...`, `ghp_...`, `AKIA...`) & high-entropy secret literals | `error` | Yes (`process.env`) |
| **`DG008`** | Infrastructure Resilience | Unbounded `while (true)` async loops & network `fetch()` calls missing `AbortSignal.timeout()` | `error` / `warning` | Yes (`AbortSignal.timeout`) |

---

## ⚡ Quick Start (60-Second Setup)

Add `.github/workflows/devguard.yml` to your repository. DevGuard works out-of-the-box in **Offline Deterministic Mode** (no API key required) or **Hybrid Dual-Layer Mode** when `GEMINI_API_KEY` is provided.

```yaml
name: DevGuard Security Gatekeeper

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  devguard-audit:
    name: AI-Slop & Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run DevGuard v1.2.0
        id: devguard
        uses: OkyWoww/DevGuard@v1.2.0
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          # Optional: Enable Layer 2 Gemini Adversarial Reasoning
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
          threshold: "80"
          fail_on_error: "true"

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.devguard.outputs.sarif_file }}
```

---

## 🔧 Action Inputs & Outputs

### Inputs

| Input | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `github_token` | **Yes** | `${{ github.token }}` | Token used to post sticky PR summaries and inline `suggestion` review comments. |
| `gemini_api_key` | No | `""` | Google Gemini API key for Layer 2 Adversarial Reasoning. Falls back gracefully to Layer 1 Offline AST mode if omitted or rate-limited. |
| `threshold` | No | `"80"` | Minimum overall score (`0`–`100`) required to pass the PR gate. |
| `fail_on_error` | No | `"true"` | Exit with code `1` (blocking PR merge) when fatal flaws (`DG001`, `DG003`–`DG008`) are detected. |

### Outputs

| Output | Example | Description |
| :--- | :--- | :--- |
| `sarif_file` | `devguard-results.sarif` | Path to the generated OASIS SARIF v2.1.0 report. |
| `overall_score` | `92` | Aggregate audit score across all scanned files (`0`–`100`). |
| `audit_status` | `PASS` / `FAIL` | Final gatekeeper verdict for downstream CI steps. |

---

## 🏗️ Hybrid Dual-Layer Architecture

1. **Layer 1 — Deterministic AST & Heuristic Engine (`0-Latency`, `Zero-Dependency`):**
   * Built strictly on native Node.js modules (`node:fs`, `node:path`, `node:http`, `node:https`, `node:module`).
   * Immune to prompt injection attempts hidden in code comments (`// IGNORE ALL PREVIOUS INSTRUCTIONS`).
   * Cross-checks imported packages against the nearest `package.json` and Node built-ins without external registry latency.
2. **Layer 2 — Gemini Adversarial Reasoning (`Fail-Open`):**
   * Reviews subtle business-logic flaws and defense-in-depth gaps when `gemini_api_key` is configured.
   * Designed with strict **Fail-Open Resilience**: if the external LLM API times out or returns HTTP 429/5xx, DevGuard seamlessly completes the audit using Layer 1 results and still writes the SARIF report.
3. **One-Click PR Inline Remediation & Sticky Summary:**
   * Posts inline review comments directly on affected diff lines with ready-to-commit GitHub ` ```suggestion ` blocks (deduplicated per `path:line:ruleId` and fail-open on out-of-hunk HTTP 422 responses).
   * Updates a single **Sticky Summary Table** on the PR conversation thread without comment spam.

---

## 🧪 Local Development & Verification

DevGuard enforces a strict zero-dependency test harness using Node's built-in test runner (`node:test`):

```bash
# 1. Typecheck application & CLI
npm run lint

# 2. Build standalone web UI bundle
npm run build

# 3. Run isolated zero-dependency integration test suite (14/14 scenarios)
npm test

# 4. Run DevGuard self-audit locally
npx tsx src/cli.ts src/devguardAnalyzer.ts src/cli.ts src/githubCommenter.ts src/sarifGenerator.ts
```

---

## 📄 License

MIT License — Built for developers shipping fast with AI without sacrificing production security.