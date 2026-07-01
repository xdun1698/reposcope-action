/**
 * Self-contained security scanner for reposcope-action.
 *
 * Mirrors the detection rules from the RepoScope VS Code extension
 * (src/engine/vulnScanRegex.ts + src/engine/vulnRules.ts) so the action
 * produces identical findings to the in-editor experience.
 */

import * as fs from 'fs'
import * as path from 'path'

// ─── Types ──────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Confidence = 'high' | 'medium' | 'low'

export interface VulnFinding {
  type: string
  severity: Severity
  confidence: Confidence
  line: number
  file: string
  message: string
  snippet: string
  fix: string
  cwe?: string
}

export interface ScanResult {
  findings: VulnFinding[]
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  counts: { critical: number; high: number; medium: number; low: number }
  filesScanned: number
  filesSkipped: number
}

// ─── Core patterns (ported from vulnScanRegex.ts) ───────────────────────────

const COMMENT_RE = /^\s*(\/\/|#|\/\*|\*|<!--)/
const ENV_FALLBACK_RE =
  /(process\.env\.\w+|Environment\.GetEnvironmentVariable|os\.getenv|os\.environ|getenv\s*\(|std::getenv|System\.getenv|ENV\[|ENV\.fetch)/
const PLACEHOLDER_RE =
  /(your[_-]?|example|placeholder|change[_-]?me|dummy|sample|redacted|xxxx|<[^>]+>|\*{3,}|todo|replace[_-]?this|insert[_-]?|foobar|abc123|123456)/i

const BASE_PATTERNS: Array<{
  id: string
  pattern: RegExp
  severity: Severity
  confidence: Confidence
  message: string
  fix: string
  cwe: string
  skipIfEnvFallback?: boolean
  placeholderAware?: boolean
}> = [
  {
    id: 'api_key',
    pattern: /\b(api[_-]?key|api[_-]?secret)\s*=\s*["']([a-zA-Z0-9_-]{8,})["']/i,
    severity: 'high',
    confidence: 'high',
    message: 'Hardcoded API key or secret',
    fix: "Move to env var: process.env.MY_API_KEY or os.getenv('MY_API_KEY')",
    cwe: 'CWE-798',
    placeholderAware: true,
  },
  {
    id: 'aws_key',
    pattern: /(AKIA|ASIA)[A-Z0-9]{16}/i,
    severity: 'critical',
    confidence: 'high',
    message: 'AWS access key committed in source',
    fix: 'Use IAM roles or AWS Secrets Manager — never hardcode AWS keys',
    cwe: 'CWE-798',
  },
  {
    id: 'hardcoded_password',
    pattern: /\b(password|passwd|pwd)\b\s*=\s*["']([^"']{4,})["']/i,
    severity: 'high',
    confidence: 'medium',
    message: 'Hardcoded password in source',
    fix: 'Use env vars or a secrets manager',
    cwe: 'CWE-259',
    placeholderAware: true,
  },
  {
    id: 'private_key',
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
    confidence: 'high',
    message: 'Private key committed in source',
    fix: 'Remove immediately — rotate this key and store it in a secrets manager',
    cwe: 'CWE-798',
  },
  {
    id: 'hardcoded_url',
    pattern: /https?:\/\/(localhost|127\.0\.0\.1)/i,
    severity: 'low',
    confidence: 'low',
    message: 'Hardcoded localhost URL',
    fix: 'Use config file or relative paths',
    cwe: 'CWE-547',
    skipIfEnvFallback: true,
  },
  {
    id: 'hardcoded_secret',
    pattern: /\b(api_key|secret|password)\s*=\s*['"][^'"]{8,}['"]/i,
    severity: 'high',
    confidence: 'medium',
    message: 'Possible hardcoded secret in source',
    fix: 'Move real credentials to environment variables or a secrets manager',
    cwe: 'CWE-798',
    placeholderAware: true,
  },
  {
    id: 'eval_call',
    pattern: /\beval\s*\(\s*(?!\s*\))/,
    severity: 'critical',
    confidence: 'high',
    message: 'eval() called with an expression — arbitrary code execution risk',
    fix: 'Remove eval(); use JSON.parse, a vetted parser, or a safe alternative',
    cwe: 'CWE-95',
  },
  {
    id: 'sql_concat',
    pattern: /(execute|query|cursor)\s*\(\s*['"][^'"]*%\s*/i,
    severity: 'high',
    confidence: 'medium',
    message: 'SQL built with string formatting — injection risk',
    fix: 'Use parameterized queries or an ORM; never paste user input into raw SQL',
    cwe: 'CWE-89',
  },
  {
    id: 'innerhtml_assign',
    pattern: /\.innerHTML\s*=/i,
    severity: 'high',
    confidence: 'medium',
    message: 'DOM innerHTML assigned directly — XSS risk',
    fix: "Prefer textContent, a sanitizer, or your framework's safe HTML APIs",
    cwe: 'CWE-79',
  },
  // Extended rules (from vulnRules.ts)
  {
    id: 'jwt_token',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}/,
    severity: 'high',
    confidence: 'medium',
    message: 'Hardcoded JWT in source',
    fix: 'Never commit signed tokens; issue them at runtime and store secrets in a vault',
    cwe: 'CWE-798',
  },
  {
    id: 'github_token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}/,
    severity: 'critical',
    confidence: 'high',
    message: 'GitHub personal/OAuth token committed in source',
    fix: 'Revoke the token immediately and move it to an environment variable or secret store',
    cwe: 'CWE-798',
  },
  {
    id: 'slack_token',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
    severity: 'critical',
    confidence: 'high',
    message: 'Slack token committed in source',
    fix: 'Revoke the Slack token and load it from configuration at runtime',
    cwe: 'CWE-798',
  },
  {
    id: 'google_api_key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: 'high',
    confidence: 'high',
    message: 'Google API key committed in source',
    fix: 'Restrict and rotate the key; load it from an environment variable',
    cwe: 'CWE-798',
  },
  {
    id: 'stripe_secret_key',
    pattern: /\b(sk|rk)_live_[0-9a-zA-Z]{16,}/,
    severity: 'critical',
    confidence: 'high',
    message: 'Stripe LIVE secret key committed in source',
    fix: 'Roll the key in the Stripe dashboard now and read it from a secret store',
    cwe: 'CWE-798',
    placeholderAware: true,
  },
  {
    id: 'stripe_test_key',
    pattern: /\b(sk|rk)_test_[0-9a-zA-Z]{16,}/,
    severity: 'high',
    confidence: 'medium',
    message: 'Stripe test secret key committed in source',
    fix: 'Even test keys should come from configuration, not source',
    cwe: 'CWE-798',
    placeholderAware: true,
  },
  {
    id: 'slack_webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/,
    severity: 'high',
    confidence: 'high',
    message: 'Slack incoming webhook URL committed in source',
    fix: 'Treat webhook URLs as secrets; load from configuration',
    cwe: 'CWE-798',
  },
  {
    id: 'bearer_token',
    pattern: /\bauthorization\s*[:=]\s*["']?\s*bearer\s+[A-Za-z0-9._-]{12,}/i,
    severity: 'medium',
    confidence: 'medium',
    message: 'Hardcoded Bearer authorization token',
    fix: 'Inject auth tokens at runtime; never hardcode them',
    cwe: 'CWE-798',
    placeholderAware: true,
  },
  {
    id: 'db_connection_creds',
    pattern:
      /\b(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|amqps?):\/\/[^\s:'"@/]+:[^\s'"@/]+@/i,
    severity: 'high',
    confidence: 'high',
    message: 'Database connection string with embedded username/password',
    fix: 'Move credentials out of the URI; use env vars or a secrets manager',
    cwe: 'CWE-798',
    placeholderAware: true,
  },
  {
    id: 'cmd_os_system',
    pattern: /\bos\.system\s*\(/,
    severity: 'high',
    confidence: 'medium',
    message: 'os.system() shells out — command injection risk with dynamic input',
    fix: 'Use subprocess.run([...], shell=False) with an argument list',
    cwe: 'CWE-78',
  },
  {
    id: 'cmd_subprocess_shell',
    pattern: /\bsubprocess\.\w+\([^)]*shell\s*=\s*True/,
    severity: 'high',
    confidence: 'high',
    message: 'subprocess called with shell=True — command injection risk',
    fix: "Pass an argument list and keep shell=False; never interpolate user input",
    cwe: 'CWE-78',
  },
  {
    id: 'cmd_node_exec',
    pattern: /\bexecSync\s*\(|\bexec\s*\(\s*[`'"][^`'"]*(\$\{|"\s*\+|'\s*\+|`\s*\+)/,
    severity: 'high',
    confidence: 'medium',
    message: 'child_process exec with a shell string — command injection risk',
    fix: 'Use execFile/spawn with an argument array; do not build shell strings',
    cwe: 'CWE-78',
  },
  {
    id: 'react_dangerous_html',
    pattern: /dangerouslySetInnerHTML/,
    severity: 'high',
    confidence: 'medium',
    message: 'React dangerouslySetInnerHTML — XSS risk if the value is user-influenced',
    fix: 'Render text, or sanitize HTML (e.g. DOMPurify) before injecting it',
    cwe: 'CWE-79',
  },
  {
    id: 'angular_bypass_security',
    pattern: /bypassSecurityTrust\w*\s*\(/,
    severity: 'high',
    confidence: 'high',
    message: 'Angular bypassSecurityTrust* disables built-in sanitization',
    fix: 'Avoid bypassing the sanitizer; sanitize untrusted values instead',
    cwe: 'CWE-79',
  },
  {
    id: 'cors_wildcard_header',
    pattern: /access-control-allow-origin["']?\s*[:,]\s*["']\*["']/i,
    severity: 'medium',
    confidence: 'medium',
    message: 'CORS Access-Control-Allow-Origin set to "*"',
    fix: 'Restrict to an explicit allow-list of trusted origins',
    cwe: 'CWE-942',
  },
  {
    id: 'cors_lib_wildcard',
    pattern: /\bcors\s*\(\s*\{[^}]*origin\s*:\s*(["']\*["']|true)/i,
    severity: 'medium',
    confidence: 'medium',
    message: 'CORS middleware allows any origin',
    fix: 'Set origin to an explicit list; avoid "*" / true with credentials',
    cwe: 'CWE-942',
  },
  {
    id: 'tls_reject_unauthorized_false',
    pattern: /rejectUnauthorized\s*:\s*false/i,
    severity: 'high',
    confidence: 'high',
    message: 'TLS certificate validation disabled (rejectUnauthorized: false)',
    fix: 'Keep certificate validation on; install proper CA certs instead',
    cwe: 'CWE-295',
  },
  {
    id: 'tls_node_env_disable',
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0/,
    severity: 'high',
    confidence: 'high',
    message: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables all TLS verification',
    fix: 'Never disable global TLS verification; fix the certificate chain',
    cwe: 'CWE-295',
  },
  {
    id: 'tls_python_verify_false',
    pattern: /\bverify\s*=\s*False\b/,
    severity: 'medium',
    confidence: 'medium',
    message: 'TLS verification disabled (verify=False)',
    fix: 'Leave verify=True; provide a CA bundle if needed',
    cwe: 'CWE-295',
  },
  {
    id: 'tls_go_insecure_skip_verify',
    pattern: /InsecureSkipVerify\s*:\s*true/,
    severity: 'high',
    confidence: 'high',
    message: 'Go TLS InsecureSkipVerify: true disables certificate validation',
    fix: 'Remove InsecureSkipVerify; validate the server certificate',
    cwe: 'CWE-295',
  },
  {
    id: 'weak_hash_md5',
    pattern:
      /hashlib\.md5\b|createHash\(\s*["']md5["']\)|MessageDigest\.getInstance\(\s*["']MD5["']\)|\bMD5CryptoServiceProvider\b/,
    severity: 'medium',
    confidence: 'low',
    message: 'MD5 is cryptographically broken for security use',
    fix: 'Use SHA-256+ (hashing) or bcrypt/argon2/scrypt (passwords)',
    cwe: 'CWE-327',
  },
  {
    id: 'weak_hash_sha1',
    pattern:
      /hashlib\.sha1\b|createHash\(\s*["']sha1["']\)|MessageDigest\.getInstance\(\s*["']SHA-?1["']\)/,
    severity: 'low',
    confidence: 'low',
    message: 'SHA-1 is deprecated for security use',
    fix: 'Use SHA-256 or stronger',
    cwe: 'CWE-327',
  },
]

// ─── Scoring ─────────────────────────────────────────────────────────────────

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 28,
  high: 14,
  medium: 5,
  low: 1.5,
}

const CONFIDENCE_FACTOR: Record<Confidence, number> = {
  high: 1,
  medium: 0.65,
  low: 0.35,
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
const CONFIDENCE_RANK: Record<Confidence, number> = { high: 0, medium: 1, low: 2 }

function computeScore(findings: VulnFinding[]): { score: number; grade: 'A' | 'B' | 'C' | 'D' | 'F' } {
  let penalty = 0
  for (const f of findings) {
    penalty += (SEVERITY_PENALTY[f.severity] ?? 1) * (CONFIDENCE_FACTOR[f.confidence] ?? 0.65)
  }
  const score = Math.max(0, Math.round(100 - penalty))
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F'
  return { score, grade }
}

function severityCounts(findings: VulnFinding[]) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings) c[f.severity]++
  return c
}

/** Collapse multiple findings on the same file:line to the single most severe. */
function dedupe(findings: VulnFinding[]): VulnFinding[] {
  const best = new Map<string, VulnFinding>()
  for (const f of findings) {
    const key = `${f.file}\x00${f.line}`
    const cur = best.get(key)
    if (!cur) { best.set(key, f); continue }
    const fS = SEVERITY_RANK[f.severity] ?? 9
    const cS = SEVERITY_RANK[cur.severity] ?? 9
    if (fS < cS || (fS === cS && (CONFIDENCE_RANK[f.confidence] ?? 1) < (CONFIDENCE_RANK[cur.confidence ?? 'medium'] ?? 1))) {
      best.set(key, f)
    }
  }
  return [...best.values()]
}

// ─── File filtering ───────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next',
  '__pycache__', '.venv', 'venv', 'env', 'coverage', '.nyc_output', '.reposcope',
])

const SUPPORTED_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.go', '.java', '.cs', '.rs', '.cpp', '.c', '.h',
  '.sh', '.bash', '.zsh', '.env', '.yaml', '.yml', '.toml', '.json',
  '.html', '.vue', '.svelte',
])

const INLINE_SUPPRESS_RE = /reposcope[-:]?\s*ignore/i

function isEnvFile(filename: string): boolean {
  const base = path.basename(filename)
  if (/\.(example|sample|template|dist)$/i.test(base)) return false
  return /^\.env(\.[A-Za-z0-9_-]+)?$/.test(base)
}

function isManifestFile(filename: string): boolean {
  const base = path.basename(filename).toLowerCase()
  return base === 'package.json' || base === 'requirements.txt' || base === 'requirements.in'
}

// ─── Per-file scanner ─────────────────────────────────────────────────────────

function scanFileLines(lines: string[], relFile: string): VulnFinding[] {
  const findings: VulnFinding[] = []

  for (const rule of BASE_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      if (COMMENT_RE.test(line)) continue
      if (INLINE_SUPPRESS_RE.test(line)) continue
      if (i > 0 && INLINE_SUPPRESS_RE.test(lines[i - 1])) continue
      if (rule.skipIfEnvFallback && ENV_FALLBACK_RE.test(line)) continue

      if (!rule.pattern.test(line)) continue

      let confidence = rule.confidence
      if (rule.placeholderAware && PLACEHOLDER_RE.test(line)) confidence = 'low'

      findings.push({
        type: rule.id,
        severity: rule.severity,
        confidence,
        line: i + 1,
        file: relFile,
        message: rule.message,
        snippet: line.trim().slice(0, 120),
        fix: rule.fix,
        cwe: rule.cwe,
      })
    }
  }

  return findings
}

function scanEnvFile(lines: string[], relFile: string): VulnFinding[] {
  const SECRET_KEY_RE =
    /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|PRIVATE|API|AUTH|ACCESS|DSN|DATABASE_URL|CONN)/i
  const VALUE_REF_RE = /^\$\{?[A-Za-z_]/

  const findings: VulnFinding[] = []
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq <= 0) continue
    const key = line.slice(0, eq).replace(/^export\s+/i, '').trim()
    let value = line.slice(eq + 1).trim()
    const quoted = /^["'].*["']$/.test(value)
    if (quoted) value = value.slice(1, -1)
    else value = value.split(/\s+#/)[0]!.trim()
    if (!value || VALUE_REF_RE.test(value) || !SECRET_KEY_RE.test(key) || value.length < 6) continue
    const placeholder = PLACEHOLDER_RE.test(value) || /^(true|false|0|1|localhost|null|none)$/i.test(value)
    findings.push({
      type: 'env_secret',
      severity: 'high',
      confidence: placeholder ? 'low' : 'medium',
      line: i + 1,
      file: relFile,
      message: `Secret-like value committed in env file (${key})`,
      snippet: `${key}=********`,
      fix: 'Keep secrets out of committed env files; use .env.example with blanks.',
      cwe: 'CWE-798',
    })
  }
  return findings
}

// ─── Workspace walker ─────────────────────────────────────────────────────────

function walkDir(dir: string, root: string, results: string[]): void {
  let entries: fs.Dirent[]
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.env') {
      // skip hidden dirs/files except .env files
      if (entry.isDirectory()) continue
      if (!isEnvFile(entry.name)) continue
    }
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue
      walkDir(path.join(dir, entry.name), root, results)
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase()
      const base = entry.name.toLowerCase()
      if (SUPPORTED_EXTENSIONS.has(ext) || isEnvFile(entry.name) || base === 'package.json' ||
          base === 'requirements.txt' || base === 'requirements.in') {
        results.push(path.join(dir, entry.name))
      }
    }
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function scanWorkspace(workspacePath: string): Promise<ScanResult> {
  const allFiles: string[] = []
  walkDir(workspacePath, workspacePath, allFiles)

  const allFindings: VulnFinding[] = []
  let filesScanned = 0
  let filesSkipped = 0

  for (const absPath of allFiles) {
    const relFile = path.relative(workspacePath, absPath).split(path.sep).join('/')

    let text: string
    try {
      text = fs.readFileSync(absPath, 'utf8')
      // Skip binary-looking files
      if (text.includes('\x00')) { filesSkipped++; continue }
    } catch {
      filesSkipped++
      continue
    }

    filesScanned++
    const lines = text.split(/\r?\n/)

    if (isEnvFile(absPath)) {
      allFindings.push(...scanEnvFile(lines, relFile))
    } else if (isManifestFile(absPath)) {
      // For now, scan manifest files with the standard patterns too
      allFindings.push(...scanFileLines(lines, relFile))
    } else {
      allFindings.push(...scanFileLines(lines, relFile))
    }
  }

  const findings = dedupe(allFindings)
  const { score, grade } = computeScore(findings)
  const counts = severityCounts(findings)

  return { findings, score, grade, counts, filesScanned, filesSkipped }
}
