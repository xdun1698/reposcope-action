/**
 * Generates a self-contained HTML compliance report and writes it to disk
 * for upload as a GitHub Actions artifact.
 *
 * Maps findings to 5 frameworks: OWASP Top 10 (2021), SOC 2 Type II,
 * PCI-DSS v4.0, EU AI Act Article 12, ISO/IEC 42001.
 */

import * as fs from 'fs'
import * as path from 'path'
import type { VulnFinding, ScanResult } from './scanner'

// ─── Framework mappings ───────────────────────────────────────────────────────

interface FrameworkControl {
  id: string
  name: string
  cweIds?: string[]
  findingTypes?: string[]
}

const OWASP: FrameworkControl[] = [
  { id: 'A01', name: 'Broken Access Control', findingTypes: ['cors_wildcard_header', 'cors_lib_wildcard', 'tls_reject_unauthorized_false'] },
  { id: 'A02', name: 'Cryptographic Failures', findingTypes: ['weak_hash_md5', 'weak_hash_sha1', 'private_key', 'tls_node_env_disable', 'tls_python_verify_false', 'tls_go_insecure_skip_verify'] },
  { id: 'A03', name: 'Injection', findingTypes: ['sql_concat', 'eval_call', 'cmd_os_system', 'cmd_subprocess_shell', 'cmd_node_exec', 'cmd_php_shell', 'cmd_go_exec'] },
  { id: 'A04', name: 'Insecure Design', findingTypes: ['hardcoded_url'] },
  { id: 'A05', name: 'Security Misconfiguration', findingTypes: ['cors_wildcard_header', 'cors_lib_wildcard', 'tls_reject_unauthorized_false', 'tls_node_env_disable'] },
  { id: 'A06', name: 'Vulnerable & Outdated Components', findingTypes: ['vulnerable_dependency'] },
  { id: 'A07', name: 'Identification & Authentication Failures', findingTypes: ['hardcoded_password', 'jwt_token', 'bearer_token'] },
  { id: 'A08', name: 'Software & Data Integrity Failures', findingTypes: ['eval_call'] },
  { id: 'A09', name: 'Security Logging & Monitoring Failures', findingTypes: [] },
  { id: 'A10', name: 'SSRF', findingTypes: [] },
]

const SOC2: FrameworkControl[] = [
  { id: 'CC6.1', name: 'Logical access security (credentials)', findingTypes: ['api_key', 'hardcoded_password', 'hardcoded_secret', 'env_secret', 'db_connection_creds', 'bearer_token', 'jwt_token'] },
  { id: 'CC6.6', name: 'Unauthorized access restriction (cloud keys)', findingTypes: ['aws_key', 'google_api_key', 'stripe_secret_key', 'stripe_test_key', 'github_token', 'slack_token'] },
  { id: 'CC6.7', name: 'Data transmission protection (TLS)', findingTypes: ['tls_reject_unauthorized_false', 'tls_node_env_disable', 'tls_python_verify_false', 'tls_go_insecure_skip_verify'] },
  { id: 'CC7.1', name: 'Vulnerability detection', findingTypes: ['vulnerable_dependency'] },
  { id: 'CC8.1', name: 'Change management (injection risk)', findingTypes: ['sql_concat', 'cmd_os_system', 'cmd_subprocess_shell', 'cmd_node_exec', 'eval_call'] },
]

const PCIDSS: FrameworkControl[] = [
  { id: 'Req 3', name: 'Protect stored cardholder data', findingTypes: ['hardcoded_secret', 'env_secret', 'db_connection_creds'] },
  { id: 'Req 4', name: 'Protect data in transit (TLS)', findingTypes: ['tls_reject_unauthorized_false', 'tls_node_env_disable', 'tls_go_insecure_skip_verify'] },
  { id: 'Req 6', name: 'Develop secure systems', findingTypes: ['sql_concat', 'innerhtml_assign', 'react_dangerous_html', 'angular_bypass_security', 'eval_call', 'cmd_os_system'] },
  { id: 'Req 8', name: 'Identify and authenticate users', findingTypes: ['hardcoded_password', 'api_key', 'stripe_secret_key', 'bearer_token'] },
  { id: 'Req 12', name: 'Information security policies', findingTypes: ['cors_wildcard_header', 'cors_lib_wildcard'] },
]

const EU_AI_ACT: FrameworkControl[] = [
  { id: 'Art.12(1)', name: 'Logging capability for high-risk AI systems', findingTypes: [] },
  { id: 'Art.12(2)', name: 'Traceability of AI input/output', findingTypes: [] },
  { id: 'Art.15', name: 'Accuracy, robustness, cybersecurity', findingTypes: ['eval_call', 'sql_concat', 'cmd_os_system', 'cmd_subprocess_shell'] },
  { id: 'Art.9', name: 'Risk management system (credentials in AI code)', findingTypes: ['api_key', 'hardcoded_secret', 'github_token', 'stripe_secret_key', 'bearer_token'] },
]

const ISO42001: FrameworkControl[] = [
  { id: '6.1.2', name: 'AI risk assessment', findingTypes: ['eval_call', 'sql_concat', 'cmd_os_system'] },
  { id: '8.4', name: 'AI system lifecycle — security controls', findingTypes: ['hardcoded_secret', 'env_secret', 'api_key', 'github_token'] },
  { id: '9.1', name: 'Monitoring, measurement, analysis (code quality)', findingTypes: ['vulnerable_dependency', 'weak_hash_md5', 'weak_hash_sha1'] },
]

const FRAMEWORKS: Record<string, { label: string; controls: FrameworkControl[] }> = {
  owasp: { label: 'OWASP Top 10 (2021)', controls: OWASP },
  soc2: { label: 'SOC 2 Type II', controls: SOC2 },
  'pci-dss': { label: 'PCI-DSS v4.0', controls: PCIDSS },
  'eu-ai-act': { label: 'EU AI Act Article 12', controls: EU_AI_ACT },
  'iso-42001': { label: 'ISO/IEC 42001', controls: ISO42001 },
}

// ─── Report builder ───────────────────────────────────────────────────────────

type ControlStatus = 'PASS' | 'PARTIAL' | 'FAIL' | 'NOT_APPLICABLE'

function getControlStatus(control: FrameworkControl, findings: VulnFinding[]): ControlStatus {
  if (!control.findingTypes?.length) return 'NOT_APPLICABLE'
  const matched = findings.filter((f) => control.findingTypes!.includes(f.type))
  if (!matched.length) return 'PASS'
  const hasHigh = matched.some((f) => f.severity === 'critical' || f.severity === 'high')
  return hasHigh ? 'FAIL' : 'PARTIAL'
}

function statusColor(s: ControlStatus): string {
  switch (s) {
    case 'PASS': return '#22c55e'
    case 'PARTIAL': return '#f59e0b'
    case 'FAIL': return '#ef4444'
    default: return '#94a3b8'
  }
}

export function generateReport(
  result: ScanResult,
  frameworks: string[],
  repoName: string,
  generatedAt: Date = new Date()
): string {
  const { findings, score, grade, counts } = result

  const frameworkSections = frameworks
    .filter((f) => FRAMEWORKS[f])
    .map((fk) => {
      const fw = FRAMEWORKS[fk]
      const controlRows = fw.controls
        .map((ctrl) => {
          const status = getControlStatus(ctrl, findings)
          const matched = findings.filter((f) => ctrl.findingTypes?.includes(f.type))
          return `
            <tr>
              <td style="padding:8px 12px;font-family:monospace;font-size:13px;">${ctrl.id}</td>
              <td style="padding:8px 12px;font-size:13px;">${ctrl.name}</td>
              <td style="padding:8px 12px;">
                <span style="background:${statusColor(status)};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">${status}</span>
              </td>
              <td style="padding:8px 12px;font-size:12px;color:#64748b;">${matched.length > 0 ? `${matched.length} finding${matched.length > 1 ? 's' : ''}` : '—'}</td>
            </tr>`
        })
        .join('')

      const passCount = fw.controls.filter((c) => getControlStatus(c, findings) === 'PASS').length
      const total = fw.controls.length
      const posture = Math.round((passCount / total) * 100)

      return `
        <section style="margin-bottom:40px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
            <h2 style="margin:0;font-size:18px;font-weight:600;">${fw.label}</h2>
            <span style="font-size:15px;font-weight:600;color:${posture >= 80 ? '#22c55e' : posture >= 60 ? '#f59e0b' : '#ef4444'}">Posture: ${posture}%</span>
          </div>
          <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
            <thead>
              <tr style="background:#f8fafc;">
                <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:100px;">Control</th>
                <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;">Name</th>
                <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:120px;">Status</th>
                <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:120px;">Evidence</th>
              </tr>
            </thead>
            <tbody>${controlRows}</tbody>
          </table>
        </section>`
    })
    .join('')

  const findingRows = findings
    .slice(0, 100)
    .map(
      (f) => `
      <tr style="border-top:1px solid #f1f5f9;">
        <td style="padding:8px 12px;">
          <span style="background:${f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : f.severity === 'medium' ? '#f59e0b' : '#94a3b8'};
            color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">${f.severity.toUpperCase()}</span>
        </td>
        <td style="padding:8px 12px;font-family:monospace;font-size:12px;">${escHtml(f.file)}:${f.line}</td>
        <td style="padding:8px 12px;font-size:13px;">${escHtml(f.message)}</td>
        <td style="padding:8px 12px;font-size:12px;color:#64748b;">${f.cwe ?? '—'}</td>
      </tr>`
    )
    .join('')

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>RepoScope Security Report — ${repoName}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; }
    .container { max-width: 960px; margin: 0 auto; padding: 40px 24px; }
    .disclaimer { background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 12px 16px; font-size: 12px; color: #92400e; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;padding-bottom:20px;border-bottom:2px solid #e2e8f0;">
      <div>
        <div style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.1em;color:#6366f1;margin-bottom:4px;">RepoScope · Security Report</div>
        <h1 style="font-size:24px;font-weight:700;">${escHtml(repoName)}</h1>
        <div style="font-size:13px;color:#64748b;margin-top:4px;">Generated ${generatedAt.toUTCString()}</div>
      </div>
      <div style="text-align:center;">
        <div style="font-size:48px;font-weight:800;color:${score >= 80 ? '#22c55e' : score >= 70 ? '#f59e0b' : '#ef4444'};">${score}</div>
        <div style="font-size:14px;font-weight:600;color:#64748b;">/ 100 · Grade ${grade}</div>
      </div>
    </div>

    <!-- Counts -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:40px;">
      ${[
        { label: 'Critical', count: counts.critical, color: '#ef4444' },
        { label: 'High', count: counts.high, color: '#f97316' },
        { label: 'Medium', count: counts.medium, color: '#f59e0b' },
        { label: 'Low', count: counts.low, color: '#94a3b8' },
      ]
        .map(
          (s) =>
            `<div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;text-align:center;">
          <div style="font-size:32px;font-weight:800;color:${s.color};">${s.count}</div>
          <div style="font-size:13px;font-weight:600;color:#64748b;">${s.label}</div>
        </div>`
        )
        .join('')}
    </div>

    <!-- Framework posture -->
    ${frameworkSections}

    <!-- All findings -->
    <section style="margin-bottom:40px;">
      <h2 style="font-size:18px;font-weight:600;margin-bottom:12px;">All Findings (${findings.length}${findings.length > 100 ? ', showing first 100' : ''})</h2>
      <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
        <thead>
          <tr style="background:#f8fafc;">
            <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:100px;">Severity</th>
            <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:260px;">Location</th>
            <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;">Finding</th>
            <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:90px;">CWE</th>
          </tr>
        </thead>
        <tbody>${findingRows}</tbody>
      </table>
    </section>

    <div class="disclaimer">
      <strong>Disclaimer:</strong> This report covers code-level security patterns only. It is a development aid, not a certification or legal compliance tool. Findings represent automated heuristic detections — manual review is required before use in any formal audit. Token costs (if shown elsewhere) are estimates. &nbsp;·&nbsp; <a href="https://reposcope.app">reposcope.app</a>
    </div>
  </div>
</body>
</html>`
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export function writeReport(html: string, reportPath: string): void {
  const dir = path.dirname(reportPath)
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(reportPath, html, 'utf8')
}
