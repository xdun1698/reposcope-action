/**
 * Generates a self-contained HTML security report and writes it to disk
 * for upload as a GitHub Actions artifact.
 *
 * This action reports SECURITY findings + posture only. The full compliance
 * mapping (OWASP / SOC 2 / PCI-DSS / EU AI Act / ISO 42001) and the audit
 * evidence templates are RepoScope Pro features and live only in the
 * RepoScope VS Code extension — not in this open-source action.
 */

import * as fs from 'fs'
import * as path from 'path'
import type { VulnFinding, ScanResult } from './scanner'

// ─── Grouping helpers ─────────────────────────────────────────────────────────

function groupByType(findings: VulnFinding[]): Array<{ type: string; count: number; severity: string }> {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  const map = new Map<string, { type: string; count: number; severity: string }>()
  for (const f of findings) {
    const cur = map.get(f.type)
    if (cur) {
      cur.count++
      if ((rank[f.severity] ?? 9) < (rank[cur.severity] ?? 9)) cur.severity = f.severity
    } else {
      map.set(f.type, { type: f.type, count: 1, severity: f.severity })
    }
  }
  return [...map.values()].sort((a, b) => b.count - a.count)
}

function severityColor(sev: string): string {
  return sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f97316' : sev === 'medium' ? '#f59e0b' : '#94a3b8'
}

// ─── Report builder ───────────────────────────────────────────────────────────

export function generateReport(
  result: ScanResult,
  repoName: string,
  generatedAt: Date = new Date()
): string {
  const { findings, score, grade, counts } = result

  const byType = groupByType(findings)
  const typeRows = byType
    .map(
      (t) => `
      <tr style="border-top:1px solid #f1f5f9;">
        <td style="padding:8px 12px;font-family:monospace;font-size:13px;">${escHtml(t.type)}</td>
        <td style="padding:8px 12px;">
          <span style="background:${severityColor(t.severity)};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">${t.severity.toUpperCase()}</span>
        </td>
        <td style="padding:8px 12px;font-size:13px;text-align:right;">${t.count}</td>
      </tr>`
    )
    .join('')

  const findingRows = findings
    .slice(0, 100)
    .map(
      (f) => `
      <tr style="border-top:1px solid #f1f5f9;">
        <td style="padding:8px 12px;">
          <span style="background:${severityColor(f.severity)};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">${f.severity.toUpperCase()}</span>
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
  <title>RepoScope Security Report — ${escHtml(repoName)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; }
    .container { max-width: 960px; margin: 0 auto; padding: 40px 24px; }
    .cta { background: #eef2ff; border: 1px solid #c7d2fe; border-radius: 8px; padding: 20px 24px; margin: 32px 0; }
    .cta a { color: #4f46e5; font-weight: 600; text-decoration: none; }
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
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px;">
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

    <!-- Findings by type -->
    <section style="margin-bottom:32px;">
      <h2 style="font-size:18px;font-weight:600;margin-bottom:12px;">Findings by Type</h2>
      <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;">
        <thead>
          <tr style="background:#f8fafc;">
            <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;">Detector</th>
            <th style="text-align:left;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:120px;">Severity</th>
            <th style="text-align:right;padding:10px 12px;font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;width:80px;">Count</th>
          </tr>
        </thead>
        <tbody>${typeRows || '<tr><td colspan="3" style="padding:16px;text-align:center;color:#22c55e;">No security findings — clean scan.</td></tr>'}</tbody>
      </table>
    </section>

    <!-- Compliance CTA (Pro) -->
    <div class="cta">
      <div style="font-size:15px;font-weight:600;margin-bottom:6px;">Need audit-ready compliance evidence?</div>
      <div style="font-size:13px;color:#475569;line-height:1.5;">
        RepoScope Pro maps every finding to <strong>OWASP Top 10, SOC 2 Type II, PCI-DSS v4.0, EU AI Act Article 12, and ISO/IEC 42001</strong>,
        with per-control PASS/PARTIAL/FAIL posture and one-click audit document generation (Control Matrix, Attestation Memo, Gap Plan, Auditor Evidence Response).
        <br/><br/>
        <a href="https://marketplace.visualstudio.com/items?itemName=nxgentech.reposcope-ai">Install RepoScope for VS Code, Cursor &amp; Devin Desktop →</a>
      </div>
    </div>

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
        <tbody>${findingRows || '<tr><td colspan="4" style="padding:16px;text-align:center;color:#22c55e;">No findings.</td></tr>'}</tbody>
      </table>
    </section>

    <div class="disclaimer">
      <strong>Disclaimer:</strong> This report covers code-level security patterns only. It is a development aid, not a certification or legal compliance tool. Findings are automated heuristic detections — manual review is required. &nbsp;·&nbsp; <a href="https://reposcope.app">reposcope.app</a>
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
