/**
 * Posts PR review comments (one per finding) and creates a GitHub Check run
 * with the overall security score and summary.
 */

import * as core from '@actions/core'
import * as github from '@actions/github'
import type { VulnFinding, ScanResult } from './scanner'

type Octokit = ReturnType<typeof github.getOctokit>

// ─── Severity display ─────────────────────────────────────────────────────────

const SEVERITY_EMOJI: Record<string, string> = {
  critical: '[CRITICAL]',
  high: '[HIGH]',
  medium: '[MEDIUM]',
  low: '[LOW]',
}

// ─── PR review comments ───────────────────────────────────────────────────────

/**
 * Builds the markdown body for a single PR review comment.
 * Kept concise so it fits cleanly in the PR diff view.
 */
function buildCommentBody(f: VulnFinding): string {
  const badge = SEVERITY_EMOJI[f.severity] ?? `[${f.severity.toUpperCase()}]`
  const cwe = f.cwe ? ` · ${f.cwe}` : ''
  return [
    `**RepoScope ${badge}${cwe}**`,
    '',
    f.message,
    '',
    `**Fix:** ${f.fix}`,
    '',
    f.snippet ? `\`\`\`\n${f.snippet}\n\`\`\`` : '',
    '',
    `_Confidence: ${f.confidence} · [Install RepoScope](https://marketplace.visualstudio.com/items?itemName=nxgentech.reposcope-ai) for in-editor findings_`,
  ]
    .filter((l) => l !== undefined)
    .join('\n')
}

/**
 * Posts individual PR review comments for each finding.
 * Skips gracefully if the file/line isn't part of the diff.
 */
export async function postPrReviewComments(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number,
  commitSha: string,
  findings: VulnFinding[]
): Promise<{ posted: number; skipped: number }> {
  let posted = 0
  let skipped = 0

  // Fetch the PR diff to know which file+line positions are reviewable
  let reviewablePositions: Map<string, Set<number>>
  try {
    reviewablePositions = await fetchDiffPositions(octokit, owner, repo, pullNumber)
  } catch (err) {
    core.warning(`Could not fetch PR diff for comment placement: ${err}. Skipping inline comments.`)
    return { posted: 0, skipped: findings.length }
  }

  for (const f of findings) {
    const filePositions = reviewablePositions.get(f.file)
    if (!filePositions?.has(f.line)) {
      // Line not in this PR's diff — skip (GitHub would reject it)
      skipped++
      continue
    }
    try {
      await octokit.rest.pulls.createReviewComment({
        owner,
        repo,
        pull_number: pullNumber,
        commit_id: commitSha,
        path: f.file,
        line: f.line,
        side: 'RIGHT',
        body: buildCommentBody(f),
      })
      posted++
    } catch (err) {
      core.debug(`Skipped comment on ${f.file}:${f.line} — ${err}`)
      skipped++
    }
  }

  return { posted, skipped }
}

/**
 * Posts a single summary review comment on the PR with the overall score,
 * counts by severity, and a link to the uploaded artifact.
 */
export async function postSummaryComment(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number,
  result: ScanResult,
  threshold: number,
  artifactUrl?: string
): Promise<void> {
  const { score, grade, counts, findings } = result
  const passed = score >= threshold

  const scoreEmoji = passed ? 'PASS' : 'FAIL'
  const lines = [
    `## RepoScope Security Scan — ${scoreEmoji}`,
    '',
    `**Score: ${score}/100 (${grade})** · ${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low`,
    '',
    `${findings.length} deduplicated findings across ${result.filesScanned} files scanned.`,
  ]

  if (!passed) {
    lines.push('', `> Score ${score} is below the configured threshold of ${threshold}. This check will fail.`)
  }

  if (counts.critical > 0 || counts.high > 0) {
    lines.push('', '**Top findings by severity:**', '')
    const top = findings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .slice(0, 5)
    for (const f of top) {
      const badge = SEVERITY_EMOJI[f.severity] ?? ''
      lines.push(`- ${badge} \`${f.file}:${f.line}\` — ${f.message}`)
    }
    if (findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length > 5) {
      lines.push(`- _…and ${findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length - 5} more_`)
    }
  }

  if (artifactUrl) {
    lines.push('', `[View full compliance report](${artifactUrl})`)
  }

  lines.push('', '_[Install RepoScope](https://marketplace.visualstudio.com/items?itemName=nxgentech.reposcope-ai) to see findings live in your editor._')

  await octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: pullNumber,
    body: lines.join('\n'),
  })
}

// ─── GitHub Check run ─────────────────────────────────────────────────────────

export async function createCheckRun(
  octokit: Octokit,
  owner: string,
  repo: string,
  headSha: string,
  result: ScanResult,
  threshold: number,
  failOnSeverity: string
): Promise<void> {
  const { score, grade, counts, findings } = result
  const thresholdFailed = threshold > 0 && score < threshold
  const severityFailed = hasSeverityViolation(counts, failOnSeverity)
  const passed = !thresholdFailed && !severityFailed

  const title = passed
    ? `RepoScope — PASS · Score ${score}/100 (${grade})`
    : `RepoScope — FAIL · Score ${score}/100 · ${getFailReason(thresholdFailed, severityFailed, threshold, failOnSeverity)}`

  const summary = [
    `**${counts.critical}** critical · **${counts.high}** high · **${counts.medium}** medium · **${counts.low}** low`,
    ``,
    `${findings.length} findings in ${result.filesScanned} files scanned.`,
  ].join('\n')

  const annotations = findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 50) // GitHub limits to 50 annotations per request
    .map((f) => ({
      path: f.file,
      start_line: f.line,
      end_line: f.line,
      annotation_level: (f.severity === 'critical' ? 'failure' : 'warning') as 'failure' | 'warning' | 'notice',
      message: `${f.message} (${f.cwe ?? f.type})`,
      title: `RepoScope: ${f.type}`,
      raw_details: `Fix: ${f.fix}\nSnippet: ${f.snippet}`,
    }))

  try {
    await octokit.rest.checks.create({
      owner,
      repo,
      name: 'RepoScope Security',
      head_sha: headSha,
      status: 'completed',
      conclusion: passed ? 'success' : 'failure',
      completed_at: new Date().toISOString(),
      output: {
        title,
        summary,
        annotations,
      },
    })
  } catch (err) {
    core.warning(`Could not create Check run: ${err}`)
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hasSeverityViolation(
  counts: { critical: number; high: number; medium: number; low: number },
  failOn: string
): boolean {
  switch (failOn) {
    case 'critical': return counts.critical > 0
    case 'high': return counts.critical > 0 || counts.high > 0
    case 'medium': return counts.critical > 0 || counts.high > 0 || counts.medium > 0
    case 'low': return Object.values(counts).some((n) => n > 0)
    default: return false
  }
}

function getFailReason(
  thresholdFailed: boolean,
  severityFailed: boolean,
  threshold: number,
  failOn: string
): string {
  if (thresholdFailed && severityFailed) return `score below ${threshold} and ${failOn}+ finding`
  if (thresholdFailed) return `score below ${threshold}`
  return `${failOn}+ severity finding`
}

/**
 * Fetches the PR diff and extracts which lines of which files are reviewable
 * (i.e., are part of this PR's changes). GitHub only accepts comments on lines
 * that appear in the diff.
 */
async function fetchDiffPositions(
  octokit: Octokit,
  owner: string,
  repo: string,
  pullNumber: number
): Promise<Map<string, Set<number>>> {
  const files = await octokit.paginate(octokit.rest.pulls.listFiles, {
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  })

  const map = new Map<string, Set<number>>()
  for (const file of files) {
    if (!file.patch) continue
    const lines = new Set<number>()
    let currentLine = 0
    for (const part of file.patch.split('\n')) {
      const header = part.match(/^@@ -\d+(?:,\d+)? \+(\d+)/)
      if (header) {
        currentLine = parseInt(header[1], 10) - 1
        continue
      }
      if (part.startsWith('+')) {
        currentLine++
        lines.add(currentLine)
      } else if (!part.startsWith('-')) {
        currentLine++
      }
    }
    map.set(file.filename, lines)
  }
  return map
}
