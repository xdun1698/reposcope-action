/**
 * reposcope-action — entrypoint
 *
 * Flow:
 *  1. Read inputs
 *  2. Scan the workspace
 *  3. Generate + write the HTML report
 *  4. If on a PR, post inline review comments + summary
 *  5. Create a GitHub Check run
 *  6. Set outputs
 *  7. Fail if threshold or severity gate is not met
 */

import * as core from '@actions/core'
import * as github from '@actions/github'
import { DefaultArtifactClient } from '@actions/artifact'
import * as path from 'path'

import { scanWorkspace } from './scanner'
import { postPrReviewComments, postSummaryComment, createCheckRun } from './commenter'
import { generateReport, writeReport } from './reporter'

async function run(): Promise<void> {
  try {
    // ── Inputs ────────────────────────────────────────────────────────────────

    const token = core.getInput('token', { required: true })
    const workspacePath = core.getInput('workspace-path') || process.env.GITHUB_WORKSPACE || process.cwd()
    const failOn = core.getInput('fail-on') || 'high'
    const threshold = parseInt(core.getInput('threshold') || '0', 10)
    const commentOnPr = core.getInput('comment-on-pr') !== 'false'
    const reportRelPath = core.getInput('report-path') || '.reposcope/report.html'
    const reportAbsPath = path.resolve(workspacePath, reportRelPath)

    const octokit = github.getOctokit(token)
    const ctx = github.context
    const { owner, repo } = ctx.repo

    core.startGroup('RepoScope — inputs')
    core.info(`Workspace: ${workspacePath}`)
    core.info(`Fail on severity: ${failOn}`)
    core.info(`Score threshold: ${threshold}`)
    core.info(`Comment on PR: ${commentOnPr}`)
    core.endGroup()

    // ── Scan ─────────────────────────────────────────────────────────────────

    core.startGroup('RepoScope — scanning workspace')
    const result = await scanWorkspace(workspacePath)
    core.info(`Scanned ${result.filesScanned} files (${result.filesSkipped} skipped)`)
    core.info(`Findings: ${result.findings.length} total — critical: ${result.counts.critical}, high: ${result.counts.high}, medium: ${result.counts.medium}, low: ${result.counts.low}`)
    core.info(`Score: ${result.score}/100 (${result.grade})`)
    core.endGroup()

    // ── Report ────────────────────────────────────────────────────────────────

    core.startGroup('RepoScope — generating report')
    const repoName = `${owner}/${repo}`
    const html = generateReport(result, repoName)
    writeReport(html, reportAbsPath)
    core.info(`Report written to ${reportAbsPath}`)
    core.endGroup()

    // Upload artifact
    let artifactUrl: string | undefined
    try {
      const artifactClient = new DefaultArtifactClient()
      await artifactClient.uploadArtifact('reposcope-report', [reportAbsPath], workspacePath)
      core.info('Compliance report uploaded as GitHub Actions artifact: reposcope-report')
    } catch (err) {
      core.warning(`Artifact upload failed: ${err}`)
    }

    // ── PR comments ───────────────────────────────────────────────────────────

    const isPr = ctx.eventName === 'pull_request' || ctx.eventName === 'pull_request_target'
    if (isPr && commentOnPr) {
      const pullNumber = ctx.payload.pull_request?.number
      const headSha = ctx.payload.pull_request?.head?.sha || ctx.sha

      if (pullNumber) {
        core.startGroup('RepoScope — posting PR review comments')
        const { posted, skipped } = await postPrReviewComments(
          octokit, owner, repo, pullNumber, headSha, result.findings
        )
        core.info(`Inline comments: ${posted} posted, ${skipped} skipped (not in diff)`)

        await postSummaryComment(octokit, owner, repo, pullNumber, result, threshold, artifactUrl)
        core.info('Summary comment posted')
        core.endGroup()

        core.startGroup('RepoScope — creating Check run')
        await createCheckRun(octokit, owner, repo, headSha, result, threshold, failOn)
        core.endGroup()
      }
    } else {
      // On push events, still create a Check run against the commit SHA
      const headSha = ctx.sha
      if (headSha) {
        core.startGroup('RepoScope — creating Check run')
        await createCheckRun(octokit, owner, repo, headSha, result, threshold, failOn)
        core.endGroup()
      }
    }

    // ── Outputs ───────────────────────────────────────────────────────────────

    core.setOutput('security-score', String(result.score))
    core.setOutput('findings-count', String(result.findings.length))
    core.setOutput('critical-count', String(result.counts.critical))
    core.setOutput('high-count', String(result.counts.high))
    core.setOutput('report-path', reportAbsPath)

    // ── Pass / fail gate ──────────────────────────────────────────────────────

    const thresholdFailed = threshold > 0 && result.score < threshold
    const severityFailed = hasSeverityViolation(result.counts, failOn)

    if (thresholdFailed) {
      core.setFailed(
        `RepoScope: Security score ${result.score} is below the configured threshold of ${threshold}.`
      )
      return
    }

    if (severityFailed) {
      const worst = result.findings
        .filter((f) => meetsOrExceedsSeverity(f.severity, failOn))
        .slice(0, 3)
        .map((f) => `${f.file}:${f.line} (${f.type})`)
        .join(', ')
      core.setFailed(
        `RepoScope: Found ${failOn}+ severity issues. First affected: ${worst}. ` +
        `Set fail-on: none to allow all severities.`
      )
      return
    }

    core.info(`RepoScope: PASS — score ${result.score}/100, no ${failOn}+ severity violations.`)
  } catch (err) {
    core.setFailed(`RepoScope action failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

function meetsOrExceedsSeverity(severity: string, failOn: string): boolean {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  return (rank[severity] ?? 9) <= (rank[failOn] ?? 9)
}

run()
