/**
 * AI-code provenance for reposcope-action.
 *
 * Ported from the RepoScope extension's FREE-tier Code Provenance Engine
 * (src/provenance/aiDetector.ts). Uses only local, deterministic signals —
 * no network, no LLM, no proprietary model:
 *   1. Repo-level AI tooling configured (.cursorrules, .cursor/rules, copilot)
 *   2. Per-file git history: latest commit that touched the file references a
 *      known AI coding tool, or is marked as generated.
 *
 * This is the same free capability the extension ships as "Provenance"
 * (Security · Repo Map · Provenance). It exposes NO paid/Pro functionality:
 * the compliance framework mappings and audit-document templates stay
 * extension-only and are never included here.
 */

import * as fs from 'fs'
import * as path from 'path'
import { execFileSync } from 'child_process'

export interface FileProvenance {
  file: string
  confidence: 'high' | 'medium'
  signals: string[]
}

export interface ProvenanceResult {
  /** Files whose git history attributes them to an AI coding tool. */
  aiAttributed: FileProvenance[]
  aiAttributedCount: number
  filesChecked: number
  /** Repo-level AI tooling detected (context, not per-file attribution). */
  repoSignals: string[]
  /** True when git history was readable; false on shallow/uninitialised repos. */
  gitAvailable: boolean
}

/** Commit-message tokens that strongly imply AI authorship. */
const AI_TOOL_PATTERN = /copilot|cursor|aider|claude|chatgpt|gpt-|codeium|windsurf|devin/i
/** Conventional-commit subjects that flag generated changes. */
const GENERATED_COMMIT_PATTERN = /^(feat|fix|refactor|chore)(\(.+\))?:.*\bgenerated\b/i

/** Walks up from a file/dir to the nearest `.git` root, else returns the start dir. */
export function findWorkspaceRoot(startPath: string): string {
  let dir = fs.existsSync(startPath) && fs.statSync(startPath).isDirectory()
    ? startPath
    : path.dirname(startPath)
  for (let i = 0; i < 64; i++) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return dir
}

/** Repo-level signals derived from AI tooling configured in the workspace. */
export function repoToolingSignals(root: string): string[] {
  const signals: string[] = []

  if (fs.existsSync(path.join(root, '.cursorrules'))) {
    signals.push('AI tooling configured (.cursorrules)')
  }

  const rulesDir = path.join(root, '.cursor', 'rules')
  try {
    if (fs.existsSync(rulesDir) && fs.readdirSync(rulesDir).some((f) => f.endsWith('.mdc'))) {
      signals.push('AI tooling configured (.cursor/rules)')
    }
  } catch {
    // unreadable directory — no signal
  }

  const githubDir = path.join(root, '.github')
  try {
    if (fs.existsSync(githubDir) && fs.readdirSync(githubDir).some((f) => f.startsWith('copilot-'))) {
      signals.push('AI tooling configured (GitHub Copilot)')
    }
  } catch {
    // unreadable directory — no signal
  }

  return signals
}

/** Signals from the most recent commit message touching `filePath`. */
export function commitMessageSignals(filePath: string, root: string): string[] {
  let message = ''
  try {
    message = execFileSync('git', ['-C', root, 'log', '--format=%s', '-1', '--', filePath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
  } catch {
    return []
  }
  if (!message) return []

  const signals: string[] = []
  const tool = message.match(AI_TOOL_PATTERN)
  if (tool) signals.push(`commit references ${tool[0].toLowerCase()}`)
  if (GENERATED_COMMIT_PATTERN.test(message)) signals.push('commit marked as generated')
  return signals
}

/**
 * Classifies each supplied source file as AI-attributed when its git history
 * ties it to an AI coding tool. `files` are absolute paths; results are keyed
 * to workspace-relative paths.
 */
export function scanProvenance(workspacePath: string, files: string[]): ProvenanceResult {
  const root = findWorkspaceRoot(workspacePath)
  const gitAvailable = fs.existsSync(path.join(root, '.git'))
  const repoSignals = repoToolingSignals(root)

  const aiAttributed: FileProvenance[] = []
  let filesChecked = 0

  if (gitAvailable) {
    for (const abs of files) {
      filesChecked++
      const signals = commitMessageSignals(abs, root)
      if (signals.length === 0) continue
      const rel = path.relative(workspacePath, abs).split(path.sep).join('/')
      aiAttributed.push({
        file: rel,
        confidence: signals.length >= 2 ? 'high' : 'medium',
        signals,
      })
    }
  }

  return {
    aiAttributed,
    aiAttributedCount: aiAttributed.length,
    filesChecked,
    repoSignals,
    gitAvailable,
  }
}

/**
 * Builds a machine-readable provenance record (JSON) suitable for retention as
 * an AI-authorship audit trail — the kind of record-keeping EU AI Act Article 12
 * anticipates. This is a summary artifact, not a certification.
 */
export function buildProvenanceRecord(
  result: ProvenanceResult,
  repoName: string,
  commitSha: string,
  generatedAt: Date = new Date()
): string {
  return JSON.stringify(
    {
      tool: 'reposcope-action',
      repo: repoName,
      commit: commitSha,
      generatedAt: generatedAt.toISOString(),
      method: 'git-attributed AI authorship + repo tooling signals (local, deterministic)',
      filesChecked: result.filesChecked,
      aiAttributedCount: result.aiAttributedCount,
      repoSignals: result.repoSignals,
      aiAttributedFiles: result.aiAttributed,
      note: 'Heuristic provenance for AI-authorship record-keeping. Not a certification or legal-compliance determination.',
    },
    null,
    2
  )
}
