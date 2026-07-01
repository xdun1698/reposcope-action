# RepoScope Security Scanner

> Scan your codebase for security vulnerabilities on every push and pull request — inline PR comments, a build-gating security score, and a shareable HTML report.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-RepoScope-blue?logo=github)](https://github.com/marketplace/actions/reposcope-security-scanner)
[![GitHub repo](https://img.shields.io/badge/Source-xdun1698%2Freposcope--action-lightgrey?logo=github)](https://github.com/xdun1698/reposcope-action)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

On every pull request or push, RepoScope:

1. **Scans every source file** with 44 security detectors across 14 languages — secrets, SQL injection, XSS, command injection, TLS misconfigs, weak crypto, and more.
2. **Posts one PR review comment per finding** — file, line number, severity badge, CWE ID, and a concrete fix hint.
3. **Creates a GitHub Check** — `RepoScope Security — PASS` or `FAIL` with your configurable score threshold.
4. **Generates an HTML security report** — findings by type + full detail, uploaded as a build artifact.
5. **Optionally fails the build** if any finding meets or exceeds your configured severity threshold.

> Looking for **compliance mapping** (OWASP / SOC 2 / PCI-DSS / EU AI Act / ISO 42001) and **audit-ready evidence packages**? Those are RepoScope Pro features — see [In-editor + compliance](#in-editor--compliance) below.

---

## Quickstart

```yaml
# .github/workflows/security.yml
name: RepoScope Security Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write    # for PR review comments
      checks: write           # for GitHub Check runs
    steps:
      - uses: actions/checkout@v4
      - uses: xdun1698/reposcope-action@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

---

## Configuration

| Input | Default | Description |
|-------|---------|-------------|
| `token` | `${{ github.token }}` | GitHub token for posting comments and creating checks. Requires `pull-requests: write` and `checks: write` permissions. |
| `workspace-path` | `${{ github.workspace }}` | Directory to scan. Defaults to the repo root after checkout. |
| `fail-on` | `high` | Minimum severity that fails the build. Options: `none` \| `low` \| `medium` \| `high` \| `critical` |
| `threshold` | `0` | Fail if the overall security score (0–100) drops below this value. `0` disables. |
| `comment-on-pr` | `true` | Post inline review comments per finding. Set `false` for push-only runs. |
| `report-path` | `.reposcope/report.html` | Relative path (within the workspace) where the HTML report is saved. |

### Outputs

| Output | Description |
|--------|-------------|
| `security-score` | Overall score 0–100 (higher = safer) |
| `findings-count` | Total deduplicated findings |
| `critical-count` | Critical severity findings |
| `high-count` | High severity findings |
| `report-path` | Absolute path to the HTML report artifact |

---

## Examples

### Only alert, never fail

```yaml
- uses: xdun1698/reposcope-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: none
```

### Fail on any critical finding, require score ≥ 80

```yaml
- uses: xdun1698/reposcope-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: critical
    threshold: 80
```

### Use outputs in a downstream step

```yaml
- uses: xdun1698/reposcope-action@v1
  id: reposcope
  with:
    token: ${{ secrets.GITHUB_TOKEN }}

- name: Print score
  run: echo "Security score: ${{ steps.reposcope.outputs.security-score }}"
```

---

## Security detectors

RepoScope ships **44 detectors** across **14 languages**, including:

| Category | Examples |
|----------|----------|
| **Hardcoded secrets** | API keys, AWS keys, GitHub tokens, Slack tokens, Stripe live keys, Google API keys, JWTs, Bearer tokens |
| **Database credentials** | MongoDB/PostgreSQL/MySQL connection strings with embedded passwords, `.env` secret values |
| **Command injection** | `os.system()`, `subprocess(shell=True)`, `execSync`, `shell_exec()`, backtick interpolation |
| **Cross-site scripting** | `innerHTML =`, `dangerouslySetInnerHTML`, `v-html`, Angular `bypassSecurityTrust*`, `document.write` |
| **SQL injection** | `cursor.execute(f"...")`, string-interpolated queries |
| **TLS misconfigurations** | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`, `verify=False` |
| **Weak cryptography** | MD5, SHA-1 in hashing contexts |
| **Permissive CORS** | `Access-Control-Allow-Origin: *`, `origin: '*'` |

---

## Suppress false positives

Add an inline comment on the finding line (or the line above) to suppress it:

```python
STRIPE_KEY = "sk_test_example"  # reposcope-ignore: test fixture, not a real key
```

```typescript
// reposcope-ignore: intentional for local dev only
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
```

---

## In-editor + compliance

This action covers **security scanning**. For the full RepoScope experience, install the **[RepoScope extension](https://marketplace.visualstudio.com/items?itemName=nxgentech.reposcope-ai)** (VS Code, Cursor, Devin Desktop):

- **Live findings** as you write code, not just in CI
- **Compliance posture** — maps findings to OWASP Top 10 (2021), SOC 2 Type II, PCI-DSS v4.0, EU AI Act Article 12, and ISO/IEC 42001 with per-control PASS/PARTIAL/FAIL status
- **Audit evidence packages** — one-click Control Matrix, Attestation Memo, Gap Plan, and Auditor Evidence Response
- **Cost & Budget intelligence**, **AI Game Plan**, and **code provenance** tracking

Free tier includes the security scanner + Repo Map + provenance. Compliance and audit tooling are Pro ($14.99/mo).

---

## Contributing

Pull requests welcome. Please open an issue first for significant changes.

1. `npm install`
2. `npm run compile` — TypeScript to `dist/`
3. `npm run build` — bundle with `ncc` for the `runs.main: dist/index.js` entrypoint

## License

MIT © [NxGen Tech Solutions](https://reposcope.app)
