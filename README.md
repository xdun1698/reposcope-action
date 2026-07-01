# RepoScope Security & Compliance Scanner

> Scan your codebase for security vulnerabilities, map findings to 5 compliance frameworks, and generate an audit-ready evidence package — all from your GitHub Actions workflow.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-RepoScope-blue?logo=github)](https://github.com/marketplace/actions/reposcope-security-compliance-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What it does

On every pull request or push, RepoScope:

1. **Scans every source file** for 44 security detectors across 14 languages — secrets, SQL injection, XSS, command injection, TLS misconfigs, weak crypto, and more.
2. **Posts one PR review comment per finding** — file, line number, severity badge, CWE ID, and a concrete fix hint.
3. **Creates a GitHub Check** — `RepoScope Security — PASS` or `FAIL` with your configurable score threshold.
4. **Generates a compliance report** mapping every finding to OWASP Top 10 (2021), SOC 2 Type II, PCI-DSS v4.0, EU AI Act Article 12, and ISO/IEC 42001 — uploaded as a build artifact.
5. **Optionally fails the build** if any finding meets or exceeds your configured severity threshold.

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
      - uses: nxgentech/reposcope-action@v1
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
| `frameworks` | `owasp,soc2,pci-dss` | Comma-separated compliance frameworks in the report. Options: `owasp`, `soc2`, `pci-dss`, `eu-ai-act`, `iso-42001` |
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
- uses: nxgentech/reposcope-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: none
```

### Fail on any critical finding, require score ≥ 80

```yaml
- uses: nxgentech/reposcope-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: critical
    threshold: 80
```

### Full EU AI Act + ISO 42001 compliance report

```yaml
- uses: nxgentech/reposcope-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    frameworks: owasp,soc2,pci-dss,eu-ai-act,iso-42001
    fail-on: high
    threshold: 70
```

### Use outputs in a downstream step

```yaml
- uses: nxgentech/reposcope-action@v1
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

## Compliance frameworks

Each finding is mapped to controls in:

- **OWASP Top 10 (2021)** — A01–A10
- **SOC 2 Type II** — CC6.1, CC6.6, CC6.7, CC7.1, CC8.1
- **PCI-DSS v4.0** — Requirements 3, 4, 6, 8, 12
- **EU AI Act Article 12** — Traceability + cybersecurity controls
- **ISO/IEC 42001** — AI risk assessment + lifecycle security

> **Disclaimer:** This tool covers code-level controls only. It is a development aid, not a certification or legal compliance tool. Manual review is required before use in any formal audit.

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

## For in-editor findings

Install the **[RepoScope VS Code extension](https://marketplace.visualstudio.com/items?itemName=nxgentech.reposcope-ai)** to see the same findings live as you write code, with compliance posture scoring, AI Game Plan, and 1-click audit evidence packages — in VS Code, Cursor, and Devin Desktop.

---

## Contributing

Pull requests welcome. Please open an issue first for significant changes.

1. `npm install`
2. `npm run compile` — TypeScript to `dist/`
3. `npm run build` — bundle with `ncc` for the `runs.main: dist/index.js` entrypoint
4. Test against a real repo with `act` (local GitHub Actions runner)

## License

MIT © [NxGen Tech Solutions](https://reposcope.app)
