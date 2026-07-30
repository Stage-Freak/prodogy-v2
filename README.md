# Prodogy

**Intelligent deployment-readiness linter** — a production-readiness coach for your CI/CD pipeline.

Prodogy goes beyond syntax and security scanning to answer four questions about your deployment configs:

1. **Is this config production-safe?** (missing resource limits, root containers, `:latest` tags)
2. **What could break at deploy time?** (deprecated APIs, missing probes)
3. **What is hard to maintain later?** (git-history heatmaps, tight coupling, neglected debt)
4. **Which files need permission or redaction before analysis?** (confidential-file detection)

It plugs into any CI system as a pipeline step, posts an annotated PR comment, and can fail the build on critical issues.

## Architecture

The **JSON report is the single source of truth**. A deterministic rule engine produces it; every renderer (terminal, PR comment, SARIF, web UI) merely displays it. This keeps CI pass/fail decisions reproducible and offline. An optional LLM layer may *annotate* findings but never decides severity.

```
files / git ──▶ discovery ─▶ parsers ─▶ rule engine ─▶ suppression ─▶ Report (JSON)
                                                                          │
                        ┌──────────────┬───────────────┬─────────────────┤
                        ▼              ▼               ▼                 ▼
                   terminal       PR comment        SARIF          web dashboard
```

## Install (local dev)

```bash
python3 -m venv .venv --without-pip
. .venv/bin/activate
curl -sS https://bootstrap.pypa.io/get-pip.py | python   # only if pip is missing
pip install -e ".[dev,web]"
```

## Usage

### GitHub Action (recommended)

Add one step to any workflow — no copy-paste needed. The action installs Prodogy,
collects changed files in PR mode, runs the scan, optionally posts a PR comment,
and fails the build on blocking findings:

```yaml
- uses: Stage-Freak/prodogy-v2@main
  with:
    fail-on: error              # gate threshold
    post-pr-comment: true       # auto-post a PR comment with findings
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

**Inputs:**

| Input | Default | Description |
|---|---|---|
| `fail-on` | `error` | Minimum severity that fails the build (`critical`, `error`, `warning`, `info`) |
| `changed` | — | File listing changed paths (one per line) — override auto-detection |
| `config` | — | Path to a `.prodogy.yml` config file |
| `baseline` | — | Baseline file to suppress pre-existing findings |
| `version` | — | Pin a specific Prodogy version (e.g. `v0.2.0`) |
| `post-pr-comment` | `false` | Post a findings summary as a PR comment |
| `github-token` | — | GitHub token for posting PR comments |
| `enrich` | `false` | Enrich findings with LLM-generated contextual explanations |
| `llm-api-key` | — | API key for the LLM provider (set as a GitHub secret) |
| `llm-provider-url` | — | LLM provider base URL (default: `https://api.openai.com/v1`) |
| `llm-model` | — | LLM model name (default: `gpt-4o-mini`)

**With LLM enrichment enabled:**

```yaml
- uses: Stage-Freak/prodogy-v2@main
  with:
    fail-on: error
    post-pr-comment: true
    github-token: ${{ secrets.GITHUB_TOKEN }}
    enrich: true
    llm-api-key: ${{ secrets.PRODOGY_LLM_API_KEY }}
    llm-provider-url: https://openrouter.ai/api/v1
    llm-model: openrouter/free
```

For SARIF upload (GitHub Code Scanning), add one more step after the action:

```yaml
- uses: Stage-Freak/prodogy-v2@main

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: /tmp/prodogy-report.json
  continue-on-error: true
```

See [`examples/ci/github-actions.yml`](examples/ci/github-actions.yml) for a complete example.

### CLI

```bash
prodogy scan ./path                       # human-friendly terminal report
prodogy scan ./path --fail-on critical    # gate: exit non-zero on critical+
prodogy scan ./path -f markdown -o pr.md  # PR-comment body
prodogy scan ./path -f sarif -o out.sarif # CI code-scanning
prodogy scan ./path -f compliance         # control-mapped audit report
prodogy scan ./path --maintainability     # add the git-history heatmap
prodogy scan . --changed changed.txt      # PR mode: only scan changed files
prodogy scan . --config .prodogy.yml      # use a config file (auto-discovered too)
prodogy scan . --write-baseline base.json # accept current findings as a baseline
prodogy scan . --baseline base.json       # gate only on NEW findings
prodogy rules                             # list all rules
prodogy enrich ./path                     # add LLM contextual explanations (optional)
prodogy serve                             # launch the local web dashboard (auth on)
```

Exit code is `1` when a finding at or above `--fail-on` (default `error`) exists — this is the pipeline gate.

## Rules (v0.2 — 58 rules)

Run `prodogy rules` for the live, authoritative list. Many rules carry compliance mappings
(CIS Docker/Kubernetes, NSA/CISA, PCI DSS, SOC 2) surfaced in the compliance report.

**Core**

| ID | Severity | What it catches |
|---|---|---|
| CORE001 | error | Config file that fails to parse (would break the deploy) |
| CORE002 | warning | A rule crashed mid-scan (surfaced, never silent) |

**Dockerfile**

| ID | Severity | What it catches |
|---|---|---|
| DOCKER001 | error | `:latest` / unpinned base image |
| DOCKER002 | error | Container runs as root |
| DOCKER003 | warning | No HEALTHCHECK |
| DOCKER004 | critical | Hard-coded secret in ENV/ARG |
| DOCKER005 | warning | `ADD` used where `COPY` is safer |

**Docker Compose**

| ID | Severity | What it catches |
|---|---|---|
| DC001 | error | Service image uses `:latest` or an unpinned tag |
| DC002 | warning | Service has no healthcheck |
| DC003 | critical | Hard-coded secret in service environment |
| DC004 | warning | Service has no resource limits |
| DC005 | info | Service has no restart policy |

**Kubernetes**

| ID | Severity | What it catches |
|---|---|---|
| K8S001 | error | Missing resource requests/limits |
| K8S002 | warning | Missing liveness/readiness probe |
| K8S003 | critical | Privileged / root container |
| K8S004 | info | Missing recommended app labels |
| K8S005 | error | Deprecated/removed apiVersion |
| K8S006 | critical | Host namespace (hostNetwork/PID/IPC) |
| K8S007 | error | Dangerous Linux capabilities added |
| K8S008 | warning | Writable root filesystem |
| K8S009 | critical | Plaintext credentials in a Secret manifest |
| K8S010 | warning | Service account token auto-mounted |

**CI/CD (GitHub Actions / GitLab CI)**

| ID | Severity | What it catches |
|---|---|---|
| CI001 | warning | Third-party action not pinned to a commit SHA |
| CI002 | critical | Hard-coded secret in a CI pipeline |
| CI003 | error | Overly broad workflow permissions |
| CI004 | critical | `pull_request_target` checks out untrusted PR code |
| CI005 | warning | Job has no timeout limit |
| CI006 | info | Artifact upload has no retention limit |

**Terraform**

| ID | Severity | What it catches |
|---|---|---|
| TF001 | error | S3 bucket server-side encryption not enabled |
| TF002 | critical | S3 bucket has public access enabled |
| TF003 | warning | Remote state backend missing encryption or locking |
| TF004 | critical | IAM policy grants root-level access |
| TF005 | warning | S3 bucket access logging not enabled |

**Ansible**

| ID | Severity | What it catches |
|---|---|---|
| ANS001 | warning | Playbook uses `become: yes` without restricting to a specific user |
| ANS002 | critical | Hard-coded secret in playbook variables |
| ANS003 | info | Playbook uses shell/command module instead of an idempotent module |

**Monitoring (Grafana / Prometheus)**

| ID | Severity | What it catches |
|---|---|---|
| MON001 | critical | Grafana anonymous authentication enabled |
| MON002 | error | Grafana not configured for HTTPS |
| MON003 | critical | Grafana admin password not changed from default |
| MON004 | warning | Prometheus retention period not configured |
| MON005 | warning | Prometheus has no alerting configuration |
| MON006 | warning | Prometheus metrics endpoint exposed without auth |

**Secrets (any file)**

| ID | Severity | What it catches |
|---|---|---|
| SECRET001 | critical | File appears to contain secrets |

## Configuration (`.prodogy.yml`)

Drop a `.prodogy.yml` at your repo root (auto-discovered) to customize behavior:

```yaml
# Disable specific rules entirely.
disabled_rules: [K8S004]

# Override a rule's severity.
severity_overrides:
  DOCKER003: info

# Exclude paths from scanning (supports **/ recursive globs).
exclude:
  - "**/vendor/**"
  - "examples/**"

# Default gate threshold.
fail_on: error

# Categories whose findings can never be suppressed inline.
# Defaults to [confidential] — secrets always block the gate.
non_suppressible: [confidential]
```

## Baseline mode (adopt on existing repos without a wall of red)

```bash
prodogy scan . --write-baseline .prodogy-baseline.json  # accept today's findings
prodogy scan . --baseline .prodogy-baseline.json        # gate only on NEW findings
```

Pre-existing findings are suppressed (with an audit note) so the gate only fails
on regressions. Confidential/secret findings are never baselined away — a newly
committed secret always blocks the build.

## Compliance reporting

```bash
prodogy scan . -f compliance -o compliance.md
```

Produces a control-mapped report grouping findings by framework (CIS Docker/K8s,
NSA/CISA, PCI DSS, SOC 2), with file:line evidence per control and a documented-
exceptions section listing suppressed findings and their justifications.

## LLM enrichment (optional, annotation-only)

```bash
export PRODOGY_LLM_API_KEY=sk-...         # or set llm.api_key in .prodogy.yml
prodogy scan . --enrich                  # enrich findings inline during a scan
prodogy enrich .                         # or as a standalone pass
prodogy enrich . -f markdown -o pr.md    # enrich then render any supported format
prodogy enrich . --cache-stats           # inspect the enrichment cache
prodogy enrich . --force                 # re-enrich even already-cached findings
```

An LLM call adds a plain-language, project-aware `llm_explanation` to each
finding — deeper remediation guidance, cross-finding correlation — but it
**never** touches `severity`, `rule_id`, `rationale`, or any other
deterministic field. A `critical` finding stays `critical` no matter what the
model says; the gate decision is unaffected. Enrichment is fully optional —
the tool works completely offline without it.

Configuration (env vars, or an `llm:` block in `.prodogy.yml`):

| Setting | Env var | Default |
|---|---|---|
| API key | `PRODOGY_LLM_API_KEY` | *(none — enrichment disabled until set)* |
| Provider base URL | `PRODOGY_LLM_PROVIDER_URL` | `https://api.openai.com/v1` |
| Model | `PRODOGY_LLM_MODEL` | `gpt-4o-mini` |

Any provider that exposes an OpenAI-compatible `/chat/completions` endpoint
works. Without an API key configured, `enrich` prints setup instructions and
exits `0` rather than failing the build.

Results are cached by finding fingerprint in `.prodogy-enrich-cache.json`
(7-day TTL) to avoid redundant API calls and control cost; delete that file or
pass `--force` to re-enrich.

## Web dashboard

A local, minimal dashboard renders the same report the CLI produces — findings
with filters, the maintainability heatmap, and a scanned-files list.

```bash
prodogy serve                      # http://127.0.0.1:8765
prodogy serve --allow ./k8s        # restrict scans to a directory
prodogy serve --no-auth            # disable the token (not recommended)
```

Security defaults (a local dev tool that reads files, so it is locked down):

- **Auth token required by default** — the CLI prints a ready-to-open URL with a
  random per-run token. Requests without it get 401.
- **Path allowlisting** — scans are restricted to the current directory (or
  `--allow` roots). Any path outside them returns 403, so the dashboard cannot be
  used to read arbitrary files.

Do not expose it to an untrusted network even with auth on.

## Suppressing a rule

Context matters — a batch job may not need probes. Suppress inline:

```yaml
- name: batch-worker  # prodogy-ok:K8S002 batch job, no probes needed
```

Suppressed findings stay in the report (marked `suppressed`) for an audit trail; they just don't count toward the gate.

## Trust model for secrets

The confidential-file detector **never auto-approves**. A filename matching an example/template pattern (`*.example`, `sample.*`) reduces severity to a warning *and records an audit note* — it never silently hides a finding. Human-in-the-loop by design.

## Testing

```bash
pytest -q
```
