# Prodogy — Product Validation & Strategy Report

*Synthesis of multi-disciplinary expert reviews (technical architecture, security,
finance/pricing) and the implementation response. This document is the strategic
companion to the codebase.*

---

## Executive summary

Prodogy is an intelligent deployment-readiness linter that plugs into CI/CD and
answers four questions about deployment configs: is this production-safe, what
could break at deploy time, what is hard to maintain later, and which files need
protection before analysis. Expert review across three disciplines converged on
one conclusion: **the core architecture is sound and the concept is fundable; the
risks are trust, accuracy, and scope discipline — not feasibility.**

Following the reviews, the product was hardened from a solid prototype toward a
production-grade tool. Rule coverage grew from 14 to 21 rules, the web server's
critical security gaps were closed, configuration and compliance reporting were
added, and the git-history engine was made scalable.

---

## 1. Technical architecture (validated)

**Verdict:** Well-designed core. Clean pipeline (discover → parse → rules →
suppression → report), a single Report contract that all renderers consume,
fault-isolated rules, deterministic offline execution, and line-accurate
findings. Suitable as a CI gate.

**Key risks identified and status:**

| Risk | Severity | Status |
|---|---|---|
| Sequential scan bottleneck on monorepos | High | Documented; parallelization is the next perf milestone |
| O(n) git subprocess per file in maintainability | High | **Fixed** — single-pass `git log` with timestamps |
| No config/profile system | High | **Fixed** — `.prodogy.yml` (disable rules, severity overrides, excludes, protected categories) |
| Silent rule-exception false-negatives | Medium | **Fixed** — surfaced as `CORE002` findings |
| No external plugin system | Medium | Planned (entry_points) |
| File-size / YAML-bomb guard | Medium | Planned |

## 2. Security (validated — was the weakest area, now much stronger)

**Verdict before:** rules 6/10, tool self-security 4/10. The web dashboard
allowed unauthenticated arbitrary filesystem reads, and the "never auto-approve a
secret" guarantee was silently defeatable by an inline suppression comment.

**Fixes shipped:**

- **Web path allowlisting** — scans restricted to explicit `--allow` roots;
  path traversal to `/etc`, `~/.ssh`, etc. returns 403. No more `expanduser`.
- **Web auth token** — a random per-run Bearer token is required by default;
  the CLI prints a ready-to-open URL. `--no-auth` is opt-in and warned.
- **Non-suppressible confidential findings** — secret findings can no longer be
  silenced by `# prodogy-ok`; the attempt is recorded in the audit note and the
  finding still blocks the gate. This restores the central trust guarantee.
- **Better secret accuracy** — known provider formats (AWS `AKIA`, GCP `AIza`,
  GitHub `ghp_`, Slack, Stripe, JWT) are detected directly; the generic heuristic
  was tightened (entropy ≥ 3.5 + character-class diversity) to cut false positives.
- **New high-value rules** — host namespaces (K8S006), dangerous capabilities
  (K8S007), writable root FS (K8S008), plaintext Secret manifests (K8S009),
  auto-mounted SA token (K8S010), broad GHA permissions (CI003),
  `pull_request_target` checkout of untrusted code (CI004).

**Still open:** rate limiting / concurrency cap on the web server; dependency
vulnerability scanning in CI.

## 3. Finance & pricing (validated)

**Verdict:** Structurally attractive SaaS economics. The deterministic engine
runs on the customer's CI runners, so core COGS is near-zero and gross margins
land at ~85–92%. Open-core is mandatory for adoption in this category.

**Recommended model:**

| Tier | Price | Includes |
|---|---|---|
| Community (OSS) | $0 | Engine, CLI, CI integration, SARIF/markdown, all rules |
| Team | ~$25/dev/mo | Hosted dashboard, custom rules, org policy, notifications |
| Business | ~$55/dev/mo | LLM explanations, SSO, audit log, **compliance reports**, SLA |
| Enterprise | custom | Air-gapped, dedicated CS, attestations |

**Swing factor:** the optional LLM explanation layer. Must be cached and use
small models (Haiku / 4o-mini) to keep Business-tier COGS near $1.50–3/dev.

**Path to PMF:** ~$1.5M seed for ~18 months runway; conservative $1M ARR by
year 3, base case ~$3.8M.

## 4. Market & positioning (partial — see open items)

Prodogy competes with checkov, trivy, datree, and kics. Those tools win on
breadth of security rules. Prodogy's defensible differentiator is the
**maintainability-aware, plain-language "staff engineer" layer** — the
git-history heatmap (churn, co-change coupling, neglected debt) plus rationale
that explains *why* something matters, not just that it's wrong. The compliance
report (control-mapped to CIS / NSA / PCI / SOC2) is the enterprise wedge.

Recommended positioning: not "another scanner" but a **deployment-readiness
coach** that combines a gate with operability insight.

---

## Implemented in this iteration (v0.1 → v0.2)

- 21 rules (from 14): +5 K8s hardening, +2 GHA supply-chain, expanded secrets
- `.prodogy.yml` config: disable rules, severity overrides, path excludes,
  `fail_on`, non-suppressible categories
- Compliance report format mapping findings to CIS/NSA/PCI/SOC2 controls
- `compliance_refs` on findings and rules
- Web server security: path allowlisting + per-run auth token
- Trust fix: confidential findings are non-suppressible with audit trail
- Rule-error surfacing (`CORE002`) instead of silent skips
- Single-pass git history (scalability)
- 69 tests, ~89% coverage, lint clean

## Recommended next milestones (priority order)

1. Parallelize scanning (ProcessPool) + file-size guards for monorepo scale
2. LLM explanation layer (cached, small-model, strictly annotation-only)
3. External plugin system via `importlib.metadata.entry_points`
4. Baseline/diff mode (only fail on *new* findings) — major alert-fatigue win
5. PR-comment posting integration (GitHub App) for a real end-to-end demo
6. Terraform + Helm-template rule coverage
7. Web server rate limiting; dependency scanning in CI
