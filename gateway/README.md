# Prodogy Gateway

A small internal proxy so every team's CI pipeline can use Prodogy's optional
LLM enrichment (`prodogy scan --enrich` / `prodogy enrich`) **without** each
repo holding the real Veynora API key.

```
CI job (any repo)  ──▶  Prodogy Gateway (EC2, this service)  ──▶  Veynora  ──▶  Nova Pro / Claude Haiku
    (virtual key)              (holds the real VEYNORA_API_KEY)
```

- One real credential, held only on this instance.
- Each team/repo gets its own **virtual key** — revocable individually,
  with its own daily request budget.
- Exposes an OpenAI-compatible `/v1/chat/completions` endpoint, which is
  exactly what Prodogy's enricher (`src/prodogy/enricher.py`) already
  expects — **no changes to Prodogy itself are needed.**

## What this is not

This is not a scan proxy. Source code never passes through this gateway —
only Prodogy's own findings (rule ID, message, rationale/remediation text,
file:line) get sent to the LLM for enrichment, and never a raw secret value
(Prodogy's secret rules only ever report a variable *name*, never its
value — see `src/prodogy/rules/secret_rules.py`). Every repo still runs
`prodogy scan` itself, locally in its own CI job, exactly as documented in
the main [README](../README.md). This gateway only stands in for the LLM
call in the optional `--enrich` step.

## Deploy (EC2)

1. **Provision** a small EC2 instance (this workload is light — a `t3.micro`
   is plenty for a handful of internal teams). Put it in a security group
   that only allows inbound 443 (or 8080, see TLS note below) from your
   office/VPN CIDR, or from your GitHub Actions runners if you've locked
   that down — this is your call, the gateway itself doesn't enforce it.

2. **Install Node.js 20+** (the server uses the built-in global `fetch`,
   available since Node 18):
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
   sudo apt-get install -y nodejs
   ```

3. **Copy this `gateway/` directory** to `/opt/prodogy-gateway` on the
   instance (e.g. `git clone` the repo there, or `scp` just this folder).

4. **Create the real-credentials env file** (root-only, never committed):
   ```bash
   sudo mkdir -p /etc/prodogy-gateway
   sudo tee /etc/prodogy-gateway/env >/dev/null <<'EOF'
   VEYNORA_BASE_URL=https://veynoraai-backend-ene8hfb7fjaacrbs.centralindia-01.azurewebsites.net
   VEYNORA_API_KEY=<the real Veynora key>
   GATEWAY_PORT=8080
   GATEWAY_KEYS_FILE=/opt/prodogy-gateway/keys.json
   GATEWAY_LOG_FILE=/opt/prodogy-gateway/access.log
   EOF
   sudo chmod 600 /etc/prodogy-gateway/env
   ```

5. **Issue virtual keys** — copy the template and fill in real random
   strings, one per team:
   ```bash
   cd /opt/prodogy-gateway
   cp keys.json.example keys.json
   # Generate a key per team:
   openssl rand -hex 24
   # Paste the result as a key in keys.json, replacing the placeholder,
   # and set "label" to something identifying the team/repo.
   chmod 600 keys.json
   ```

6. **Create the service user and install the systemd unit:**
   ```bash
   sudo useradd --system --no-create-home prodogy-gateway
   sudo chown -R prodogy-gateway:prodogy-gateway /opt/prodogy-gateway
   sudo cp prodogy-gateway.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now prodogy-gateway
   sudo systemctl status prodogy-gateway
   ```

7. **TLS**: the Node process here speaks plain HTTP. Put a reverse proxy in
   front for TLS termination — e.g. [Caddy](https://caddyfile.com/) with a
   two-line Caddyfile handles Let's Encrypt automatically:
   ```
   your-gateway-domain.internal {
       reverse_proxy localhost:8080
   }
   ```
   If this instance lives entirely inside a private VPN subnet you already
   trust, you can skip TLS and use plain HTTP on the internal address
   instead — that's a call for whoever owns your network, not made here.

## Verify it's up

```bash
curl https://your-gateway-domain.internal/healthz
# {"status":"ok"}

curl https://your-gateway-domain.internal/v1/chat/completions \
  -H "Authorization: Bearer <a real virtual key from keys.json>" \
  -H "Content-Type: application/json" \
  -d '{"model":"Amazon Nova Pro","messages":[{"role":"user","content":"say hi"}],"max_tokens":50}'
```

Without a valid key you should get `401`; past a key's `dailyBudget` you
should get `429`.

## Point a repo at the gateway

In that repo's `.prodogy.yml`:
```yaml
llm:
  provider_url: "https://your-gateway-domain.internal/v1"
  model: "Amazon Nova Pro"
  api_key: "${PRODOGY_GATEWAY_KEY}"   # from a CI secret, see below
```

Or entirely via CI environment/secrets, with no `.prodogy.yml` change:
```yaml
env:
  PRODOGY_LLM_PROVIDER_URL: "https://your-gateway-domain.internal/v1"
  PRODOGY_LLM_MODEL: "Amazon Nova Pro"
  PRODOGY_LLM_API_KEY: ${{ secrets.PRODOGY_GATEWAY_KEY }}
```

Each repo's CI secret holds *its own* virtual key from `keys.json` — never
the real Veynora credential. If a repo is compromised or a team leaves,
delete their line from `keys.json` on the gateway; no redeploy needed
(`keys.json` is re-read on every request).

If Nova Pro's answers read as too generic for a given finding, switch that
repo's `model` to `Claude Haiku 4.5` — both are already listed in the
gateway's `/v1/models` and require no gateway-side changes.

## Operating it

- **Add a team**: generate a key (`openssl rand -hex 24`), add it to
  `keys.json` with a label and budget, hand it to the team via your normal
  secrets channel (never git, never Slack in plaintext).
- **Revoke a team**: delete their entry from `keys.json`. Takes effect on
  their next request.
- **Cost/usage visibility**: `access.log` on the instance is a JSON-lines
  file — one line per request with `label`, `model`, token counts, latency,
  and status, but never message content. Tail it or ship it to your normal
  log aggregation.
  ```bash
  tail -f /opt/prodogy-gateway/access.log
  ```
- **Raise/lower a budget**: edit the `dailyBudget` value for that team's key
  in `keys.json`. Budgets reset daily at UTC midnight (in-memory counters —
  a gateway restart also resets them early, which is fine at this scale).

## Local development

```bash
cd gateway
cp keys.json.example keys.json   # then put a real random key in it
cat > .env <<'EOF'
VEYNORA_BASE_URL=https://veynoraai-backend-ene8hfb7fjaacrbs.centralindia-01.azurewebsites.net
VEYNORA_API_KEY=<your real key>
GATEWAY_PORT=8080
EOF
node server.js
```

Then from anywhere:
```bash
export PRODOGY_LLM_PROVIDER_URL=http://localhost:8080/v1
export PRODOGY_LLM_MODEL="Amazon Nova Pro"
export PRODOGY_LLM_API_KEY=<the virtual key you put in keys.json>
prodogy enrich examples/bad
```
