/**
 * Prodogy Gateway — internal LLM proxy for `prodogy enrich` / `--enrich`.
 *
 * Problem this solves: Prodogy's optional LLM enrichment layer
 * (src/prodogy/enricher.py) needs an OpenAI-compatible endpoint. Without this
 * gateway, every internal repo's CI would need its own copy of the real
 * Veynora API key. Instead:
 *
 *   - This process holds the ONE real Veynora credential (VEYNORA_API_KEY).
 *   - Each internal team/repo gets a distributed "virtual key" (see keys.json)
 *     that is meaningless outside this gateway and can be revoked individually.
 *   - Requests are translated from OpenAI's /v1/chat/completions shape to
 *     Veynora's Anthropic-style /proxy/v1/messages shape and back, so Prodogy
 *     needs zero code changes — it just points PRODOGY_LLM_PROVIDER_URL here.
 *
 * This is derived from ../veynora-adapter.js but deliberately smaller: it
 * drops streaming and tool-calling support, since Prodogy's enricher
 * (_call_llm in enricher.py) never sets `stream` or `tools` on its requests.
 * Keeping unused code paths out keeps this easier to audit.
 *
 * What is NOT sent through this gateway: raw secret values. Prodogy's own
 * secret-detection rules (src/prodogy/rules/secret_rules.py) only ever put a
 * variable *name* in a finding message (e.g. "'API_TOKEN' appears to hold a
 * real secret value"), never the value itself — so the enrichment payload
 * this gateway forwards contains no live credentials by construction.
 *
 * Usage: node server.js  (reads env vars + keys.json from this directory,
 * or the paths given by GATEWAY_KEYS_FILE / GATEWAY_ENV_FILE)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// ── load env (real Veynora credentials + gateway settings) ──────────────────
// In production this comes from the systemd EnvironmentFile
// (/etc/prodogy-gateway/env); for local dev, a .env file in this directory.
const envFile = process.env.GATEWAY_ENV_FILE || path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  fs.readFileSync(envFile, 'utf8').split('\n').forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eq = trimmed.indexOf('=');
    if (eq === -1) return;
    const key = trimmed.slice(0, eq).trim();
    if (!(key in process.env)) process.env[key] = trimmed.slice(eq + 1).trim();
  });
}

const VEYNORA_BASE = (process.env.VEYNORA_BASE_URL || '').replace(/\/+$/, '');
const VEYNORA_KEY = process.env.VEYNORA_API_KEY || '';
const PORT = parseInt(process.env.GATEWAY_PORT || process.env.PORT || '8080', 10);
const KEYS_FILE = process.env.GATEWAY_KEYS_FILE || path.join(__dirname, 'keys.json');
const LOG_FILE = process.env.GATEWAY_LOG_FILE || path.join(__dirname, 'access.log');

if (!VEYNORA_BASE || !VEYNORA_KEY) {
  console.error(
    'FATAL: VEYNORA_BASE_URL and VEYNORA_API_KEY must be set (via env or ' +
    `${envFile}). Refusing to start without the real upstream credential.`
  );
  process.exit(1);
}

const MODELS = [
  { id: 'Amazon Nova Pro', object: 'model', owned_by: 'amazon' },
  { id: 'Claude Haiku 4.5', object: 'model', owned_by: 'anthropic' },
];

// ── virtual keys ──────────────────────────────────────────────────────────────
// keys.json maps a virtual key string -> { label, dailyBudget }. Reloaded on
// every request so a key can be added/revoked without restarting the process
// (edit keys.json, next request picks it up — no deploy needed for key ops).
function loadKeys() {
  try {
    const raw = fs.readFileSync(KEYS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return parsed;
  } catch (e) {
    console.error(`WARNING: could not read/parse ${KEYS_FILE}: ${e.message}`);
  }
  return {};
}

// ── in-memory per-key daily budget tracking ──────────────────────────────────
// Single-instance gateway, so an in-memory counter is sufficient — no Redis.
// Resets naturally every UTC day via the dayKey() bucket below.
const usage = new Map(); // `${label}:${dayKey}` -> request count

function dayKey() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
}

function checkAndIncrementBudget(label, dailyBudget) {
  const key = `${label}:${dayKey()}`;
  const count = usage.get(key) || 0;
  if (count >= dailyBudget) return false;
  usage.set(key, count + 1);
  return true;
}

// ── access logging (metadata only — never request/response content) ────────
function logRequest(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
  fs.appendFile(LOG_FILE, line, (err) => {
    if (err) console.error(`WARNING: failed to write access log: ${err.message}`);
  });
}

// ── helpers ───────────────────────────────────────────────────────────────────
function jsonResponse(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      // Guard against unbounded request bodies.
      if (body.length > 1_000_000) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

/**
 * Authenticate a request against keys.json.
 * Returns { label, dailyBudget } on success, or null (caller sends 401).
 */
function authenticate(req) {
  const auth = req.headers['authorization'] || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const virtualKey = match[1].trim();
  const keys = loadKeys();
  const entry = keys[virtualKey];
  if (!entry) return null;
  return { label: entry.label || 'unknown', dailyBudget: entry.dailyBudget ?? 200 };
}

// ── Veynora call (same translation as veynora-adapter.js, non-streaming only) ─
async function callVeynora(model, messages, maxTokens, system) {
  const body = {
    model,
    messages,
    max_tokens: maxTokens,
    ...(system ? { system } : {}),
  };

  const res = await fetch(`${VEYNORA_BASE}/proxy/v1/messages`, {
    method: 'POST',
    headers: {
      'x-api-key': VEYNORA_KEY,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(body),
  });

  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(`Veynora ${res.status}`), { data, status: res.status });

  const text = Array.isArray(data.content)
    ? data.content.filter((b) => b && b.type === 'text').map((b) => b.text).join('\n')
    : '';

  return {
    text,
    inputTokens: data.usage?.input_tokens ?? 0,
    outputTokens: data.usage?.output_tokens ?? 0,
  };
}

// ── route handlers ────────────────────────────────────────────────────────────
function handleModels(req, res) {
  jsonResponse(res, 200, { object: 'list', data: MODELS });
}

async function handleChatCompletions(req, res) {
  const started = Date.now();
  const auth = authenticate(req);
  if (!auth) {
    jsonResponse(res, 401, { error: { message: 'Missing or invalid API key' } });
    return;
  }

  let oai;
  try {
    oai = JSON.parse(await readBody(req));
  } catch (e) {
    jsonResponse(res, 400, { error: { message: `Invalid JSON body: ${e.message}` } });
    return;
  }

  // Prodogy's enricher never streams or uses tools (see _call_llm in
  // enricher.py) — reject anything that does rather than silently
  // mishandling it, so a misconfigured client fails loudly. Checked before
  // the budget debit below so a malformed/unsupported request never costs
  // the caller quota.
  if (oai.stream) {
    jsonResponse(res, 400, { error: { message: 'Streaming is not supported by this gateway' } });
    return;
  }
  if (Array.isArray(oai.tools) && oai.tools.length > 0) {
    jsonResponse(res, 400, { error: { message: 'Tool calling is not supported by this gateway' } });
    return;
  }

  if (!checkAndIncrementBudget(auth.label, auth.dailyBudget)) {
    logRequest({ label: auth.label, status: 429, reason: 'daily_budget_exceeded' });
    jsonResponse(res, 429, {
      error: { message: `Daily budget exceeded for '${auth.label}'. Try again tomorrow (UTC).` },
    });
    return;
  }

  const maxTokens = Math.min(oai.max_tokens || 4096, 10240);
  const system = oai.messages?.find((m) => m.role === 'system')?.content || undefined;
  const messages = (oai.messages || [])
    .filter((m) => m.role !== 'system')
    .map((m) => ({
      role: m.role,
      content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
    }));

  let result;
  try {
    result = await callVeynora(oai.model, messages, maxTokens, system);
  } catch (e) {
    const status = e.status && e.status >= 400 && e.status < 600 ? 502 : 502;
    logRequest({
      label: auth.label,
      model: oai.model,
      status,
      error: e.message,
      latencyMs: Date.now() - started,
    });
    jsonResponse(res, status, { error: { message: `Upstream error: ${e.message}` } });
    return;
  }

  logRequest({
    label: auth.label,
    model: oai.model,
    status: 200,
    promptTokens: result.inputTokens,
    completionTokens: result.outputTokens,
    latencyMs: Date.now() - started,
  });

  jsonResponse(res, 200, {
    id: `chatcmpl-gw-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: oai.model,
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content: result.text },
        finish_reason: 'stop',
      },
    ],
    usage: {
      prompt_tokens: result.inputTokens,
      completion_tokens: result.outputTokens,
      total_tokens: result.inputTokens + result.outputTokens,
    },
  });
}

function handleHealth(req, res) {
  jsonResponse(res, 200, { status: 'ok' });
}

// ── server ────────────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const { method, url } = req;

  if (method === 'GET' && url === '/healthz') return handleHealth(req, res);
  if (method === 'GET' && url === '/v1/models') return handleModels(req, res);
  if (method === 'POST' && url === '/v1/chat/completions') {
    handleChatCompletions(req, res).catch((e) => {
      console.error('Unhandled error:', e);
      jsonResponse(res, 500, { error: { message: 'Internal gateway error' } });
    });
    return;
  }

  jsonResponse(res, 404, { error: { message: `Cannot ${method} ${url}` } });
});

server.listen(PORT, () => {
  console.log(`Prodogy Gateway listening on http://0.0.0.0:${PORT}/v1`);
  console.log(`Proxying to: ${VEYNORA_BASE}`);
  console.log(`Keys file:   ${KEYS_FILE}`);
  console.log(`Access log:  ${LOG_FILE}`);
});
