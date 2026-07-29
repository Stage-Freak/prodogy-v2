/**
 * Veynora → OpenAI-compatible adapter with tool-calling support
 *
 * Since Veynora strips the `tools` field before hitting Bedrock, this adapter:
 *   1. Injects tool definitions into the system prompt as JSON schema
 *   2. Instructs the model to respond with a special XML tag when it wants to call a tool
 *   3. Parses the model's text response and converts tool calls into OpenAI tool_call chunks
 *   4. OpenCode receives proper tool_calls and executes them natively
 *
 * Usage: node veynora-adapter.js  (reads .env automatically)
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');

// ── load .env ─────────────────────────────────────────────────────────────────
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const eq = trimmed.indexOf('=');
    if (eq === -1) return;
    process.env[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  });
  console.log(`Loaded .env from ${envPath}`);
}

const VEYNORA_BASE = (process.env.VEYNORA_BASE_URL || 'https://veynoraai-backend-ene8hfb7fjaacrbs.centralindia-01.azurewebsites.net').replace(/\/+$/, '');
const VEYNORA_KEY  = process.env.VEYNORA_API_KEY || '';
const PORT         = parseInt(process.env.PORT || '4099', 10);

const MODELS = [
  { id: 'Claude Haiku 4.5',  object: 'model', owned_by: 'anthropic' },
  { id: 'Amazon Nova Pro',   object: 'model', owned_by: 'amazon' },
  { id: 'Amazon Nova Lite',  object: 'model', owned_by: 'amazon' },
  { id: 'Amazon Nova Micro', object: 'model', owned_by: 'amazon' },
];

// ── helpers ───────────────────────────────────────────────────────────────────

function jsonResponse(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end',  () => resolve(body));
    req.on('error', reject);
  });
}

/**
 * Build a system prompt addendum that teaches the model how to call tools.
 * The model must respond with <tool_call> XML when it wants to use a tool.
 */
function buildToolSystemPrompt(tools) {
  if (!tools || tools.length === 0) return '';

  const toolDefs = tools.map(t => {
    const fn = t.function || t;
    return `### ${fn.name}\nDescription: ${fn.description || ''}\nParameters (JSON schema): ${JSON.stringify(fn.parameters || {}, null, 2)}`;
  }).join('\n\n');

  return `\n\n---\nYou have access to the following tools. When you need to use a tool, you MUST respond with ONLY a <tool_call> block and nothing else. Do not add any explanation before or after the tool call.\n\nFormat:\n<tool_call>\n{"name": "tool_name", "arguments": {...}}\n</tool_call>\n\nAfter the tool result is returned, continue your response normally.\n\nAvailable tools:\n${toolDefs}\n---`;
}

/**
 * Parse text response looking for <tool_call>...</tool_call>.
 * Returns { toolCall: {name, arguments} | null, textBefore: string }
 */
function parseToolCall(text) {
  const match = text.match(/<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/i);
  if (!match) return { toolCall: null, textBefore: text };

  try {
    const parsed = JSON.parse(match[1]);
    const textBefore = text.slice(0, match.index).trim();
    return { toolCall: parsed, textBefore };
  } catch {
    return { toolCall: null, textBefore: text };
  }
}

// ── SSE helpers ───────────────────────────────────────────────────────────────

function sseWrite(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function makeChunk(model, delta, finishReason = null, usage = null) {
  const chunk = {
    id: `chatcmpl-veynora-${Date.now()}`,
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  };
  if (usage) chunk.usage = usage;
  return chunk;
}

function streamText(res, text, model) {
  // Role opener
  sseWrite(res, makeChunk(model, { role: 'assistant', content: '' }));
  // Content in chunks
  const SIZE = 20;
  for (let i = 0; i < text.length; i += SIZE) {
    sseWrite(res, makeChunk(model, { content: text.slice(i, i + SIZE) }));
  }
}

function streamToolCall(res, toolCall, model) {
  const callId = `call_${Date.now()}`;
  // Role opener with tool_calls
  sseWrite(res, makeChunk(model, {
    role: 'assistant',
    content: null,
    tool_calls: [{
      index: 0,
      id: callId,
      type: 'function',
      function: { name: toolCall.name, arguments: '' },
    }],
  }));
  // Stream the arguments JSON
  const argsStr = JSON.stringify(toolCall.arguments || {});
  const SIZE = 20;
  for (let i = 0; i < argsStr.length; i += SIZE) {
    sseWrite(res, makeChunk(model, {
      tool_calls: [{
        index: 0,
        function: { arguments: argsStr.slice(i, i + SIZE) },
      }],
    }));
  }
}

// ── Veynora call ──────────────────────────────────────────────────────────────

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
      'x-api-key':    VEYNORA_KEY,
      'Content-Type': 'application/json',
      Accept:         'application/json',
    },
    body: JSON.stringify(body),
  });

  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(`Veynora ${res.status}`), { data });

  const text = Array.isArray(data.content)
    ? data.content.filter(b => b?.type === 'text').map(b => b.text).join('\n')
    : '';

  return {
    text,
    inputTokens:  data.usage?.input_tokens  ?? 0,
    outputTokens: data.usage?.output_tokens ?? 0,
  };
}

// ── route handlers ────────────────────────────────────────────────────────────

function handleModels(req, res) {
  jsonResponse(res, 200, { object: 'list', data: MODELS });
}

async function handleChatCompletions(req, res) {
  let oai;
  try { oai = JSON.parse(await readBody(req)); }
  catch { return jsonResponse(res, 400, { error: 'Invalid JSON body' }); }

  const streaming  = oai.stream === true;
  const tools      = oai.tools || [];
  const hasTools   = tools.length > 0;
  const maxTokens  = Math.min(oai.max_tokens || 4096, 10240);

  // Extract system prompt; append tool instructions if tools present
  let system = oai.messages?.find(m => m.role === 'system')?.content || '';
  if (hasTools) system += buildToolSystemPrompt(tools);

  // Build messages (no system role, coerce content to string)
  const messages = (oai.messages || [])
    .filter(m => m.role !== 'system')
    .map(m => {
      // Convert tool result messages → user messages so Veynora accepts them
      if (m.role === 'tool') {
        return { role: 'user', content: `Tool result for ${m.name || 'tool'}: ${typeof m.content === 'string' ? m.content : JSON.stringify(m.content)}` };
      }
      // Convert assistant tool_calls messages back to text so context is preserved
      if (m.role === 'assistant' && m.tool_calls) {
        const calls = m.tool_calls.map(tc => `<tool_call>\n${JSON.stringify({ name: tc.function.name, arguments: JSON.parse(tc.function.arguments || '{}') })}\n</tool_call>`).join('\n');
        return { role: 'assistant', content: calls };
      }
      return {
        role: m.role,
        content: typeof m.content === 'string' ? m.content : JSON.stringify(m.content),
      };
    });

  console.log(`→ Veynora  model="${oai.model}"  msgs=${messages.length}  tools=${tools.length}  stream=${streaming}`);

  let result;
  try {
    result = await callVeynora(oai.model, messages, maxTokens, system || undefined);
  } catch (e) {
    console.error('Veynora error:', e.message);
    if (streaming) {
      res.writeHead(502, { 'Content-Type': 'text/event-stream' });
      return res.end(`data: ${JSON.stringify({ error: e.message })}\n\n`);
    }
    return jsonResponse(res, 502, { error: { message: e.message } });
  }

  console.log(`← OK  in=${result.inputTokens}  out=${result.outputTokens}`);

  const { toolCall, textBefore } = hasTools
    ? parseToolCall(result.text)
    : { toolCall: null, textBefore: result.text };

  if (toolCall) console.log(`  ↳ tool_call: ${toolCall.name}(${JSON.stringify(toolCall.arguments)})`);

  const usage = {
    prompt_tokens:     result.inputTokens,
    completion_tokens: result.outputTokens,
    total_tokens:      result.inputTokens + result.outputTokens,
  };

  if (streaming) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });

    if (toolCall) {
      // Stream any preamble text first
      if (textBefore) streamText(res, textBefore, oai.model);
      // Then stream the tool call
      streamToolCall(res, toolCall, oai.model);
      // Finish with tool_calls stop reason
      sseWrite(res, makeChunk(oai.model, {}, 'tool_calls', usage));
    } else {
      // Pure text response
      streamText(res, result.text, oai.model);
      sseWrite(res, makeChunk(oai.model, {}, 'stop', usage));
    }

    res.write('data: [DONE]\n\n');
    res.end();

  } else {
    // Non-streaming
    if (toolCall) {
      jsonResponse(res, 200, {
        id: `chatcmpl-veynora-${Date.now()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: oai.model,
        choices: [{
          index: 0,
          message: {
            role: 'assistant',
            content: null,
            tool_calls: [{
              id: `call_${Date.now()}`,
              type: 'function',
              function: {
                name: toolCall.name,
                arguments: JSON.stringify(toolCall.arguments || {}),
              },
            }],
          },
          finish_reason: 'tool_calls',
        }],
        usage,
      });
    } else {
      jsonResponse(res, 200, {
        id: `chatcmpl-veynora-${Date.now()}`,
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: oai.model,
        choices: [{
          index: 0,
          message: { role: 'assistant', content: result.text },
          finish_reason: 'stop',
        }],
        usage,
      });
    }
  }
}

// ── server ────────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const { method, url } = req;
  console.log(`${method} ${url}`);

  if (method === 'GET'  && url === '/v1/models')           return handleModels(req, res);
  if (method === 'POST' && url === '/v1/chat/completions') return handleChatCompletions(req, res);

  jsonResponse(res, 404, { error: `Cannot ${method} ${url}` });
});

server.listen(PORT, () => {
  console.log(`\nVeynora adapter  →  http://localhost:${PORT}/v1`);
  console.log(`Proxying to: ${VEYNORA_BASE}\n`);
});
