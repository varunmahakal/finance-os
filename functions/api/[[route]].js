// Finance OS — Cloudflare Pages Functions
// Catch-all handler for all /api/* routes
// No npm dependencies — uses Web Crypto API (available in Workers runtime)

// ═══════════════════════════════════════
//  CRYPTO HELPERS
// ═══════════════════════════════════════

// 10,000 iterations keeps CPU time well under Cloudflare Workers' 10ms free-plan limit.
// Security model: PIN is a UI gate on a personal single-user app; SESSION_SECRET
// protects server-side token forgery regardless of PIN hash strength.
const PBKDF2_ITERATIONS = 10_000;

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return arr;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPin(pin, saltHex) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

// Constant-time hex string comparison to prevent timing attacks
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function createSessionToken(secret) {
  const payload = {
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
    rand: bytesToHex(crypto.getRandomValues(new Uint8Array(16)))
  };
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${payloadB64}.${sigB64}`;
}

async function verifySessionToken(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigB64] = parts;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    // Re-pad base64url back to standard base64
    const pad = s => s + '='.repeat((4 - s.length % 4) % 4);
    const sigBytes = Uint8Array.from(atob(pad(sigB64.replace(/-/g, '+').replace(/_/g, '/'))), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payloadB64));
    if (!valid) return null;
    const payload = JSON.parse(atob(pad(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))));
    if (payload.exp < Date.now()) return null; // expired
    return payload;
  } catch (e) {
    return null;
  }
}

// Parse cookie header into an object
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) cookies[k.trim()] = v.join('=').trim();
  }
  return cookies;
}

// ═══════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════

async function requireAuth(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const token = cookies['session'];
  const payload = await verifySessionToken(token, env.SESSION_SECRET);
  if (!payload) return json({ error: 'Unauthorized' }, 401);
  return payload; // truthy = authenticated
}

// ═══════════════════════════════════════
//  RESPONSE HELPERS
// ═══════════════════════════════════════

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}

function sessionCookieHeader(token) {
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`;
}

function clearCookieHeader() {
  return `session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

function defaultSettings() {
  return {
    salary: 35000, bills: 10000, food: 4000, travel: 3000,
    petrol: 3000, emi: 2700, sip: 2000, subs: 1000,
    saveMo: 4000, savings: 30000, iphoneGoal: 89999, appraisal: 7
  };
}

// ═══════════════════════════════════════
//  ROUTE HANDLERS
// ═══════════════════════════════════════

// POST /api/auth/setup — first-time PIN registration
async function handleSetup(request, env) {
  // Only allowed if no auth row exists yet
  const existing = await env.DB.prepare('SELECT id FROM auth WHERE id = 1').first();
  if (existing) return json({ error: 'PIN already configured' }, 403);

  const body = await request.json().catch(() => ({}));
  const { pin } = body;
  if (!pin || !/^\d{4,8}$/.test(pin)) return json({ error: 'PIN must be 4–8 digits' }, 400);

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = bytesToHex(saltBytes);
  const hashHex = await hashPin(pin, saltHex);

  await env.DB.prepare('INSERT INTO auth (id, salt, hash) VALUES (1, ?, ?)').bind(saltHex, hashHex).run();
  return json({ ok: true });
}

// POST /api/auth/login — validate PIN and set session cookie
async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const { pin } = body;
  if (!pin) return json({ error: 'PIN required' }, 400);

  const row = await env.DB.prepare('SELECT salt, hash FROM auth WHERE id = 1').first();
  if (!row) return json({ error: 'PIN not set up yet — call /api/auth/setup first' }, 401);

  const derived = await hashPin(pin, row.salt);
  if (!timingSafeEqual(derived, row.hash)) return json({ error: 'Wrong PIN' }, 401);

  const token = await createSessionToken(env.SESSION_SECRET);
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookieHeader(token) });
}

// POST /api/auth/logout — clear session cookie
async function handleLogout() {
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookieHeader() });
}

// GET /api/state — return full app state
async function handleGetState(env) {
  const appState = await env.DB.prepare('SELECT settings, pending FROM app_state WHERE id = 1').first();
  const { results } = await env.DB.prepare(
    'SELECT id, month_key, cat, amt, note, ts, confirmed_at FROM expenses ORDER BY ts ASC'
  ).all();

  // Reconstruct expenses object { "YYYY-MM": [{...}, ...] }
  const expenses = {};
  for (const row of results) {
    if (!expenses[row.month_key]) expenses[row.month_key] = [];
    expenses[row.month_key].push({
      id: Number(row.id),
      cat: row.cat,
      amt: row.amt,
      note: row.note,
      ts: row.ts,
      confirmedAt: row.confirmed_at || undefined
    });
  }

  return json({
    settings: appState ? JSON.parse(appState.settings) : defaultSettings(),
    expenses,
    pending: appState ? JSON.parse(appState.pending) : []
  });
}

// PUT /api/state — full-replace state (DELETE all + batch INSERT)
async function handlePutState(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== 'object') return json({ error: 'Invalid body' }, 400);

  const { settings, expenses, pending } = body;

  const stmts = [
    env.DB.prepare('DELETE FROM expenses'),
    env.DB.prepare('INSERT OR REPLACE INTO app_state (id, settings, pending) VALUES (1, ?, ?)')
      .bind(JSON.stringify(settings || defaultSettings()), JSON.stringify(pending || []))
  ];

  // Batch insert all expense entries
  for (const [monthKey, entries] of Object.entries(expenses || {})) {
    if (!Array.isArray(entries)) continue;
    for (const e of entries) {
      stmts.push(
        env.DB.prepare(
          'INSERT INTO expenses (id, month_key, cat, amt, note, ts, confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(
          String(e.id), monthKey, e.cat, e.amt,
          e.note || '', e.ts, e.confirmedAt || e.confirmed_at || null
        )
      );
    }
  }

  await env.DB.batch(stmts);
  return json({ ok: true });
}

// POST /api/migrate — one-time import from localStorage blob
async function handleMigrate(request, env) {
  const body = await request.json().catch(() => null);
  if (!body) return json({ error: 'Invalid body' }, 400);

  // Count expenses for response
  let expenseCount = 0;
  for (const entries of Object.values(body.expenses || {})) {
    if (Array.isArray(entries)) expenseCount += entries.length;
  }

  // Reuse put state logic
  const putResp = await handlePutState(
    new Request(request.url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }),
    env
  );
  if (!putResp.ok) return putResp;

  return json({ ok: true, expenseCount });
}

// ═══════════════════════════════════════
//  MAIN ROUTER
// ═══════════════════════════════════════

export async function onRequest(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight (useful during local dev with wrangler pages dev)
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }

    // Health check — no bindings needed, useful for diagnosing missing bindings
    if (path === '/api/health') {
      return json({
        ok: true,
        hasDB: !!env.DB,
        hasSecret: !!env.SESSION_SECRET,
        bindings: Object.keys(env).filter(k => !k.startsWith('CF_'))
      });
    }

    // ── Unauthenticated auth routes ──
    if (path === '/api/auth/setup' && method === 'POST') return handleSetup(request, env);
    if (path === '/api/auth/login' && method === 'POST')  return handleLogin(request, env);
    if (path === '/api/auth/logout' && method === 'POST') return handleLogout();

    // ── Session-protected routes ──
    const session = await requireAuth(request, env);
    if (session instanceof Response) return session; // 401

    if (path === '/api/state' && method === 'GET') return handleGetState(env);
    if (path === '/api/state' && method === 'PUT') return handlePutState(request, env);
    if (path === '/api/migrate' && method === 'POST') return handleMigrate(request, env);

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    // Surface the real error instead of Cloudflare's generic 1101
    return new Response(JSON.stringify({ error: 'Internal error', details: e.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
