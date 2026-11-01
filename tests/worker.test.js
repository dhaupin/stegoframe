/**
 * Stegoframe worker tests — the HTML lane's env injection + rate limiting,
 * driven in-process against a canned ASSETS fixture (no sockets, no network).
 * Run with: npm test
 *
 * Covers the two stegoframe#7 findings: replacement-pattern mangling in the
 * env substitution, and the client-spoofable rate-limit key.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import worker from '../_worker.js';

const REAL_FETCH = globalThis.fetch;

before(() => {
  // pingSupabase is best-effort and fire-and-forget; keep it in-process so a
  // test never opens a socket to a fake Supabase host.
  globalThis.fetch = async () => new Response('', { status: 200 });
});
after(() => {
  globalThis.fetch = REAL_FETCH;
});

function makeKv() {
  const store = new Map();
  return {
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
  };
}

function makeEnv({ url = 'https://proj.supabase.co', anon = 'sb_publishable_x', html = '<html>{{SUPA_URL}}|{{SUPA_ANON}}</html>', kv = true } = {}) {
  const env = {
    SUPA_URL: url,
    SUPA_ANON: anon,
    ASSETS: {
      async fetch(req) {
        const path = new URL(req.url).pathname;
        if (path === '/' || path === '/index.html') {
          return new Response(html, { status: 200, headers: { 'content-type': 'text/html', etag: 'W/"canary"' } });
        }
        return new Response(`asset:${path}`, { status: 200, headers: { 'content-type': 'application/javascript' } });
      },
    },
  };
  if (kv) env.SF_KV = makeKv();
  return env;
}

function pageRequest(headers = {}) {
  return new Request('https://stegoframe.test/', { headers });
}

const ctx = { waitUntil() {} };

describe('env injection (placeholder substitution)', () => {
  it('substitutes each placeholder exactly once and leaves none behind', async () => {
    const env = makeEnv({ url: 'https://abc.supabase.co', anon: 'sb_publishable_ok' });
    const res = await worker.fetch(pageRequest(), env, ctx);
    const body = await res.text();
    assert.strictEqual(body, '<html>https://abc.supabase.co|sb_publishable_ok</html>');
    assert.ok(!body.includes('{{SUPA_URL}}') && !body.includes('{{SUPA_ANON}}'));
  });

  it('inserts a value containing $& literally (no placeholder re-emission)', async () => {
    const env = makeEnv({ url: 'https://x.supabase.co/$&-EVIL' });
    const body = await (await worker.fetch(pageRequest(), env, ctx)).text();
    assert.ok(body.includes('https://x.supabase.co/$&-EVIL'), 'the $& value must land literally');
    assert.ok(!body.includes('{{SUPA_URL}}'), 'the placeholder must not survive');
  });

  it('inserts a value containing $\' literally (no document-tail splice)', async () => {
    const env = makeEnv({ anon: "sb_publishable_x-$'" });
    const body = await (await worker.fetch(pageRequest(), env, ctx)).text();
    assert.ok(body.includes("sb_publishable_x-$'"), "the $' value must land literally");
    assert.ok(!body.includes('{{SUPA_ANON}}'), 'the placeholder must not survive');
    // The $' pattern would have spliced the whole document tail in after the
    // match, ballooning the page; a literal insert keeps it one page.
    assert.strictEqual(body.match(/<\/html>/g)?.length ?? 0, body.includes('</html>') ? 1 : 0);
  });

  it('preserves the asset status and headers through injection', async () => {
    const env = makeEnv();
    const res = await worker.fetch(pageRequest(), env, ctx);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('etag'), 'W/"canary"');
    assert.strictEqual(res.headers.get('content-type'), 'text/html');
  });

  it('passes non-HTML requests straight to ASSETS untouched', async () => {
    const env = makeEnv();
    const res = await worker.fetch(new Request('https://stegoframe.test/app.js'), env, ctx);
    assert.strictEqual(await res.text(), 'asset:/app.js');
  });
});

describe('rate limiting', () => {
  it('wraps one IP at hit 21 with Retry-After 60', async () => {
    const env = makeEnv();
    const headers = { 'CF-Connecting-IP': '203.0.113.7' };
    let firstBlock = null;
    for (let i = 1; i <= 25; i++) {
      const res = await worker.fetch(pageRequest(headers), env, ctx);
      if (res.status === 429 && firstBlock === null) firstBlock = i;
    }
    assert.strictEqual(firstBlock, 21, 'the documented wall is exact');
    const blocked = await worker.fetch(pageRequest(headers), env, ctx);
    assert.strictEqual(blocked.headers.get('Retry-After'), '60');
  });

  it('enforces the same wall in the in-memory fallback', async () => {
    const env = makeEnv({ kv: false });
    const headers = { 'CF-Connecting-IP': '198.51.100.9' };
    let firstBlock = null;
    for (let i = 1; i <= 25; i++) {
      const res = await worker.fetch(pageRequest(headers), env, ctx);
      if (res.status === 429 && firstBlock === null) firstBlock = i;
    }
    assert.strictEqual(firstBlock, 21);
  });

  it('rotating CF-Connecting-IP gives every request a fresh bucket (documented trust boundary)', async () => {
    const env = makeEnv();
    for (let i = 0; i < 30; i++) {
      const res = await worker.fetch(pageRequest({ 'CF-Connecting-IP': `203.0.113.${i}` }), env, ctx);
      assert.strictEqual(res.status, 200, 'a rotated CF edge IP defeats the limit — expected off-CF, documented in the worker header');
    }
  });

  it('does not trust a header only the client can supply (X-Forwarded-For)', async () => {
    // Two different XFF values with no CF header both key to "unknown" and
    // therefore SHARE the bucket — a spoofed XFF cannot mint a new one.
    const env = makeEnv();
    let firstBlock = null;
    for (let i = 1; i <= 25; i++) {
      const res = await worker.fetch(pageRequest({ 'X-Forwarded-For': `10.0.0.${i}` }), env, ctx);
      if (res.status === 429 && firstBlock === null) firstBlock = i;
    }
    assert.strictEqual(firstBlock, 21, 'a client-supplied XFF must not rotate the bucket');
  });

  it('falls back to CF-Pseudo-IPv4 when CF-Connecting-IP is absent', async () => {
    const env = makeEnv();
    let firstBlock = null;
    for (let i = 1; i <= 25; i++) {
      const res = await worker.fetch(pageRequest({ 'CF-Pseudo-IPv4': '203.0.113.50' }), env, ctx);
      if (res.status === 429 && firstBlock === null) firstBlock = i;
    }
    assert.strictEqual(firstBlock, 21);
  });
});
