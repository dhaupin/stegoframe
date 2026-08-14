/**
 * Stegoframe — Cloudflare Pages Worker
 * ──────────────────────────────────────────────────────────────────────────────
 * Two responsibilities:
 *
 *   1. ENV INJECTION — substitutes {{SUPA_URL}} and {{SUPA_ANON}} placeholders
 *      in index.html at request time using Cloudflare Pages environment variables.
 *      Keeps credentials out of source control without a build step.
 *
 *   2. RATE LIMITING — enforces per-IP request limits to prevent bots and abuse.
 *      Uses KV when available (distributed, persistent).
 *      Falls back to in-memory tracking (per-instance, basic protection).
 *
 * ── Why direct connection (no proxy) ─────────────────────────────────────────
 * Supabase Realtime uses persistent WebSocket connections that go from the
 * browser directly to Supabase's servers. Cloudflare Pages Functions cannot
 * upgrade HTTP connections to WebSockets (no Durable Objects available in
 * Pages). Proxying REST calls through this worker is possible but pointless —
 * the anon key is public by design. After page load this worker is not in the
 * request path at all.
 *
 * ── Cloudflare Pages dashboard setup ─────────────────────────────────────────
 * Settings → Environment variables → Add (both Production and Preview):
 *
 *   SUPA_URL   = https://your-project-id.supabase.co
 *   SUPA_ANON  = sb_publishable_...   (publishable/anon key — NOT the secret key)
 *
 * For KV-based rate limiting (recommended for production):
 *   Create a KV namespace and bind it as SF_KV.
 *   If not bound, falls back to in-memory rate limiting.
 *
 * ── Rate limit behaviour ──────────────────────────────────────────────────────
 * Window:   60 seconds (sliding, reset per window)
 * Limit:    20 requests per IP per window
 * Response: 429 with Retry-After header on breach
 *
 * KV mode:   key "rl:{ip}" with 60-second TTL — distributed across edge nodes
 * Memory mode: in-memory Map — works without KV but per-instance only
 *
 * This limit applies to HTML page loads only, not to Supabase API calls (which
 * go directly from the browser). For Supabase-level rate limiting, use Supabase
 * dashboard → API settings → rate limits, or add a Postgres function with
 * pg_cron to purge expired rooms automatically.
 *
 * ── This file ─────────────────────────────────────────────────────────────────
 * Must be named _worker.js at the repo root. Cloudflare Pages picks it up
 * automatically — no wrangler.toml configuration needed for Pages projects.
 */

// ── Rate limit constants ──────────────────────────────────────────────────────
const RL_WINDOW_SEC = 60;   // sliding window duration in seconds
const RL_MAX_HITS   = 20;   // maximum page loads per IP per window

// ── In-memory fallback rate limiter (when KV unavailable) ────────────────────
const _memRl = new Map();

// ══════════════════════════════════════════════════════════════════════════════
// KEEPALIVE PING — prevents Supabase free tier from pausing
// ──────────────────────────────────────────────────────────────────────────────
// Runs on every HTML request. A simple SELECT 1 keeps the DB awake.
// ══════════════════════════════════════════════════════════════════════════════
async function pingSupabase(env) {
  if (!env.SUPA_URL || !env.SUPA_ANON) return;
  
  try {
    await fetch(`${env.SUPA_URL}/rest/v1/`, {
      method: "HEAD",
      headers: {
        "apikey": env.SUPA_ANON,
        "Authorization": `Bearer ${env.SUPA_ANON}`
      }
    });
  } catch (e) {
    // Silent fail - keepalive is best-effort
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only intercept the HTML document. All other assets (JS, fonts, CDN
    // requests) either go directly to their origin or pass through Pages'
    // asset pipeline unchanged. This worker is never in the path after page load.
    const isHtml = url.pathname === "/" || url.pathname === "/index.html";

    if (isHtml) {
      // Keep Supabase awake on every page visit
      pingSupabase(env);

      // ── Rate limit check ────────────────────────────────────────────────────
      const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const now = Date.now();

      if (env.SF_KV) {
        // KV-based rate limiting (distributed across edge nodes)
        const key = `rl:${ip}`;
        try {
          const raw  = await env.SF_KV.get(key);
          const hits = raw ? parseInt(raw, 10) : 0;

          if (hits >= RL_MAX_HITS) {
            return new Response("Too Many Requests", {
              status: 429,
              headers: { "Retry-After": String(RL_WINDOW_SEC), "Content-Type": "text/plain" },
            });
          }
          ctx.waitUntil(env.SF_KV.put(key, String(hits + 1), { expirationTtl: RL_WINDOW_SEC }));
        } catch (e) {
          console.error("SF_KV rate limit error:", e);
        }
      } else {
        // In-memory fallback (per-instance only, but always-on)
        // Clean up expired entries on each request (lazy cleanup)
        if (_memRl.size > 1000) {
          
          for (const [k, v] of _memRl) {
            if (now - v.windowStart > RL_WINDOW_SEC * 1000) _memRl.delete(k);
          }
        }
        const data = _memRl.get(ip);
        if (data && now - data.windowStart < RL_WINDOW_SEC * 1000) {
          if (data.hits >= RL_MAX_HITS) {
            return new Response("Too Many Requests", {
              status: 429,
              headers: { "Retry-After": String(RL_WINDOW_SEC), "Content-Type": "text/plain" },
            });
          }
          data.hits++;
        } else {
          _memRl.set(ip, { hits: 1, windowStart: now });
        }
      }

      // ── Fetch static asset ──────────────────────────────────────────────────
      const asset = await env.ASSETS.fetch(request);
      if (!asset.ok) return asset; // pass through 404s, etc.

      // ── Substitute environment variable placeholders ─────────────────────────
      // Replace both placeholders in a single pass. If env vars are missing
      // (e.g. not yet configured), substitution produces empty strings and the
      // Supabase client will log a clear error — easier to debug than a cryptic
      // runtime failure.
      let html = await asset.text();
      html = html
        .replace(/\{\{SUPA_URL\}\}/g,  env.SUPA_URL  ?? "")
        .replace(/\{\{SUPA_ANON\}\}/g, env.SUPA_ANON ?? "");

      // Return modified HTML with original status + headers intact
      // (preserves Content-Type, Cache-Control, ETag, etc. from Pages)
      return new Response(html, {
        status:  asset.status,
        headers: asset.headers,
      });
    }

    // All non-HTML requests pass through to the Pages asset pipeline untouched
    return env.ASSETS.fetch(request);
  },
};
