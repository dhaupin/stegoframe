/**
 * Stegoframe — Cloudflare Pages Worker
 * ──────────────────────────────────────────────────────────────────────────────
 * Two responsibilities:
 *
 *   1. ENV INJECTION — substitutes {{SUPA_URL}} and {{SUPA_ANON}} placeholders
 *      in index.html at request time using Cloudflare Pages environment variables.
 *      Keeps credentials out of source control without a build step.
 *
 *   2. RATE LIMITING — enforces per-IP request limits using a KV namespace to
 *      prevent bots and abuse from exhausting Supabase free-tier quotas.
 *      Limits are applied to all HTML page loads (room joins/creates).
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
 * For rate limiting, create a KV namespace named "SF_RL" and bind it:
 *   Settings → Functions → KV namespace bindings → Add:
 *     Variable name: SF_RL
 *     KV namespace:  stegoframe-rate-limit   (or any name you choose)
 *
 * If SF_RL is not bound, rate limiting is silently skipped (graceful degradation).
 *
 * ── Rate limit behaviour ──────────────────────────────────────────────────────
 * Window:   60 seconds (sliding, reset per window)
 * Limit:    20 requests per IP per window
 * Response: 429 with Retry-After header on breach
 * Storage:  KV key "rl:{ip}" with 60-second TTL — auto-expires, no cleanup needed
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only intercept the HTML document. All other assets (JS, fonts, CDN
    // requests) either go directly to their origin or pass through Pages'
    // asset pipeline unchanged. This worker is never in the path after page load.
    const isHtml = url.pathname === "/" || url.pathname === "/index.html";

    if (isHtml) {
      // ── Rate limit check ────────────────────────────────────────────────────
      // Skip gracefully if KV namespace is not bound (local dev, misconfigured env).
      if (env.SF_RL) {
        const ip  = request.headers.get("CF-Connecting-IP") ?? "unknown";
        const key = `rl:${ip}`;

        try {
          const raw   = await env.SF_RL.get(key);
          const hits  = raw ? parseInt(raw, 10) : 0;

          if (hits >= RL_MAX_HITS) {
            // Over limit — return 429 with a Retry-After hint
            return new Response("Too Many Requests", {
              status: 429,
              headers: {
                "Retry-After":  String(RL_WINDOW_SEC),
                "Content-Type": "text/plain",
              },
            });
          }

          // Increment counter. ctx.waitUntil ensures the KV write completes
          // even if the response is sent first (non-blocking fast path).
          ctx.waitUntil(
            env.SF_RL.put(key, String(hits + 1), { expirationTtl: RL_WINDOW_SEC })
          );
        } catch (e) {
          // KV errors (quota, transient) — fail open so the app stays available.
          console.error("SF_RL rate limit error:", e);
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
