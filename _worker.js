/**
 * Stegoframe — Cloudflare Pages Worker
 * ──────────────────────────────────────────────────────────────────────────────
 * Serves static assets normally, but intercepts requests for index.html to
 * substitute {{SUPA_URL}} and {{SUPA_ANON}} placeholders with the actual values
 * from Cloudflare Pages environment variables before delivery.
 *
 * @why  This keeps credentials out of source control without a build step and
 *       without a proxy. The Supabase JS client connects directly to Supabase
 *       from the browser — no tunneling through this worker after page load.
 *       Realtime WebSockets work because they go browser → Supabase directly.
 *
 * Setup in Cloudflare Pages dashboard:
 *   Settings → Environment variables → Add:
 *     SUPA_URL   = https://your-project.supabase.co
 *     SUPA_ANON  = your-anon-key
 *
 * This file must be named _worker.js at the repo root. Cloudflare Pages
 * automatically picks it up — no wrangler.toml needed for Pages projects.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only intercept the HTML document — all other assets (fonts, CDN, etc.)
    // are either external or pass through the Pages asset pipeline unchanged.
    const isHtml = url.pathname === "/" || url.pathname === "/index.html";

    if (isHtml) {
      // Fetch the static asset from Pages' own asset store
      const asset = await env.ASSETS.fetch(request);

      // Guard: if the asset fetch failed for any reason, pass it through as-is
      if (!asset.ok) return asset;

      // Read the HTML text, substitute both placeholders in a single pass
      let html = await asset.text();
      html = html
        .replace(/\{\{SUPA_URL\}\}/g,  env.SUPA_URL  ?? "")
        .replace(/\{\{SUPA_ANON\}\}/g, env.SUPA_ANON ?? "");

      // Return the modified HTML with the original response headers intact
      // (preserves Content-Type, Cache-Control, ETag, etc.)
      return new Response(html, {
        status:  asset.status,
        headers: asset.headers,
      });
    }

    // All non-HTML requests (static assets served by Pages) pass through untouched
    return env.ASSETS.fetch(request);
  },
};
