export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // 1. Handle CORS Preflight immediately
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // 2. Prepare the base Supabase URL (no trailing slash)
  const supabaseBase = env.SUPA_URL.replace(/\/$/, '');
  const path = url.pathname.replace('/api', '');

  // 3. Handle WebSocket Upgrades (Realtime)
  // Must happen before any request body is touched
  if (request.headers.get("Upgrade") === "websocket") {
    const wsUrl = `${supabaseBase.replace('http', 'ws')}${path}${url.search}`;
    return fetch(wsUrl, {
      headers: request.headers,
      webSocket: true,
    });
  }

  // 4. Prepare REST Request
  const targetUrl = `${supabaseBase}${path}${url.search}`;
  const newHeaders = new Headers(request.headers);
  
  // Inject Secrets from Cloudflare Env
  newHeaders.set("apikey", env.SUPA_ANON);
  newHeaders.set("Authorization", `Bearer ${env.SUPA_ANON}`);
  
  // Bypass Browser Detection / Security blocks
  newHeaders.delete("origin");
  newHeaders.delete("referer");
  newHeaders.delete("host");
  newHeaders.set("User-Agent", "Stegoframe-Proxy/1.0");

  const fetchOptions = {
    method: request.method,
    headers: newHeaders,
    // Only include body if not GET/HEAD
    body: (request.method !== 'GET' && request.method !== 'HEAD') ? request.body : null,
    duplex: 'half'
  };

  return fetch(targetUrl, fetchOptions);
}
