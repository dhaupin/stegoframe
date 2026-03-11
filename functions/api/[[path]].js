export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey",
      },
    });
  }

  const supabaseBase = env.SUPA_URL.replace(/\/$/, '');
  const path = url.pathname.replace('/api', '');

  // IMPROVED WEBSOCKET PROXY
  // Handle WebSocket Upgrades (Realtime)
  if (request.headers.get("Upgrade") === "websocket") {
    // This maps /api/realtime/v1/websocket -> /realtime/v1/websocket on Supabase
    const supaWS = env.SUPA_URL.replace('http', 'ws').replace(/\/$/, '');
    const wsTarget = `${supaWS}${path}${url.search}`;
    
    return fetch(wsTarget, {
      headers: request.headers,
      webSocket: true,
    });
  }

  // REST PROXY
  const targetUrl = `${supabaseBase}${path}${url.search}`;
  const newHeaders = new Headers(request.headers);
  newHeaders.set("apikey", env.SUPA_ANON);
  newHeaders.set("Authorization", `Bearer ${env.SUPA_ANON}`);
  newHeaders.delete("origin");
  newHeaders.delete("referer");
  newHeaders.delete("host");
  newHeaders.set("User-Agent", "Stegoframe-Proxy/1.0");

  return fetch(targetUrl, {
    method: request.method,
    headers: newHeaders,
    body: (request.method !== 'GET' && request.method !== 'HEAD') ? request.body : null,
    duplex: 'half'
  });
}
