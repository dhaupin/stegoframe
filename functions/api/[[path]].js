export async function onRequest(context) {
  const { request, env } = context;

  // HANDLE CORS PREFLIGHT
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

  const url = new URL(request.url);
  
  // 1. Map the internal path (e.g., /api/rest/v1/messages -> /rest/v1/messages)
  const path = url.pathname.replace('/api', '');
  const supabaseUrl = new URL(`${env.SUPA_URL}${path}${url.search}`);

  // 2. Handle WebSocket Upgrades (Realtime)
  if (request.headers.get("Upgrade") === "websocket") {
    supabaseUrl.protocol = supabaseUrl.protocol.replace('http', 'ws');
    return fetch(supabaseUrl.toString(), {
      headers: request.headers,
      webSocket: true,
    });
  }

  // 3. Prepare the Headers for REST (Injecting Secrets)
  const newHeaders = new Headers(request.headers);
  newHeaders.set("apikey", env.SUPA_ANON);
  newHeaders.set("Authorization", `Bearer ${env.SUPA_ANON}`);
  
  // BYPASS BROWSER DETECTION: 
  // Supabase blocks secret keys if it sees browser-specific headers.
  newHeaders.delete("origin");
  newHeaders.delete("referer");
  newHeaders.set("User-Agent", "Stegoframe-Proxy/1.0");
  
  // Remove host to let Cloudflare set it correctly
  newHeaders.delete("host");

  // 4. Construct the Forwarding Request
  const fetchOptions = {
    method: request.method,
    headers: newHeaders,
    // Only include body if it's not a GET or HEAD request
    body: (request.method !== 'GET' && request.method !== 'HEAD') ? request.body : null,
    duplex: 'half' 
  };

  return fetch(supabaseUrl.toString(), fetchOptions);
}
