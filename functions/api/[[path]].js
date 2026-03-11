export async function onRequest(context) {
  const { request, env } = context;
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
  
  // Remove headers that might interfere with the proxy handshake
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
