export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '');
  const supabaseUrl = new URL(`${env.SUPA_URL}${path}${url.search}`);

  // Handle WebSockets for Realtime
  if (request.headers.get("Upgrade") === "websocket") {
    supabaseUrl.protocol = supabaseUrl.protocol.replace('http', 'ws');
    return fetch(supabaseUrl.toString(), {
      headers: request.headers,
      webSocket: true,
    });
  }

  // Inject the NEW secret key into the headers
  const newHeaders = new Headers(request.headers);
  newHeaders.set("apikey", env.SUPA_ANON);
  newHeaders.set("Authorization", `Bearer ${env.SUPA_ANON}`);

  return fetch(new Request(supabaseUrl.toString(), {
    method: request.method,
    headers: newHeaders,
    body: request.body,
    duplex: 'half'
  }));
}
