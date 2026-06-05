const REALM = "docs-test";

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: { "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"` },
  });
}

// Constant-time string comparison to avoid leaking length/content via timing.
function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) {
    diff |= aBytes[i] ^ bBytes[i];
  }

  return diff === 0;
}

export default {
  async fetch(request, env) {

    if (!env.AUTH_USER || !env.AUTH_PASS) {
      return new Response("Auth not configured.", { status: 503 });
    }

    const header = request.headers.get("Authorization") || "";
    const [scheme, encoded] = header.split(" ");
    if (scheme !== "Basic" || !encoded) return unauthorized();

    let user, pass;
    try {
      [user, ...pass] = atob(encoded).split(":");
      pass = pass.join(":");
    } catch {
      return unauthorized();
    }

    const ok =
      timingSafeEqual(user, env.AUTH_USER) &
      timingSafeEqual(pass, env.AUTH_PASS);

    if (!ok) {
      return unauthorized();
    }

    return env.ASSETS.fetch(request);
  },
};
