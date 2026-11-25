/*
 * OM push relay — Cloudflare Worker (free plan).
 * Receives "send a notification" calls from the Ordering Materials app and delivers
 * them as push notifications through Firebase Cloud Messaging (FCM HTTP v1).
 *
 * Settings in Cloudflare (Worker → Settings → Variables and Secrets):
 *   SERVICE_ACCOUNT  (Secret)  — full contents of the Firebase service-account JSON key
 *   APP_ACCOUNT      (Text)    — om.app@nabuurs.nl   (only this signed-in app may send)
 *   ALLOWED_ORIGIN   (Text)    — https://marcinpanda.github.io
 *
 * Devices that want notifications are listed in Firestore document om/push:
 *   { devices: { <deviceId>: { token, topics:[...], name, at } } }
 */
const enc = new TextEncoder();
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlJson = obj => b64url(enc.encode(JSON.stringify(obj)));
const fromB64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));

function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status, headers: { ...headers, 'Content-Type': 'application/json' } });
}

/* ---- 1. Check that the caller is the signed-in app account (Firebase ID token, RS256) ---- */
let certCache = { keys: null, until: 0 };
async function googleJwks() {
  if (certCache.keys && Date.now() < certCache.until) return certCache.keys;
  const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  const j = await r.json();
  certCache = { keys: j.keys, until: Date.now() + 3600e3 };
  return j.keys;
}
async function verifyIdToken(token, projectId, jwks) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('missing sign-in token');
  const header = JSON.parse(new TextDecoder().decode(fromB64url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(fromB64url(parts[1])));
  const jwk = (jwks || await googleJwks()).find(k => k.kid === header.kid);
  if (!jwk || header.alg !== 'RS256') throw new Error('unknown signing key');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromB64url(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
  const now = Math.floor(Date.now() / 1000);
  if (!ok) throw new Error('bad signature');
  if (claims.aud !== projectId || claims.iss !== 'https://securetoken.google.com/' + projectId) throw new Error('wrong project');
  if (!(claims.exp > now)) throw new Error('sign-in token expired');
  return claims;
}

/* ---- 2. Get a Google access token from the service account ---- */
let tokenCache = { token: null, until: 0 };
async function accessToken(sa, fetchFn = fetch) {
  if (tokenCache.token && Date.now() < tokenCache.until) return tokenCache.token;
  const now = Math.floor(Date.now() / 1000);
  const unsigned = b64urlJson({ alg: 'RS256', typ: 'JWT' }) + '.' + b64urlJson({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600
  });
  const der = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(unsigned));
  const assertion = unsigned + '.' + b64url(sig);
  const r = await fetchFn('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + assertion
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('Google token: ' + (j.error_description || j.error || r.status));
  tokenCache = { token: j.access_token, until: Date.now() + (j.expires_in - 120) * 1000 };
  return j.access_token;
}

/* ---- 3. Read subscribed devices from Firestore (REST) ---- */
function fsValue(v) {
  if (!v) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('timestampValue' in v) return v.timestampValue;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fsValue);
  if ('mapValue' in v) return Object.fromEntries(Object.entries(v.mapValue.fields || {}).map(([k, x]) => [k, fsValue(x)]));
  return null;
}
async function devices(projectId, at) {
  const r = await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/om/push`, { headers: { Authorization: 'Bearer ' + at } });
  if (r.status === 404) return {};
  const j = await r.json();
  if (!r.ok) throw new Error('Firestore: ' + (j.error && j.error.message || r.status));
  return fsValue({ mapValue: { fields: j.fields || {} } }).devices || {};
}
async function removeDevices(projectId, at, ids) {
  if (!ids.length) return;
  const mask = ids.map(id => 'updateMask.fieldPaths=' + encodeURIComponent('devices.`' + id + '`')).join('&');
  await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/om/push?${mask}`, {
    method: 'PATCH', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' }, body: JSON.stringify({ fields: {} })
  });
}

/* ---- 4. Send through FCM ---- */
async function sendOne(projectId, at, token, data) {
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + at, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: { token, webpush: { headers: { Urgency: 'high', TTL: '86400' }, data } } })
  });
  if (r.ok) return 'sent';
  const j = await r.json().catch(() => ({}));
  const code = JSON.stringify(j);
  return /UNREGISTERED|NOT_FOUND|INVALID_ARGUMENT/.test(code) ? 'gone' : 'error';
}

export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST') return new Response('OM push relay is running.', { headers: cors });
    try {
      const sa = JSON.parse(env.SERVICE_ACCOUNT);
      const claims = await verifyIdToken((req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, ''), sa.project_id);
      if (!env.APP_ACCOUNT || claims.email !== env.APP_ACCOUNT) return json({ error: 'not allowed' }, 403, cors);
      const b = await req.json();
      const topic = String(b.topic || 'requests');
      const data = {
        title: String(b.title || 'Ordering Materials').slice(0, 120),
        body: String(b.body || '').slice(0, 400),
        link: String(b.link || './').slice(0, 300),
        tag: String(b.tag || topic).slice(0, 60)
      };
      const at = await accessToken(sa);
      const all = await devices(sa.project_id, at);
      const targets = Object.entries(all).filter(([id, d]) => d && d.token && (d.topics || []).includes(topic) && id !== b.exclude);
      const results = await Promise.all(targets.map(([id, d]) => sendOne(sa.project_id, at, d.token, data).then(r => [id, r])));
      const gone = results.filter(([, r]) => r === 'gone').map(([id]) => id);
      await removeDevices(sa.project_id, at, gone);
      return json({ sent: results.filter(([, r]) => r === 'sent').length, removed: gone.length, failed: results.filter(([, r]) => r === 'error').length }, 200, cors);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500, cors);
    }
  }
};

