/**
 * p2pvpn Web Bridge — Service Worker
 *
 * This SW is registered with scope "/" and the "Service-Worker-Allowed: /"
 * response header so it can intercept requests from any page on the WebUI
 * origin, including the /bridge page.
 *
 * It reads the VPN CIDR and bridge host from its own URL query parameters:
 *   /bridge-sw.js?cidr=10.42.0.0/24&base=10.42.0.1
 *
 * Any fetch request whose destination hostname is an IP address inside the
 * VPN CIDR (but NOT the bridge host itself) is transparently proxied through:
 *   GET /api/bridge/proxy?target=<original-url>
 *
 * Requests to the WebUI host, non-VPN IPs, and non-HTTP(S) protocols pass
 * through to the network unchanged.
 */

const params = new URL(self.location.href).searchParams;
const CIDR_STR = params.get('cidr') || '10.42.0.0/24';
const OWN_HOST = params.get('base') || '';

// Parse CIDR into integer network/mask for fast membership tests.
const [cidrAddr, cidrBits] = CIDR_STR.split('/');
const CIDR_INT  = ipToInt(cidrAddr);
const CIDR_MASK = cidrBits
  ? (~0 << (32 - parseInt(cidrBits, 10))) >>> 0
  : 0xFFFFFFFF;

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) | (parseInt(octet, 10) & 0xFF)) >>> 0, 0) >>> 0;
}

function isVPNHost(hostname) {
  if (!hostname || hostname === OWN_HOST) return false;
  // Only intercept bare dotted-decimal IPv4 addresses.
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return false;
  const ip = ipToInt(hostname);
  return (ip & CIDR_MASK) === (CIDR_INT & CIDR_MASK);
}

// Take control of all clients immediately on activation.
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', event => {
  let url;
  try { url = new URL(event.request.url); } catch (_) { return; }

  // Only intercept http / https to VPN IPs.
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || !isVPNHost(url.hostname)) {
    return; // fall through — browser handles normally
  }

  event.respondWith(proxyRequest(event.request, url));
});

async function proxyRequest(request, url) {
  // Build proxy URL on the same origin as the SW.
  const proxyURL = new URL('/api/bridge/proxy', self.registration.scope);
  proxyURL.searchParams.set('target', url.href);

  // Forward safe request headers.
  const headers = {};
  for (const h of ['Accept', 'Accept-Language', 'Content-Type', 'Cookie', 'Referer']) {
    const v = request.headers.get(h);
    if (v) headers[h] = v;
  }

  let body = null;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    body = await request.arrayBuffer();
  }

  try {
    const resp = await fetch(proxyURL.href, {
      method: 'GET', // proxy endpoint always GET regardless of original method
      headers,
      signal: request.signal,
    });
    // Re-serve the response under the original URL so the browser sees the
    // correct page origin, enabling full navigation within the iframe.
    return new Response(resp.body, {
      status:  resp.status,
      headers: resp.headers,
    });
  } catch (err) {
    return new Response(`Proxy error: ${err.message}`, {
      status:  502,
      headers: { 'Content-Type': 'text/plain' },
    });
  }
}
