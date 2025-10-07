const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');
const { pipeline } = require('stream');
const { promisify } = require('util');
const pipelineAsync = promisify(pipeline);

const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
const DEFAULT_RATE_LIMIT_POINTS = 30;
const FETCH_TIMEOUT_MS = 20_000;

const rateLimitStore = new Map();

function isPrivateIP(ip) {
  if (!net.isIP(ip)) return false;
  if (ip.includes('.')) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
  } else {
    if (ip === '::1' || ip.startsWith('fe80') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  }
  return false;
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function checkRateLimit(clientIp, points = DEFAULT_RATE_LIMIT_POINTS, windowMs = DEFAULT_RATE_LIMIT_WINDOW_MS) {
  const now = Date.now();
  const entry = rateLimitStore.get(clientIp) || { pointsLeft: points, windowStart: now };
  if (now - entry.windowStart > windowMs) {
    entry.pointsLeft = points;
    entry.windowStart = now;
  }
  if (entry.pointsLeft <= 0) {
    rateLimitStore.set(clientIp, entry);
    return false;
  }
  entry.pointsLeft -= 1;
  rateLimitStore.set(clientIp, entry);
  return true;
}

function setCORSHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}

async function handler(req, res) {
  setCORSHeaders(res);

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  if (req.method !== 'GET') {
    res.statusCode = 405;
    res.setHeader('Allow', 'GET,OPTIONS');
    return res.end('Only GET allowed');
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(clientIp)) {
    res.statusCode = 429;
    return res.end('Rate limit exceeded');
  }

  const target = (req.query && req.query.url) || (req.url && new URL('http://dummy' + req.url).searchParams.get('url'));
  if (!target) {
    res.statusCode = 400;
    return res.end('Missing url parameter');
  }

  let parsed;
  try {
    parsed = new URL(target);
    if (!/^https?:$/.test(parsed.protocol)) throw new Error();
  } catch {
    res.statusCode = 400;
    return res.end('Invalid target URL');
  }

  try {
    const records = await dns.lookup(parsed.hostname, { all: true });
    if (!records || records.length === 0) throw new Error();
    for (const r of records) {
      if (isPrivateIP(r.address)) {
        res.statusCode = 403;
        return res.end('Access to private IP ranges is blocked');
      }
    }
  } catch {
    res.statusCode = 400;
    return res.end('DNS lookup failed or hostname invalid');
  }

  const outgoingHeaders = {};
  const incoming = req.headers;
  const allowedForwardHeaders = ['accept', 'accept-encoding', 'user-agent', 'referer', 'x-requested-with'];
  for (const h of allowedForwardHeaders) {
    if (incoming[h]) outgoingHeaders[h] = incoming[h];
  }
  if (req.query && req.query.auth === '1' && incoming['authorization']) {
    outgoingHeaders['authorization'] = incoming['authorization'];
  }

  const allowCookies = req.query && (req.query.allowCookies === '1' || req.query.allowCookies === 'true');
  if (allowCookies && incoming.cookie) {
    outgoingHeaders.cookie = incoming.cookie;
  }

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  const lib = parsed.protocol === 'https:' ? https : http;
  const requestOptions = {
    method: 'GET',
    headers: outgoingHeaders,
    timeout: FETCH_TIMEOUT_MS,
  };

  const upstreamReq = lib.request(parsed, (upstreamRes) => {
    clearTimeout(t);

    const responseHeaders = {};
    const safeHeaders = [
      'content-type', 'content-length', 'content-disposition', 'cache-control',
      'last-modified', 'etag', 'expires', 'x-amz-meta-*', 'accept-ranges', 'content-range'
    ];
    for (const [k, v] of Object.entries(upstreamRes.headers || {})) {
      const kl = k.toLowerCase();
      if (kl === 'set-cookie' && !allowCookies) continue;
      if (kl === 'location' && v) {
        try {
          const loc = new URL(String(v), parsed);
          responseHeaders['location'] = `/api/proxy?url=${encodeURIComponent(loc.toString())}`;
          continue;
        } catch {}
      }
      let copied = false;
      for (const pattern of safeHeaders) {
        if (pattern.endsWith('*')) {
          if (kl.startsWith(pattern.slice(0, -1))) {
            responseHeaders[k] = v;
            copied = true;
            break;
          }
        } else if (kl === pattern) {
          responseHeaders[k] = v;
          copied = true;
          break;
        }
      }
      if (!copied && ['server', 'x-powered-by', 'via'].includes(kl) === false) {
        responseHeaders[k] = v;
      }
    }

    for (const [k, v] of Object.entries(responseHeaders)) res.setHeader(k, v);
    setCORSHeaders(res);

    res.statusCode = upstreamRes.statusCode || 200;

    pipelineAsync(upstreamRes, res).catch(() => {
      try { res.destroy(); } catch {}
    });
  });

  upstreamReq.on('error', (err) => {
    clearTimeout(t);
    if (err.name === 'AbortError') {
      res.statusCode = 504;
      return res.end('Upstream request timed out');
    }
    res.statusCode = 502;
    return res.end('Bad gateway: ' + err.message);
  });

  upstreamReq.on('timeout', () => {
    upstreamReq.destroy(new Error('Timeout'));
  });

  upstreamReq.end();
}

module.exports = (req, res) => {
  if (!req.query) {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    req.query = Object.fromEntries(urlObj.searchParams.entries());
  }

  handler(req, res).catch(() => {
    try {
      if (!res.headersSent) {
        res.statusCode = 500;
        setCORSHeaders(res);
        res.end('Internal server error');
      } else {
        res.end();
      }
    } catch {}
  });
};
