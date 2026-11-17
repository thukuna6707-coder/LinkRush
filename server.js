const http = require("node:http");
const https = require("node:https");
const dns = require("node:dns").promises;
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");
const { URL } = require("node:url");
const PROVIDERS = require("./providers.json");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");
const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 12000;
const MAX_BODY = 1024 * 64;

function detectProvider(input) {
  let hostname;
  try { hostname = new URL(input).hostname.toLowerCase(); } catch { return null; }
  return PROVIDERS.find(provider => (provider.domains || []).some(domain => hostname === domain || hostname.endsWith("." + domain))) || null;
}

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a,b] = p;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19));
}
function isPublicIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return !isPrivateIPv4(ip);
  if (v === 6) {
    const s = ip.toLowerCase();
    return !(s === "::" || s === "::1" || s.startsWith("fc") || s.startsWith("fd") ||
      s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") ||
      s.startsWith("feb") || s.startsWith("::ffff:127.") || s.startsWith("::ffff:10.") ||
      s.startsWith("::ffff:192.168."));
  }
  return false;
}
async function resolvePublic(hostname) {
  if (net.isIP(hostname)) {
    if (!isPublicIp(hostname)) throw new Error("Private or reserved network destinations are not allowed.");
    return hostname;
  }
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some(r => !isPublicIp(r.address))) {
    throw new Error("This hostname resolves to a private or reserved network address.");
  }
  return records[0].address;
}
function requestOnce(urlObj, ip) {
  return new Promise((resolve, reject) => {
    const transport = urlObj.protocol === "https:" ? https : http;
    const req = transport.request(urlObj, {
      method: "GET",
      headers: {
        "User-Agent": "LinkRush/1.0 (+redirect-inspector)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Range": "bytes=0-65535"
      },
      timeout: TIMEOUT_MS,
      lookup: (_hostname, _options, callback) => callback(null, ip, net.isIP(ip))
    }, res => {
      let bytes = 0;
      const chunks = [];
      res.on("data", chunk => {
        bytes += chunk.length;
        if (bytes <= MAX_BODY) chunks.push(chunk);
        else req.destroy(new Error("Response body limit exceeded."));
      });
      res.on("end", () => resolve({
        status: res.statusCode || 0,
        headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    req.on("timeout", () => req.destroy(new Error("The destination server timed out.")));
    req.on("error", reject);
    req.end();
  });
}
function extractMetaRefresh(html, base) {
  const meta = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*([^"']+)/i);
  if (!meta) return null;
  try { return new URL(meta[1].trim().replace(/^['"]|['"]$/g, ""), base).toString(); } catch { return null; }
}
function extractJsRedirect(html, base) {
  const patterns = [
    /(?:window|document)\.location(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    /location\.replace\(\s*["']([^"']+)["']\s*\)/i
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m) { try { return new URL(m[1], base).toString(); } catch {} }
  }
  return null;
}
async function inspect(start) {
  let current = new URL(start);
  const chain = [];
  const seen = new Set();
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (!["http:", "https:"].includes(current.protocol)) throw new Error("Only HTTP and HTTPS links are supported.");
    if (current.username || current.password) throw new Error("Links containing embedded credentials are not accepted.");
    if (seen.has(current.href)) throw new Error("A redirect loop was detected.");
    seen.add(current.href);
    const ip = await resolvePublic(current.hostname);
    const response = await requestOnce(current, ip);
    chain.push({ url: current.href, status: response.status });
    const location = response.headers.location;
    if (location && [301,302,303,307,308].includes(response.status)) {
      if (i === MAX_REDIRECTS) throw new Error("Maximum redirect count reached.");
      current = new URL(location, current);
      continue;
    }
    const meta = extractMetaRefresh(response.body, current.href);
    const js = extractJsRedirect(response.body, current.href);
    const candidate = meta || js;
    if (candidate && i < MAX_REDIRECTS) {
      current = new URL(candidate);
      continue;
    }
    const html = response.body;
    const captcha = /captcha|recaptcha|hcaptcha|cloudflare.*challenge|verify you are human|checking your browser/i.test(html);
    const gatedAction = /complete.{0,40}survey|survey.{0,40}(unlock|continue)|subscribe.{0,30}(unlock|continue)|unlock.{0,30}survey|sign in to continue|log in to continue/i.test(html);
    const interstitial = captcha || gatedAction || /click here to continue|continue to destination|please wait|adblock/i.test(html);
    const provider = detectProvider(start);
    return {
      finalUrl: current.href,
      resolved: !interstitial,
      chain,
      status: response.status,
      provider: provider ? { name: provider.name, category: provider.category, status: provider.status } : null,
      needsHuman: interstitial,
      verificationUrl: interstitial ? start : null,
      reason: captcha ? "Human CAPTCHA verification is required. Continue on the original provider page; LinkRush cannot solve, copy, transfer, or replay CAPTCHA tokens." :
        gatedAction ? "The provider appears to require a survey, subscription, or sign-in. LinkRush cannot skip that requirement; complete it with the provider if you choose." :
        interstitial ? "The provider shows an interstitial or requires another action. Continue on the original provider page." : null
    };
  }
  throw new Error("Too many redirects.");
}
function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(body);
}
const server = http.createServer(async (req, res) => {
  if (req.url === "/health") return send(res, 200, { ok: true });
  if (req.method === "GET" && new URL(req.url, "http://localhost").pathname === "/api/providers") {
    return send(res, 200, { providers: PROVIDERS.map(({ name, category, status, note }) => ({ name, category, status, note: note || null })) });
  }
  if (req.method === "POST" && req.url === "/api/resolve") {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 4096) req.destroy();
    });
    req.on("end", async () => {
      try {
        const data = JSON.parse(raw || "{}");
        if (typeof data.url !== "string" || data.url.length > 2048) return send(res, 400, { error: "Enter a valid URL (maximum 2,048 characters)." });
        let url;
        try { url = new URL(data.url); } catch { return send(res, 400, { error: "That URL is not valid." }); }
        if (!["http:", "https:"].includes(url.protocol)) return send(res, 400, { error: "Only HTTP and HTTPS links are supported." });
        const result = await inspect(url.href);
        return send(res, 200, result);
      } catch (err) {
        return send(res, 422, { error: err.message || "Unable to resolve this link." });
      }
    });
    return;
  }
  if (req.method === "GET") {
    let pathname;
    try { pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname); }
    catch { return send(res, 400, { error: "Invalid request path" }); }
    const requested = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
    const file = path.resolve(PUBLIC_DIR, requested);
    const relative = path.relative(PUBLIC_DIR, file);
    if (relative.startsWith("..") || path.isAbsolute(relative)) return send(res, 403, { error: "Forbidden" });
    fs.readFile(file, (err, data) => {
      if (err) return send(res, 404, { error: "Not found" });
      const type = file.endsWith(".html") ? "text/html; charset=utf-8" : "application/octet-stream";
      res.writeHead(200, { "Content-Type": type, "X-Content-Type-Options": "nosniff" });
      res.end(data);
    });
    return;
  }
  send(res, 405, { error: "Method not allowed" });
});
server.listen(PORT, "0.0.0.0", () => console.log(`LinkRush listening on ${PORT}`));
