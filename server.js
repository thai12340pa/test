/*  ================================================================
    CyberPulse v3.1 — Advanced Web Vulnerability Scanner
    Server-side engine: actually crawls, probes, and attacks targets.
    FOR AUTHORIZED PENETRATION TESTING ONLY.
    ================================================================ */

const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const tls = require('tls');
const https = require('https');
const http = require('http');
const url = require('url');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(require('cors')());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- shared http client ---------- */
const client = axios.create({
    timeout: 12000,
    maxRedirects: 5,
    validateStatus: () => true,          // accept every status
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
    }
});

const LIMITS = {
    crawlPages: 30,
    paramUrls: 10,
    forms: 8,
    sensitiveFileBatch: 8,
    exposureScripts: 10,
    maxResponseBytes: 500000
};

function isPrivateIp(ip) {
    if (!ip) return true;
    const v = String(ip).toLowerCase();
    if (v === 'localhost' || v === '::1' || v === '0:0:0:0:0:0:0:1') return true;
    if (v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80:')) return true;
    const parts = v.split('.').map(Number);
    if (parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
        const [a, b] = parts;
        return a === 10 || a === 127 || a === 0 ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 168) ||
            (a === 169 && b === 254) ||
            (a >= 224);
    }
    return false;
}

async function validateTargetUrl(target) {
    const normalized = normalizeUrl(target || '');
    const parsed = new URL(normalized);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only HTTP/HTTPS targets are supported');
    const host = parsed.hostname.toLowerCase();
    const allowPrivate = process.env.CYBERPULSE_ALLOW_PRIVATE_TARGETS === 'true';
    if (!allowPrivate) {
        if (host === 'localhost' || isPrivateIp(host) || host === '169.254.169.254') {
            throw new Error('Private, loopback, and metadata targets are blocked by default. Set CYBERPULSE_ALLOW_PRIVATE_TARGETS=true only for authorized lab testing.');
        }
        try {
            const addrs = await dns.lookup(host, { all: true });
            if (addrs.some(a => isPrivateIp(a.address) || a.address === '169.254.169.254')) {
                throw new Error('Target resolves to a private, loopback, or metadata IP and is blocked by default.');
            }
        } catch (e) {
            if (e.message.includes('blocked')) throw e;
        }
    }
    return normalized;
}

function redactSecret(value) {
    const s = String(value || '');
    if (s.length <= 8) return '[redacted]';
    return `${s.slice(0, 4)}...${s.slice(-4)}`;
}

function validateSensitiveBody(pathName, body) {
    const bodyText = String(body || '');
    if (pathName.includes('.env')) return /^[A-Z0-9_]{2,}\s*=.+/mi.test(bodyText) && !bodyText.includes('<html');
    if (pathName.includes('.git/config')) return /\[core\]|\[remote /i.test(bodyText);
    if (pathName === '/.git/HEAD') return bodyText.startsWith('ref:');
    if (pathName.endsWith('package.json') || pathName.endsWith('composer.json')) {
        try { const j = JSON.parse(bodyText); return !!(j.name || j.scripts || j.dependencies || j.require); }
        catch { return false; }
    }
    if (pathName.endsWith('.sql')) return /CREATE\s+TABLE|INSERT\s+INTO|mysqldump/i.test(bodyText);
    return true;
}

/* ============================================================
   1. FULL SCAN — orchestrates every check on a single target
   ============================================================ */
app.post('/api/fullscan', async (req, res) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: 'Target required' });

    let baseUrl, domain;
    try {
        baseUrl = await validateTargetUrl(target);
        domain = new URL(baseUrl).hostname;
    } catch (e) {
        return res.status(400).json({ error: e.message });
    }
    const results = { target: baseUrl, domain, startTime: Date.now(), findings: [], modules: {} };

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    const send = (evt, data) => res.write(`event: ${evt}\ndata: ${JSON.stringify(data)}\n\n`);

    try {
        // 1 — Fetch home page
        send('status', { module: 'init', message: 'Fetching target...' });
        const homeResp = await client.get(baseUrl);
        const $ = cheerio.load(homeResp.data);
        const headers = homeResp.headers;

        // 2 — Security headers
        send('status', { module: 'headers', message: 'Analyzing security headers...' });
        results.modules.headers = analyzeHeaders(headers);
        send('result', { module: 'headers', data: results.modules.headers });

        // 3 — Technology fingerprint
        send('status', { module: 'tech', message: 'Detecting technologies...' });
        results.modules.tech = detectTech(headers, homeResp.data, $);
        send('result', { module: 'tech', data: results.modules.tech });

        // 4 — Cookie analysis
        send('status', { module: 'cookies', message: 'Analyzing cookies...' });
        results.modules.cookies = analyzeCookies(headers);
        send('result', { module: 'cookies', data: results.modules.cookies });

        // 5 — Information disclosure
        send('status', { module: 'info', message: 'Checking information disclosure...' });
        results.modules.info = analyzeInfoDisclosure($, homeResp.data, headers);
        send('result', { module: 'info', data: results.modules.info });

        // 6 — Crawl website
        send('status', { module: 'crawl', message: 'Crawling website...' });
        const crawlResult = await crawlSite(baseUrl, $, send);
        results.modules.crawl = crawlResult;
        send('result', { module: 'crawl', data: { pages: crawlResult.pages.length, forms: crawlResult.forms.length, links: crawlResult.links.length } });

        // 7 — Sensitive files
        send('status', { module: 'files', message: 'Scanning for exposed files...' });
        results.modules.files = await scanSensitiveFiles(baseUrl, send);
        send('result', { module: 'files', data: results.modules.files });

        // 8 — Application exposure checks
        send('status', { module: 'exposure', message: 'Checking application exposure...' });
        results.modules.exposure = await scanExposure(baseUrl, crawlResult, send);
        send('result', { module: 'exposure', data: results.modules.exposure });

        // 9 — CORS check
        send('status', { module: 'cors', message: 'Testing CORS configuration...' });
        results.modules.cors = await testCORS(baseUrl);
        send('result', { module: 'cors', data: results.modules.cors });

        // 9 — XSS testing
        send('status', { module: 'xss', message: 'Testing for XSS vulnerabilities...' });
        results.modules.xss = await testXSS(baseUrl, crawlResult, send);
        send('result', { module: 'xss', data: results.modules.xss });

        // 10 — SQLi testing
        send('status', { module: 'sqli', message: 'Testing for SQL Injection...' });
        results.modules.sqli = await testSQLi(baseUrl, crawlResult, send);
        send('result', { module: 'sqli', data: results.modules.sqli });

        // 11 — Open redirect
        send('status', { module: 'redirect', message: 'Testing for open redirects...' });
        results.modules.redirect = await testOpenRedirect(baseUrl, crawlResult);
        send('result', { module: 'redirect', data: results.modules.redirect });

        // 12 — LFI / Path traversal
        send('status', { module: 'lfi', message: 'Testing path traversal...' });
        results.modules.lfi = await testLFI(baseUrl, crawlResult, send);
        send('result', { module: 'lfi', data: results.modules.lfi });

        // 13 — SSL/TLS
        send('status', { module: 'ssl', message: 'Analyzing SSL/TLS...' });
        results.modules.ssl = await analyzeSSL(domain);
        send('result', { module: 'ssl', data: results.modules.ssl });

        // 14 — DNS
        send('status', { module: 'dns', message: 'Enumerating DNS...' });
        results.modules.dns = await enumerateDNS(domain);
        send('result', { module: 'dns', data: results.modules.dns });

        // 15 — Subdomain discovery
        send('status', { module: 'subdomains', message: 'Discovering subdomains...' });
        results.modules.subdomains = await discoverSubdomains(domain, send);
        send('result', { module: 'subdomains', data: results.modules.subdomains });

        // collect all findings
        for (const [mod, data] of Object.entries(results.modules)) {
            if (data && data.findings) results.findings.push(...data.findings);
        }
        results.endTime = Date.now();
        results.duration = ((results.endTime - results.startTime) / 1000).toFixed(1);

        send('done', { summary: { total: results.findings.length, duration: results.duration, critical: results.findings.filter(f=>f.severity==='critical').length, high: results.findings.filter(f=>f.severity==='high').length, medium: results.findings.filter(f=>f.severity==='medium').length, low: results.findings.filter(f=>f.severity==='low').length, info: results.findings.filter(f=>f.severity==='info').length }, findings: results.findings });
    } catch (err) {
        send('error', { message: err.message });
    }
    res.end();
});

/* ============================================================
   2. INDIVIDUAL MODULE ENDPOINTS
   ============================================================ */

// --- Crawl ---
app.post('/api/crawl', async (req, res) => {
    try {
        const baseUrl = normalizeUrl(req.body.target);
        const resp = await client.get(baseUrl);
        const $ = cheerio.load(resp.data);
        const result = await crawlSite(baseUrl, $);
        res.json(result);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Headers ---
app.post('/api/headers', async (req, res) => {
    try {
        const resp = await client.get(normalizeUrl(req.body.target));
        res.json(analyzeHeaders(resp.headers));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Tech ---
app.post('/api/tech', async (req, res) => {
    try {
        const resp = await client.get(normalizeUrl(req.body.target));
        const $ = cheerio.load(resp.data);
        res.json(detectTech(resp.headers, resp.data, $));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Sensitive files ---
app.post('/api/files', async (req, res) => {
    try {
        res.json(await scanSensitiveFiles(await validateTargetUrl(req.body.target)));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Exposure ---
app.post('/api/exposure', async (req, res) => {
    try {
        const baseUrl = await validateTargetUrl(req.body.target);
        const resp = await client.get(baseUrl);
        const $ = cheerio.load(resp.data);
        const crawl = await crawlSite(baseUrl, $);
        res.json(await scanExposure(baseUrl, crawl));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- XSS ---
app.post('/api/xss', async (req, res) => {
    try {
        const baseUrl = normalizeUrl(req.body.target);
        const resp = await client.get(baseUrl);
        const $ = cheerio.load(resp.data);
        const crawl = await crawlSite(baseUrl, $);
        res.json(await testXSS(baseUrl, crawl));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- SQLi ---
app.post('/api/sqli', async (req, res) => {
    try {
        const baseUrl = normalizeUrl(req.body.target);
        const resp = await client.get(baseUrl);
        const $ = cheerio.load(resp.data);
        const crawl = await crawlSite(baseUrl, $);
        res.json(await testSQLi(baseUrl, crawl));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- LFI ---
app.post('/api/lfi', async (req, res) => {
    try {
        const baseUrl = normalizeUrl(req.body.target);
        const resp = await client.get(baseUrl);
        const $ = cheerio.load(resp.data);
        const crawl = await crawlSite(baseUrl, $);
        res.json(await testLFI(baseUrl, crawl));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- CORS ---
app.post('/api/cors', async (req, res) => {
    try { res.json(await testCORS(normalizeUrl(req.body.target))); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

// --- SSL ---
app.post('/api/ssl', async (req, res) => {
    try {
        const domain = new URL(normalizeUrl(req.body.target)).hostname;
        res.json(await analyzeSSL(domain));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- DNS ---
app.post('/api/dns', async (req, res) => {
    try {
        const domain = new URL(normalizeUrl(req.body.target)).hostname;
        res.json(await enumerateDNS(domain));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Subdomains ---
app.post('/api/subdomains', async (req, res) => {
    try {
        const domain = new URL(normalizeUrl(req.body.target)).hostname;
        res.json(await discoverSubdomains(domain));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Open Redirect ---
app.post('/api/redirect', async (req, res) => {
    try {
        const baseUrl = normalizeUrl(req.body.target);
        const resp = await client.get(baseUrl);
        const $ = cheerio.load(resp.data);
        const crawl = await crawlSite(baseUrl, $);
        res.json(await testOpenRedirect(baseUrl, crawl));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   MODULE IMPLEMENTATIONS
   ============================================================ */

function normalizeUrl(t) {
    t = t.trim();
    if (!/^https?:\/\//i.test(t)) t = 'https://' + t;
    return t.replace(/\/+$/, '');
}

/* ---------- Security Headers ---------- */
function analyzeHeaders(headers) {
    const checks = [
        { name: 'Strict-Transport-Security',       weight: 15, desc: 'Enforces HTTPS connections', severity: 'high' },
        { name: 'Content-Security-Policy',          weight: 15, desc: 'Mitigates XSS & injection', severity: 'high' },
        { name: 'X-Frame-Options',                  weight: 10, desc: 'Prevents clickjacking',     severity: 'medium' },
        { name: 'X-Content-Type-Options',           weight: 10, desc: 'Prevents MIME sniffing',     severity: 'medium' },
        { name: 'Referrer-Policy',                  weight: 8,  desc: 'Controls referer leakage',   severity: 'low' },
        { name: 'Permissions-Policy',               weight: 8,  desc: 'Controls browser features',  severity: 'medium' },
        { name: 'X-XSS-Protection',                 weight: 5,  desc: 'Legacy XSS filter',          severity: 'low' },
        { name: 'Cross-Origin-Opener-Policy',       weight: 7,  desc: 'Isolates browsing context',  severity: 'medium' },
        { name: 'Cross-Origin-Embedder-Policy',     weight: 7,  desc: 'Controls cross-origin embeds', severity: 'medium' },
        { name: 'Cross-Origin-Resource-Policy',     weight: 7,  desc: 'Restricts resource loading', severity: 'medium' },
        { name: 'X-Permitted-Cross-Domain-Policies',weight: 4,  desc: 'Controls Flash/PDF policies', severity: 'low' },
        { name: 'Cache-Control',                    weight: 4,  desc: 'Controls caching behavior',  severity: 'low' },
    ];

    let score = 0;
    let maxScore = 0;
    const results = [];
    const findings = [];

    // Dangerous headers that leak info
    const dangerousHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'];

    for (const check of checks) {
        maxScore += check.weight;
        const hdrName = check.name.toLowerCase();
        const value = headers[hdrName];
        const present = !!value;
        if (present) score += check.weight;
        results.push({ name: check.name, present, value: value || null, desc: check.desc, severity: check.severity });
        if (!present) {
            findings.push({ title: `Missing header: ${check.name}`, detail: check.desc, severity: check.severity, module: 'headers' });
        }
    }

    // Check for information leaking headers
    for (const hdr of dangerousHeaders) {
        if (headers[hdr]) {
            findings.push({ title: `Information disclosure via ${hdr} header`, detail: `Value: ${headers[hdr]}`, severity: 'low', module: 'headers' });
        }
    }

    // Header quality checks — not just presence
    const csp = String(headers['content-security-policy'] || '');
    if (csp) {
        if (/unsafe-inline/i.test(csp)) findings.push({ title: 'CSP allows unsafe-inline', detail: 'Inline scripts/styles weaken XSS protection', severity: 'medium', module: 'headers' });
        if (/unsafe-eval/i.test(csp)) findings.push({ title: 'CSP allows unsafe-eval', detail: 'eval-like JavaScript execution is permitted', severity: 'medium', module: 'headers' });
        if (/(^|\s)\*($|\s|;)/.test(csp)) findings.push({ title: 'CSP uses wildcard source', detail: 'Wildcard sources reduce policy effectiveness', severity: 'low', module: 'headers' });
        if (!/object-src\s+[^;]*'none'/i.test(csp)) findings.push({ title: "CSP missing object-src 'none'", detail: 'object-src should usually be locked down', severity: 'low', module: 'headers' });
        if (!/frame-ancestors/i.test(csp) && !headers['x-frame-options']) findings.push({ title: 'Missing clickjacking protection', detail: 'Neither CSP frame-ancestors nor X-Frame-Options is present', severity: 'medium', module: 'headers' });
    }
    const hsts = String(headers['strict-transport-security'] || '');
    if (hsts) {
        const maxAge = Number((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
        if (maxAge > 0 && maxAge < 15552000) findings.push({ title: 'HSTS max-age is short', detail: `max-age=${maxAge}; recommended at least 15552000`, severity: 'medium', module: 'headers' });
        if (!/includesubdomains/i.test(hsts)) findings.push({ title: 'HSTS missing includeSubDomains', detail: 'Subdomains are not covered by HSTS policy', severity: 'low', module: 'headers' });
    }

    const finalScore = Math.round((score / maxScore) * 100);
    return { score: finalScore, checks: results, findings, rawHeaders: headers };
}

/* ---------- Technology Detection ---------- */
function detectTech(headers, html, $) {
    const techs = [];
    const findings = [];
    const body = html.toLowerCase();

    // Server header
    if (headers['server']) {
        techs.push({ name: headers['server'], category: 'Web Server', confidence: 'high', source: 'header' });
    }
    if (headers['x-powered-by']) {
        techs.push({ name: headers['x-powered-by'], category: 'Runtime', confidence: 'high', source: 'header' });
        findings.push({ title: `X-Powered-By header exposes: ${headers['x-powered-by']}`, severity: 'low', module: 'tech' });
    }

    // Meta generator
    const generator = $('meta[name="generator"]').attr('content');
    if (generator) {
        techs.push({ name: generator, category: 'CMS/Generator', confidence: 'high', source: 'meta' });
        findings.push({ title: `CMS/Generator disclosed: ${generator}`, severity: 'info', module: 'tech' });
    }

    // WordPress
    if (body.includes('wp-content') || body.includes('wp-includes') || body.includes('wordpress')) {
        techs.push({ name: 'WordPress', category: 'CMS', confidence: 'high', source: 'content' });
        const wpVer = html.match(/WordPress\s+([\d.]+)/i);
        if (wpVer) {
            techs.push({ name: `WordPress ${wpVer[1]}`, category: 'CMS Version', confidence: 'high', source: 'content' });
            findings.push({ title: `WordPress version disclosed: ${wpVer[1]}`, severity: 'medium', module: 'tech' });
        }
    }

    // Joomla
    if (body.includes('/media/jui/') || body.includes('joomla')) {
        techs.push({ name: 'Joomla', category: 'CMS', confidence: 'medium', source: 'content' });
    }

    // Drupal
    if (body.includes('drupal.settings') || body.includes('/sites/default/') || body.includes('drupal')) {
        techs.push({ name: 'Drupal', category: 'CMS', confidence: 'medium', source: 'content' });
    }

    // JavaScript frameworks
    const jsPatterns = [
        { pattern: /react/i,          name: 'React',     test: () => body.includes('__react') || body.includes('reactroot') || body.includes('_reactlistening') },
        { pattern: /vue/i,            name: 'Vue.js',    test: () => body.includes('__vue__') || body.includes('v-cloak') || body.includes('data-v-') },
        { pattern: /angular/i,        name: 'Angular',   test: () => body.includes('ng-app') || body.includes('ng-controller') || body.includes('angular.min.js') },
        { pattern: /next/i,           name: 'Next.js',   test: () => body.includes('__next') || body.includes('/_next/') },
        { pattern: /nuxt/i,           name: 'Nuxt.js',   test: () => body.includes('__nuxt') || body.includes('/_nuxt/') },
        { pattern: /svelte/i,         name: 'Svelte',    test: () => body.includes('svelte') },
        { pattern: /jquery/i,         name: 'jQuery',    test: () => body.includes('jquery') },
        { pattern: /bootstrap/i,      name: 'Bootstrap', test: () => body.includes('bootstrap.min') || body.includes('bootstrap.css') },
        { pattern: /tailwind/i,       name: 'Tailwind',  test: () => body.includes('tailwindcss') || (html.match(/class="[^"]*(?:flex|grid|text-|bg-|p-|m-|w-|h-){3,}/i) !== null) },
    ];

    for (const jp of jsPatterns) {
        if (jp.test()) {
            techs.push({ name: jp.name, category: 'JavaScript/CSS', confidence: 'medium', source: 'content' });
        }
    }

    // PHP
    if (headers['x-powered-by']?.toLowerCase().includes('php') || body.includes('.php')) {
        techs.push({ name: 'PHP', category: 'Language', confidence: 'medium', source: 'content' });
    }

    // ASP.NET
    if (headers['x-aspnet-version'] || headers['x-aspnetmvc-version'] || body.includes('__viewstate') || body.includes('.aspx')) {
        techs.push({ name: 'ASP.NET', category: 'Framework', confidence: 'high', source: 'content' });
    }

    // Analytics
    if (body.includes('google-analytics') || body.includes('gtag') || body.includes('googletagmanager')) {
        techs.push({ name: 'Google Analytics', category: 'Analytics', confidence: 'high', source: 'content' });
    }
    if (body.includes('hotjar')) techs.push({ name: 'Hotjar', category: 'Analytics', confidence: 'medium', source: 'content' });
    if (body.includes('facebook.net/en_US/fbevents')) techs.push({ name: 'Facebook Pixel', category: 'Analytics', confidence: 'high', source: 'content' });

    // CDN
    if (headers['cf-ray'] || headers['cf-cache-status']) techs.push({ name: 'Cloudflare', category: 'CDN/WAF', confidence: 'high', source: 'header' });
    if (headers['x-amz-cf-id'] || headers['x-amz-cf-pop']) techs.push({ name: 'Amazon CloudFront', category: 'CDN', confidence: 'high', source: 'header' });
    if (headers['x-cache'] && headers['x-cache'].includes('fastly')) techs.push({ name: 'Fastly', category: 'CDN', confidence: 'high', source: 'header' });

    return { technologies: techs, findings };
}

/* ---------- Cookie Analysis ---------- */
function analyzeCookies(headers) {
    const findings = [];
    const cookies = [];
    const setCookie = headers['set-cookie'];
    if (!setCookie) return { cookies: [], findings: [{ title: 'No cookies set on initial response', severity: 'info', module: 'cookies' }] };

    const cookieHeaders = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const raw of cookieHeaders) {
        const parts = raw.split(';').map(p => p.trim());
        const [nameVal] = parts;
        const [name] = nameVal.split('=');
        const attrs = parts.slice(1);
        const flags = attrs.map(p => p.toLowerCase());
        const hasSecure = flags.some(f => f === 'secure');
        const hasHttpOnly = flags.some(f => f === 'httponly');
        const sameSiteAttr = flags.find(f => f.startsWith('samesite')) || '';
        const hasSameSite = !!sameSiteAttr;
        const sameSiteValue = sameSiteAttr.split('=')[1] || null;
        const hasDomain = flags.some(f => f.startsWith('domain='));
        const pathAttr = flags.find(f => f.startsWith('path=')) || '';
        const sessionLike = /session|sid|auth|token|jwt/i.test(name);

        const issues = [];
        if (!hasSecure) { issues.push('Missing Secure flag'); findings.push({ title: `Cookie "${name}" missing Secure flag`, severity: sessionLike ? 'high' : 'medium', module: 'cookies' }); }
        if (!hasHttpOnly) { issues.push('Missing HttpOnly flag'); findings.push({ title: `Cookie "${name}" missing HttpOnly flag — accessible via JavaScript`, severity: sessionLike ? 'high' : 'medium', module: 'cookies' }); }
        if (!hasSameSite) { issues.push('Missing SameSite attribute'); findings.push({ title: `Cookie "${name}" missing SameSite attribute — CSRF risk`, severity: 'medium', module: 'cookies' }); }
        if (sameSiteValue === 'none' && !hasSecure) { issues.push('SameSite=None without Secure'); findings.push({ title: `Cookie "${name}" uses SameSite=None without Secure`, severity: 'high', module: 'cookies' }); }
        if (sameSiteValue && !['lax', 'strict', 'none'].includes(sameSiteValue)) { issues.push('Invalid SameSite value'); findings.push({ title: `Cookie "${name}" has invalid SameSite value`, detail: sameSiteValue, severity: 'low', module: 'cookies' }); }
        if (name.startsWith('__Host-') && (!hasSecure || hasDomain || pathAttr !== 'path=/')) findings.push({ title: `Cookie "${name}" violates __Host- prefix requirements`, severity: 'medium', module: 'cookies' });
        if (name.startsWith('__Secure-') && !hasSecure) findings.push({ title: `Cookie "${name}" violates __Secure- prefix requirements`, severity: 'medium', module: 'cookies' });

        cookies.push({ name, secure: hasSecure, httpOnly: hasHttpOnly, sameSite: sameSiteValue || hasSameSite, issues, raw });
    }
    return { cookies, findings };
}

/* ---------- Information Disclosure ---------- */
function analyzeInfoDisclosure($, html, headers) {
    const findings = [];

    // HTML comments that might leak info
    const comments = [];
    html.replace(/<!--([\s\S]*?)-->/g, (_, c) => {
        const trimmed = c.trim();
        if (trimmed.length > 5 && trimmed.length < 500) {
            comments.push(trimmed);
            // Check if comments contain sensitive keywords
            const sensitive = ['password', 'secret', 'api_key', 'apikey', 'token', 'todo', 'fixme', 'hack', 'bug', 'debug', 'admin', 'root', 'credential', 'database', 'db_'];
            for (const kw of sensitive) {
                if (trimmed.toLowerCase().includes(kw)) {
                    findings.push({ title: `HTML comment contains sensitive keyword "${kw}"`, detail: trimmed.substring(0, 200), severity: 'medium', module: 'info' });
                    break;
                }
            }
        }
    });

    // Emails
    const emails = [...new Set(html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
    if (emails.length > 0) {
        findings.push({ title: `${emails.length} email address(es) found in source`, detail: emails.join(', '), severity: 'info', module: 'info' });
    }

    // Internal IPs
    const ips = [...new Set(html.match(/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g) || [])];
    if (ips.length > 0) {
        findings.push({ title: `Internal IP address(es) found in source`, detail: ips.join(', '), severity: 'medium', module: 'info' });
    }

    // Forms without CSRF token
    $('form').each((_, form) => {
        const $form = $(form);
        const action = $form.attr('action') || '';
        const method = ($form.attr('method') || 'get').toLowerCase();
        if (method === 'post') {
            const hasCsrf = $form.find('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity_token"]').length > 0;
            if (!hasCsrf) {
                findings.push({ title: `POST form without CSRF token`, detail: `Action: ${action || '(self)'}`, severity: 'medium', module: 'info' });
            }
        }
    });

    // Dangerous inline scripts
    $('script').each((_, s) => {
        const content = $(s).html();
        if (content) {
            const dangerPatterns = ['eval(', 'document.write(', 'innerHTML', 'outerHTML', '.exec('];
            for (const dp of dangerPatterns) {
                if (content.includes(dp)) {
                    findings.push({ title: `Potentially dangerous JS pattern: ${dp}`, detail: content.substring(0, 200), severity: 'low', module: 'info' });
                    break;
                }
            }
        }
    });

    // Source maps
    const sourceMapRegex = /\/\/[#@]\s*sourceMappingURL=\S+/g;
    const sourceMaps = html.match(sourceMapRegex) || [];
    if (sourceMaps.length > 0) {
        findings.push({ title: `Source map(s) exposed`, detail: sourceMaps.join(', '), severity: 'low', module: 'info' });
    }

    return { comments: comments.length, emails, internalIps: ips, findings };
}

/* ---------- Crawl Site ---------- */
async function crawlSite(baseUrl, $, send) {
    const parsed = new URL(baseUrl);
    const origin = parsed.origin;
    const visited = new Set();
    const pages = [];
    const forms = [];
    const allLinks = new Set();
    const paramUrls = [];
    const scripts = new Set();

    // Extract from initial page
    extractPageData($, baseUrl, allLinks, forms, paramUrls, scripts, origin);
    visited.add(baseUrl);
    pages.push({ url: baseUrl, status: 200 });

    // Crawl up to 30 internal pages
    const toVisit = [...allLinks].filter(l => l.startsWith(origin) && !visited.has(l)).slice(0, 30);

    for (const link of toVisit) {
        if (visited.has(link)) continue;
        visited.add(link);
        try {
            if (send) send('status', { module: 'crawl', message: `Crawling: ${link}` });
            const resp = await client.get(link, { timeout: 8000 });
            pages.push({ url: link, status: resp.status });
            if (resp.headers['content-type']?.includes('text/html')) {
                const $page = cheerio.load(resp.data);
                extractPageData($page, link, allLinks, forms, paramUrls, scripts, origin);
            }
        } catch (e) {
            pages.push({ url: link, status: 'error', error: e.message });
        }
    }

    return { pages, forms, links: [...allLinks], paramUrls, scripts: [...scripts] };
}

function extractPageData($, pageUrl, allLinks, forms, paramUrls, scripts, origin) {
    // Links
    $('a[href]').each((_, el) => {
        try {
            const href = $(el).attr('href');
            if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;
            const resolved = new URL(href, pageUrl).href.split('#')[0];
            allLinks.add(resolved);
            if (resolved.includes('?')) paramUrls.push(resolved);
        } catch (e) { }
    });

    // Same-origin JavaScript assets
    $('script[src]').each((_, el) => {
        try {
            const src = $(el).attr('src');
            if (!src) return;
            const resolved = new URL(src, pageUrl).href.split('#')[0];
            if (resolved.startsWith(origin)) scripts.add(resolved);
        } catch (e) { }
    });

    // Forms
    $('form').each((_, el) => {
        const $form = $(el);
        const action = $form.attr('action');
        const method = ($form.attr('method') || 'get').toUpperCase();
        let actionUrl;
        try { actionUrl = action ? new URL(action, pageUrl).href : pageUrl; } catch (e) { actionUrl = pageUrl; }
        const inputs = [];
        $form.find('input, textarea, select').each((_, inp) => {
            const $inp = $(inp);
            inputs.push({
                name: $inp.attr('name') || '',
                type: $inp.attr('type') || 'text',
                value: $inp.attr('value') || ''
            });
        });
        if (inputs.some(i => i.name)) {
            forms.push({ action: actionUrl, method, inputs, page: pageUrl });
        }
    });
}

/* ---------- Sensitive Files Scanner ---------- */
async function scanSensitiveFiles(baseUrl, send) {
    const paths = [
        { path: '/.env', desc: 'Environment variables (secrets, DB credentials)', severity: 'critical' },
        { path: '/.git/HEAD', desc: 'Git repository exposed', severity: 'critical' },
        { path: '/.git/config', desc: 'Git configuration', severity: 'critical' },
        { path: '/.svn/entries', desc: 'SVN repository exposed', severity: 'critical' },
        { path: '/.DS_Store', desc: 'macOS directory metadata', severity: 'medium' },
        { path: '/robots.txt', desc: 'Robots.txt — may reveal hidden paths', severity: 'info' },
        { path: '/sitemap.xml', desc: 'Sitemap — site structure', severity: 'info' },
        { path: '/crossdomain.xml', desc: 'Flash cross-domain policy', severity: 'low' },
        { path: '/security.txt', desc: 'Security contact information', severity: 'info' },
        { path: '/.well-known/security.txt', desc: 'Security policy', severity: 'info' },
        { path: '/wp-config.php.bak', desc: 'WordPress config backup', severity: 'critical' },
        { path: '/wp-config.php~', desc: 'WordPress config editor backup', severity: 'critical' },
        { path: '/wp-login.php', desc: 'WordPress login page', severity: 'info' },
        { path: '/administrator/', desc: 'Joomla admin panel', severity: 'info' },
        { path: '/admin/', desc: 'Admin panel', severity: 'medium' },
        { path: '/admin/login', desc: 'Admin login', severity: 'medium' },
        { path: '/login', desc: 'Login page', severity: 'info' },
        { path: '/phpmyadmin/', desc: 'phpMyAdmin database manager', severity: 'high' },
        { path: '/server-status', desc: 'Apache server status', severity: 'high' },
        { path: '/server-info', desc: 'Apache server info', severity: 'high' },
        { path: '/phpinfo.php', desc: 'PHP info page', severity: 'high' },
        { path: '/info.php', desc: 'PHP info page', severity: 'high' },
        { path: '/test.php', desc: 'Test file', severity: 'medium' },
        { path: '/debug', desc: 'Debug page', severity: 'high' },
        { path: '/console', desc: 'Debug console', severity: 'high' },
        { path: '/api/docs', desc: 'API documentation', severity: 'low' },
        { path: '/swagger', desc: 'Swagger API docs', severity: 'low' },
        { path: '/swagger-ui.html', desc: 'Swagger UI', severity: 'low' },
        { path: '/api/swagger.json', desc: 'Swagger JSON spec', severity: 'low' },
        { path: '/graphql', desc: 'GraphQL endpoint', severity: 'medium' },
        { path: '/.htaccess', desc: 'Apache config file', severity: 'high' },
        { path: '/.htpasswd', desc: 'Apache password file', severity: 'critical' },
        { path: '/web.config', desc: 'IIS config file', severity: 'high' },
        { path: '/elmah.axd', desc: 'ASP.NET error log', severity: 'high' },
        { path: '/trace.axd', desc: 'ASP.NET trace', severity: 'high' },
        { path: '/backup.zip', desc: 'Backup archive', severity: 'critical' },
        { path: '/backup.tar.gz', desc: 'Backup archive', severity: 'critical' },
        { path: '/backup.sql', desc: 'Database backup', severity: 'critical' },
        { path: '/db.sql', desc: 'Database dump', severity: 'critical' },
        { path: '/dump.sql', desc: 'Database dump', severity: 'critical' },
        { path: '/database.sql', desc: 'Database dump', severity: 'critical' },
        { path: '/config.php', desc: 'PHP config file', severity: 'high' },
        { path: '/config.yml', desc: 'YAML config', severity: 'high' },
        { path: '/config.json', desc: 'JSON config', severity: 'high' },
        { path: '/package.json', desc: 'Node.js package info', severity: 'low' },
        { path: '/composer.json', desc: 'PHP Composer dependencies', severity: 'low' },
        { path: '/Dockerfile', desc: 'Docker configuration', severity: 'medium' },
        { path: '/docker-compose.yml', desc: 'Docker Compose config', severity: 'medium' },
        { path: '/.dockerignore', desc: 'Docker ignore file', severity: 'low' },
        { path: '/.npmrc', desc: 'NPM config (may contain tokens)', severity: 'high' },
        { path: '/Makefile', desc: 'Build instructions', severity: 'low' },
        { path: '/README.md', desc: 'Readme file', severity: 'info' },
        { path: '/CHANGELOG.md', desc: 'Changelog', severity: 'info' },
        { path: '/LICENSE', desc: 'License file', severity: 'info' },
    ];

    const found = [];
    const findings = [];
    const BATCH = 8;

    for (let i = 0; i < paths.length; i += BATCH) {
        const batch = paths.slice(i, i + BATCH);
        if (send) send('status', { module: 'files', message: `Checking files ${i+1}-${Math.min(i+BATCH, paths.length)}/${paths.length}...` });
        const results = await Promise.allSettled(
            batch.map(async (p) => {
                try {
                    const resp = await client.get(`${baseUrl}${p.path}`, { timeout: 6000, maxContentLength: 500000 });
                    if (resp.status === 200 && resp.data && String(resp.data).length > 0) {
                        // Verify it's not a custom 404 page by checking content length and patterns
                        const body = String(resp.data);
                        const is404Page = body.toLowerCase().includes('not found') || body.toLowerCase().includes('404') || body.length < 20;

                        // Special checks for known file types
                        if (!validateSensitiveBody(p.path, body) && !['/robots.txt', '/sitemap.xml', '/security.txt', '/.well-known/security.txt', '/README.md', '/CHANGELOG.md', '/LICENSE'].includes(p.path)) return null;

                        if (!is404Page || p.path === '/robots.txt' || p.path === '/sitemap.xml') {
                            return { ...p, status: resp.status, size: body.length, snippet: body.substring(0, 300) };
                        }
                    }
                    return null;
                } catch (e) { return null; }
            })
        );
        for (const r of results) {
            if (r.status === 'fulfilled' && r.value) {
                found.push(r.value);
                if (r.value.severity !== 'info') {
                    findings.push({ title: `Exposed file: ${r.value.path}`, detail: r.value.desc, severity: r.value.severity, module: 'files' });
                }
            }
        }
    }

    return { scanned: paths.length, found, findings };
}

/* ---------- CORS Misconfiguration ---------- */
async function testCORS(baseUrl) {
    const findings = [];
    const results = [];
    const origins = [
        'https://evil.com',
        'https://attacker.com',
        'null',
        new URL(baseUrl).origin
    ];

    for (const origin of origins) {
        try {
            const resp = await client.get(baseUrl, {
                headers: { ...client.defaults.headers, 'Origin': origin }
            });
            const acao = resp.headers['access-control-allow-origin'];
            const acac = resp.headers['access-control-allow-credentials'];
            results.push({ origin, acao: acao || null, acac: acac || null });

            if (acao === '*') {
                findings.push({ title: 'CORS allows all origins (*)', detail: 'Any website can read responses', severity: 'medium', module: 'cors' });
            } else if (acao === origin && origin !== new URL(baseUrl).origin) {
                findings.push({ title: `CORS reflects arbitrary origin: ${origin}`, detail: `Access-Control-Allow-Origin: ${acao}`, severity: 'high', module: 'cors' });
                if (acac === 'true') {
                    findings.push({ title: 'CORS reflects origin with credentials!', detail: 'Attacker can steal authenticated data', severity: 'critical', module: 'cors' });
                }
            } else if (acao === 'null') {
                findings.push({ title: 'CORS allows null origin', detail: 'Sandboxed iframes can exploit this', severity: 'medium', module: 'cors' });
            }
        } catch (e) {
            results.push({ origin, error: e.message });
        }
    }

    return { results, findings };
}

/* ---------- XSS Testing ---------- */
async function testXSS(baseUrl, crawlResult, send) {
    const findings = [];
    const tested = [];
    const payloads = [
        { payload: '<script>alert("XSS")</script>', name: 'Basic script tag' },
        { payload: '"><img src=x onerror=alert(1)>', name: 'Img onerror' },
        { payload: "'-alert(1)-'", name: 'JS context break' },
        { payload: '<svg/onload=alert(1)>', name: 'SVG onload' },
        { payload: '{{7*7}}', name: 'Template injection' },
        { payload: '${7*7}', name: 'Template literal' },
        { payload: '<details open ontoggle=alert(1)>', name: 'HTML5 event' },
    ];

    const marker = `xss${crypto.randomBytes(4).toString('hex')}`;

    // Test URL parameters
    for (const paramUrl of crawlResult.paramUrls.slice(0, 10)) {
        const parsed = new URL(paramUrl);
        for (const [key, val] of parsed.searchParams) {
            // First test with harmless marker to see if it reflects
            parsed.searchParams.set(key, marker);
            try {
                if (send) send('status', { module: 'xss', message: `Testing param "${key}" on ${parsed.pathname}` });
                const resp = await client.get(parsed.href, { timeout: 8000 });
                const body = String(resp.data);
                if (body.includes(marker)) {
                    // Parameter reflects — now test with actual payloads
                    tested.push({ url: paramUrl, param: key, reflects: true });
                    for (const pl of payloads) {
                        parsed.searchParams.set(key, pl.payload);
                        try {
                            const r2 = await client.get(parsed.href, { timeout: 8000 });
                            const b2 = String(r2.data);
                            if (b2.includes(pl.payload)) {
                                findings.push({
                                    title: `Reflected XSS: parameter "${key}" reflects unencoded payload`,
                                    detail: `URL: ${parsed.pathname}?${key}=... | Payload: ${pl.name} | The payload appears unmodified in the response.`,
                                    severity: 'high',
                                    module: 'xss',
                                    evidence: { url: parsed.href, payload: pl.payload, param: key }
                                });
                                break; // One proof is enough per param
                            }
                        } catch (e) { }
                    }
                } else {
                    tested.push({ url: paramUrl, param: key, reflects: false });
                }
            } catch (e) { }
        }
    }

    // Test forms
    for (const form of crawlResult.forms.slice(0, 8)) {
        for (const input of form.inputs.filter(i => i.name && i.type !== 'hidden' && i.type !== 'submit')) {
            // Build form data with marker
            const formData = {};
            for (const inp of form.inputs) {
                formData[inp.name] = inp.name === input.name ? marker : (inp.value || 'test');
            }
            try {
                if (send) send('status', { module: 'xss', message: `Testing form input "${input.name}" on ${form.action}` });
                let resp;
                if (form.method === 'POST') {
                    resp = await client.post(form.action, new URLSearchParams(formData).toString(), {
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 8000
                    });
                } else {
                    const u = new URL(form.action);
                    for (const [k, v] of Object.entries(formData)) u.searchParams.set(k, v);
                    resp = await client.get(u.href, { timeout: 8000 });
                }
                const body = String(resp.data);
                if (body.includes(marker)) {
                    tested.push({ form: form.action, input: input.name, reflects: true });
                    for (const pl of payloads) {
                        formData[input.name] = pl.payload;
                        let r2;
                        if (form.method === 'POST') {
                            r2 = await client.post(form.action, new URLSearchParams(formData).toString(), {
                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 8000
                            });
                        } else {
                            const u2 = new URL(form.action);
                            for (const [k, v] of Object.entries(formData)) u2.searchParams.set(k, v);
                            r2 = await client.get(u2.href, { timeout: 8000 });
                        }
                        if (String(r2.data).includes(pl.payload)) {
                            findings.push({
                                title: `Reflected XSS via form input "${input.name}"`,
                                detail: `Form action: ${form.action} | Method: ${form.method} | Payload: ${pl.name}`,
                                severity: 'high',
                                module: 'xss',
                                evidence: { form: form.action, input: input.name, payload: pl.payload }
                            });
                            break;
                        }
                    }
                }
            } catch (e) { }
        }
    }

    return { tested, findings };
}

/* ---------- SQL Injection Testing ---------- */
async function testSQLi(baseUrl, crawlResult, send) {
    const findings = [];
    const tested = [];

    const payloads = [
        { payload: "'",                        name: 'Single quote' },
        { payload: "' OR '1'='1",              name: 'OR tautology' },
        { payload: "' OR '1'='1' --",          name: 'OR tautology + comment' },
        { payload: "1' AND '1'='2",            name: 'AND false' },
        { payload: "1 UNION SELECT NULL--",    name: 'UNION SELECT' },
        { payload: "1; WAITFOR DELAY '0:0:3'", name: 'Time-based (MSSQL)' },
        { payload: "1' AND SLEEP(3)--",        name: 'Time-based (MySQL)' },
    ];

    const errorPatterns = [
        /SQL syntax.*?MySQL/i,
        /Warning.*?mysql_/i,
        /MySqlException/i,
        /valid MySQL result/i,
        /PostgreSQL.*?ERROR/i,
        /pg_query\(\)/i,
        /ORA-\d{5}/i,
        /Oracle.*?Driver/i,
        /Microsoft.*?ODBC/i,
        /SQL Server.*?Error/i,
        /SQLITE_ERROR/i,
        /sqlite3\.OperationalError/i,
        /Unclosed quotation mark/i,
        /quoted string not properly terminated/i,
        /You have an error in your SQL syntax/i,
        /SQLSTATE\[/i,
        /PDOException/i,
        /unterminated string/i,
    ];

    // Test URL parameters
    for (const paramUrl of crawlResult.paramUrls.slice(0, 10)) {
        const parsed = new URL(paramUrl);
        for (const [key, origVal] of parsed.searchParams) {
            // Get baseline response
            let baselineResp;
            try { baselineResp = await client.get(paramUrl, { timeout: 8000 }); } catch (e) { continue; }
            const baselineLen = String(baselineResp.data).length;

            for (const pl of payloads) {
                parsed.searchParams.set(key, pl.payload);
                try {
                    if (send) send('status', { module: 'sqli', message: `SQLi test "${key}" [${pl.name}]` });
                    const startTime = Date.now();
                    const resp = await client.get(parsed.href, { timeout: 15000 });
                    const elapsed = Date.now() - startTime;
                    const body = String(resp.data);

                    // Check for SQL error messages
                    for (const pattern of errorPatterns) {
                        if (pattern.test(body)) {
                            findings.push({
                                title: `SQL error triggered: parameter "${key}"`,
                                detail: `URL: ${parsed.pathname} | Payload: ${pl.name} | Error pattern matched: ${pattern.source.substring(0, 60)}`,
                                severity: 'critical',
                                module: 'sqli',
                                evidence: { url: parsed.href, param: key, payload: pl.payload, pattern: pattern.source }
                            });
                            break;
                        }
                    }

                    // Check for time-based blind SQLi
                    if (pl.name.startsWith('Time-based') && elapsed > 2800) {
                        findings.push({
                            title: `Potential time-based blind SQLi: parameter "${key}"`,
                            detail: `URL: ${parsed.pathname} | Payload: ${pl.name} | Response time: ${elapsed}ms (>2800ms threshold)`,
                            severity: 'high',
                            module: 'sqli',
                            evidence: { url: parsed.href, param: key, payload: pl.payload, responseTime: elapsed }
                        });
                    }

                    // Check for significant content length difference (boolean-based)
                    const respLen = body.length;
                    const diff = Math.abs(respLen - baselineLen);
                    if (diff > baselineLen * 0.3 && diff > 200 && pl.name.includes('OR')) {
                        tested.push({ url: paramUrl, param: key, payload: pl.name, contentDiff: diff, suspicious: true });
                    }

                } catch (e) { }
            }
            parsed.searchParams.set(key, origVal); // restore
        }
    }

    // Test forms similarly
    for (const form of crawlResult.forms.slice(0, 5)) {
        for (const input of form.inputs.filter(i => i.name && i.type !== 'hidden' && i.type !== 'submit' && i.type !== 'file')) {
            for (const pl of payloads.slice(0, 3)) { // test fewer payloads on forms
                const formData = {};
                for (const inp of form.inputs) {
                    formData[inp.name] = inp.name === input.name ? pl.payload : (inp.value || 'test');
                }
                try {
                    if (send) send('status', { module: 'sqli', message: `SQLi form test "${input.name}" [${pl.name}]` });
                    let resp;
                    if (form.method === 'POST') {
                        resp = await client.post(form.action, new URLSearchParams(formData).toString(), {
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 8000
                        });
                    } else {
                        const u = new URL(form.action);
                        for (const [k, v] of Object.entries(formData)) u.searchParams.set(k, v);
                        resp = await client.get(u.href, { timeout: 8000 });
                    }
                    const body = String(resp.data);
                    for (const pattern of errorPatterns) {
                        if (pattern.test(body)) {
                            findings.push({
                                title: `SQL error via form input "${input.name}"`,
                                detail: `Form: ${form.action} | Method: ${form.method} | Payload: ${pl.name}`,
                                severity: 'critical',
                                module: 'sqli',
                                evidence: { form: form.action, input: input.name, payload: pl.payload }
                            });
                            break;
                        }
                    }
                } catch (e) { }
            }
        }
    }

    return { tested, findings };
}

/* ---------- Open Redirect ---------- */
async function testOpenRedirect(baseUrl, crawlResult) {
    const findings = [];
    const tested = [];
    const evilUrl = 'https://evil.com';
    const redirectParams = ['url', 'redirect', 'next', 'return', 'returnurl', 'return_url', 'redirect_uri', 'continue', 'dest', 'destination', 'redir', 'target', 'go', 'goto', 'link', 'forward', 'out', 'view'];

    for (const paramUrl of crawlResult.paramUrls.slice(0, 15)) {
        const parsed = new URL(paramUrl);
        for (const [key] of parsed.searchParams) {
            if (redirectParams.includes(key.toLowerCase())) {
                parsed.searchParams.set(key, evilUrl);
                try {
                    const resp = await client.get(parsed.href, { maxRedirects: 0, validateStatus: () => true, timeout: 8000 });
                    const location = resp.headers['location'] || '';
                    if (location.includes('evil.com') || (resp.status >= 300 && resp.status < 400 && location.startsWith('https://evil'))) {
                        findings.push({
                            title: `Open redirect via parameter "${key}"`,
                            detail: `URL: ${parsed.pathname} | Redirects to: ${location}`,
                            severity: 'medium',
                            module: 'redirect',
                            evidence: { url: parsed.href, param: key, redirectTo: location }
                        });
                    }
                    tested.push({ url: paramUrl, param: key, redirectsToEvil: location.includes('evil.com') });
                } catch (e) { }
            }
        }
    }

    return { tested, findings };
}

/* ---------- LFI / Path Traversal ---------- */
async function testLFI(baseUrl, crawlResult, send) {
    const findings = [];
    const tested = [];

    const payloads = [
        { payload: '../../../../etc/passwd', name: 'Linux passwd', pattern: /root:.*?:0:0/ },
        { payload: '..\\..\\..\\..\\windows\\win.ini', name: 'Windows win.ini', pattern: /\[fonts\]|\[extensions\]/i },
        { payload: '....//....//....//etc/passwd', name: 'Filter bypass 1', pattern: /root:.*?:0:0/ },
        { payload: '/%2e%2e/%2e%2e/%2e%2e/etc/passwd', name: 'URL encoded', pattern: /root:.*?:0:0/ },
        { payload: '/etc/passwd%00', name: 'Null byte', pattern: /root:.*?:0:0/ },
        { payload: 'php://filter/convert.base64-encode/resource=index.php', name: 'PHP filter wrapper', pattern: /^[A-Za-z0-9+\/=]{50,}$/ },
    ];

    const fileParams = ['file', 'page', 'path', 'doc', 'document', 'folder', 'root', 'include', 'inc', 'locate', 'show', 'site', 'template', 'view', 'content', 'layout', 'mod', 'conf', 'lang', 'pdf', 'filename'];

    for (const paramUrl of crawlResult.paramUrls.slice(0, 10)) {
        const parsed = new URL(paramUrl);
        for (const [key, origVal] of parsed.searchParams) {
            if (fileParams.includes(key.toLowerCase()) || origVal.match(/\.(php|html|txt|log|xml|json|jsp|asp)$/i)) {
                for (const pl of payloads) {
                    parsed.searchParams.set(key, pl.payload);
                    try {
                        if (send) send('status', { module: 'lfi', message: `LFI test "${key}" [${pl.name}]` });
                        const resp = await client.get(parsed.href, { timeout: 8000 });
                        const body = String(resp.data);
                        if (pl.pattern.test(body)) {
                            findings.push({
                                title: `Path traversal / LFI: parameter "${key}"`,
                                detail: `URL: ${parsed.pathname} | Payload: ${pl.name}`,
                                severity: 'critical',
                                module: 'lfi',
                                evidence: { url: parsed.href, param: key, payload: pl.payload }
                            });
                            break;
                        }
                    } catch (e) { }
                }
                parsed.searchParams.set(key, origVal);
                tested.push({ url: paramUrl, param: key });
            }
        }
    }

    return { tested, findings };
}


/* ---------- Application Exposure Checks ---------- */
async function scanExposure(baseUrl, crawlResult = {}, send) {
    const findings = [], methods = [], directories = [], endpoints = [], secrets = [], sourceMaps = [];
    const origin = new URL(baseUrl).origin;
    const methodTargets = [...new Set([baseUrl, ...(crawlResult.pages || []).map(p => p.url).filter(Boolean).slice(0, 2)])];
    for (const target of methodTargets) {
        try {
            if (send) send('status', { module: 'exposure', message: `Checking HTTP methods: ${new URL(target).pathname || '/'}` });
            const resp = await client.options(target, { timeout: 6000 });
            const allow = String(resp.headers['allow'] || resp.headers['access-control-allow-methods'] || '');
            const risky = allow.split(',').map(m => m.trim().toUpperCase()).filter(m => ['TRACE', 'PUT', 'DELETE', 'CONNECT', 'PATCH'].includes(m));
            if (allow) methods.push({ url: target, allow, risky });
            for (const m of risky) findings.push({ title: `Risky HTTP method advertised: ${m}`, detail: `${target} allows: ${allow}`, severity: m === 'TRACE' ? 'high' : 'medium', module: 'exposure', evidence: { url: target, method: m } });
        } catch (e) { }
    }
    const dirPaths = ['/uploads/', '/files/', '/backup/', '/backups/', '/static/', '/assets/', '/images/', '/downloads/'];
    for (const pathName of dirPaths) {
        try {
            if (send) send('status', { module: 'exposure', message: `Checking directory listing: ${pathName}` });
            const resp = await client.get(origin + pathName, { timeout: 6000, maxContentLength: LIMITS.maxResponseBytes });
            const body = String(resp.data || '');
            const matched = directoryListingPattern(body);
            if (resp.status === 200 && matched) {
                const severity = /backup|upload|download|files/i.test(pathName) ? 'high' : 'medium';
                directories.push({ path: pathName, status: resp.status, matchedPattern: matched });
                findings.push({ title: `Directory listing exposed: ${pathName}`, detail: `Matched pattern: ${matched}`, severity, module: 'exposure', evidence: { path: pathName, pattern: matched } });
            }
        } catch (e) { }
    }
    const exposurePaths = ['/.env', '/.env.local', '/.env.production', '/config.js', '/config.json', '/actuator', '/actuator/env', '/actuator/health', '/actuator/metrics', '/debug', '/debug/vars', '/__debugger__', '/webpack-dev-server', '/swagger-ui.html', '/swagger/', '/api-docs', '/api/docs', '/openapi.json', '/swagger.json', '/v3/api-docs', '/graphql'];
    for (const pathName of exposurePaths) {
        try {
            if (send) send('status', { module: 'exposure', message: `Checking endpoint: ${pathName}` });
            const resp = await client.get(origin + pathName, { timeout: 6000, maxContentLength: LIMITS.maxResponseBytes });
            const hit = classifyExposureEndpoint(pathName, resp, String(resp.data || ''));
            if (hit) {
                endpoints.push({ path: pathName, status: resp.status, type: hit.type, evidence: hit.evidence });
                findings.push({ title: hit.title, detail: hit.detail, severity: hit.severity, module: 'exposure', evidence: { path: pathName, type: hit.type } });
            }
        } catch (e) { }
    }
    const scriptUrls = [...new Set(crawlResult.scripts || [])].filter(u => u.startsWith(origin)).slice(0, LIMITS.exposureScripts);
    for (const scriptUrl of scriptUrls) {
        try {
            if (send) send('status', { module: 'exposure', message: `Scanning JavaScript: ${new URL(scriptUrl).pathname}` });
            const resp = await client.get(scriptUrl, { timeout: 7000, maxContentLength: LIMITS.maxResponseBytes });
            const body = String(resp.data || '');
            for (const hit of findClientSecrets(body)) {
                const item = { file: scriptUrl, type: hit.type, redacted: hit.redacted };
                secrets.push(item);
                findings.push({ title: `Potential client-side secret in JavaScript (${hit.type})`, detail: `${new URL(scriptUrl).pathname}: ${hit.redacted}`, severity: hit.severity, module: 'exposure', evidence: item });
            }
            const sm = body.match(/\/\/[#@]\s*sourceMappingURL=([^\s]+)/);
            if (sm) {
                const mapUrl = new URL(sm[1], scriptUrl).href;
                let fetchable = false;
                try {
                    const mapResp = await client.get(mapUrl, { timeout: 5000, maxContentLength: LIMITS.maxResponseBytes });
                    fetchable = mapResp.status === 200 && /"sources"\s*:|"version"\s*:/i.test(String(mapResp.data || ''));
                } catch (e) { }
                sourceMaps.push({ file: scriptUrl, mapUrl, fetchable });
                findings.push({ title: 'JavaScript source map reference exposed', detail: `${new URL(scriptUrl).pathname} -> ${new URL(mapUrl).pathname}${fetchable ? ' (fetchable)' : ''}`, severity: fetchable ? 'medium' : 'low', module: 'exposure', evidence: { file: scriptUrl, fetchable } });
            }
        } catch (e) { }
    }
    return { checked: { methods: methodTargets.length, directories: dirPaths.length, endpoints: exposurePaths.length, scripts: scriptUrls.length }, methods, directories, endpoints, secrets, sourceMaps, findings };
}

function directoryListingPattern(body) {
    const patterns = [/Index of \//i, /<title>Index of/i, /Parent Directory/i, /Directory Listing For/i, /nginx autoindex/i];
    const found = patterns.find(p => p.test(body));
    return found ? found.source : null;
}

function classifyExposureEndpoint(pathName, resp, body) {
    if (resp.status < 200 || resp.status >= 400) return null;
    const b = String(body || '');
    if (pathName.includes('.env') && validateSensitiveBody(pathName, b)) return { type: 'environment', title: `Environment file exposed: ${pathName}`, detail: 'Environment-style key/value content is publicly reachable', severity: 'critical', evidence: 'env' };
    if (/config\.(json|js)$/.test(pathName) && /(api[_-]?key|secret|token|database|password|clientid|client_id)/i.test(b)) return { type: 'config', title: `Configuration file may be exposed: ${pathName}`, detail: 'Configuration content contains sensitive-looking keys', severity: 'high', evidence: 'config' };
    if (pathName.startsWith('/actuator') && /(spring|beans|health|metrics|env|management)/i.test(b)) return { type: 'actuator', title: `Spring Boot Actuator endpoint exposed: ${pathName}`, detail: 'Actuator endpoint is reachable without authentication', severity: pathName.includes('env') ? 'high' : 'medium', evidence: 'actuator' };
    if ((pathName.startsWith('/debug') || pathName === '/__debugger__') && /(debug|trace|vars|goroutine|stack|werkzeug|console)/i.test(b)) return { type: 'debug', title: `Debug endpoint exposed: ${pathName}`, detail: 'Debug/diagnostic endpoint is reachable', severity: 'high', evidence: 'debug' };
    if (/swagger|api-docs|openapi/i.test(pathName) && /(openapi|swagger|"paths"\s*:|Swagger UI)/i.test(b)) return { type: 'api-docs', title: `API documentation exposed: ${pathName}`, detail: 'Public API documentation/specification is reachable', severity: 'medium', evidence: 'api-docs' };
    if (pathName === '/graphql' && /(graphql|GraphQL|query|mutation|Cannot query field|must provide query)/i.test(b)) return { type: 'graphql', title: 'GraphQL endpoint discovered', detail: 'GraphQL endpoint appears reachable; review introspection and auth controls', severity: 'info', evidence: 'graphql' };
    return null;
}

function findClientSecrets(body) {
    const text = String(body || '');
    const patterns = [
        { type: 'AWS Access Key ID', re: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
        { type: 'Google API Key', re: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
        { type: 'GitHub Token', re: /(?:ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{20,})/g, severity: 'critical' },
        { type: 'Slack Token', re: /xox[baprs]-[0-9A-Za-z-]{20,}/g, severity: 'critical' },
        { type: 'Secret-like assignment', re: /(?:api[_-]?key|secret|token|client[_-]?secret|private[_-]?key)\s*[:=]\s*['"]([^'"]{12,})['"]/gi, severity: 'high' }
    ];
    const hits = [];
    for (const p of patterns) {
        let m;
        while ((m = p.re.exec(text)) && hits.length < 20) {
            const value = m[1] || m[0];
            hits.push({ type: p.type, redacted: redactSecret(value), severity: p.severity });
        }
    }
    return hits;
}

/* ---------- SSL/TLS Analysis ---------- */
function analyzeSSL(domain) {
    return new Promise((resolve) => {
        const findings = [];
        const result = { supported: false, protocols: [], certificate: null, findings };

        const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
            result.supported = true;
            const cert = socket.getPeerCertificate();
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();

            result.protocol = protocol;
            result.cipher = cipher;
            result.authorized = socket.authorized;
            result.authorizationError = socket.authorizationError || null;
            if (!socket.authorized && socket.authorizationError) {
                findings.push({ title: 'Certificate chain is not trusted', detail: socket.authorizationError, severity: 'high', module: 'ssl' });
            }
            const identityError = tls.checkServerIdentity(domain, cert);
            if (identityError) {
                findings.push({ title: 'Certificate hostname mismatch', detail: identityError.message, severity: 'high', module: 'ssl' });
            }
            if (!cert.subjectaltname) {
                findings.push({ title: 'Certificate missing Subject Alternative Name', severity: 'medium', module: 'ssl' });
            }
            result.certificate = {
                subject: cert.subject,
                issuer: cert.issuer,
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                serialNumber: cert.serialNumber,
                fingerprint: cert.fingerprint256,
                subjectAltName: cert.subjectaltname,
                bits: cert.bits
            };

            // Check expiry
            const expiry = new Date(cert.valid_to);
            const now = new Date();
            const daysLeft = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
            if (daysLeft < 0) {
                findings.push({ title: 'SSL certificate has EXPIRED', detail: `Expired: ${cert.valid_to}`, severity: 'critical', module: 'ssl' });
            } else if (daysLeft < 30) {
                findings.push({ title: `SSL certificate expires in ${daysLeft} days`, detail: `Expires: ${cert.valid_to}`, severity: 'high', module: 'ssl' });
            } else if (daysLeft < 90) {
                findings.push({ title: `SSL certificate expires in ${daysLeft} days`, detail: `Expires: ${cert.valid_to}`, severity: 'medium', module: 'ssl' });
            }
            result.daysUntilExpiry = daysLeft;

            // Self-signed check
            if (cert.issuer && cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject)) {
                findings.push({ title: 'Self-signed SSL certificate detected', severity: 'high', module: 'ssl' });
            }

            // Key size
            if (cert.bits && cert.bits < 2048) {
                findings.push({ title: `Weak key size: ${cert.bits} bits`, severity: 'high', module: 'ssl' });
            }

            // Check for weak protocol
            if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
                findings.push({ title: `Deprecated TLS version: ${protocol}`, severity: 'medium', module: 'ssl' });
            }

            socket.end();
            resolve(result);
        });

        socket.on('error', (err) => {
            findings.push({ title: `SSL connection failed: ${err.message}`, severity: 'high', module: 'ssl' });
            resolve(result);
        });

        socket.setTimeout(10000, () => {
            findings.push({ title: 'SSL connection timed out', severity: 'medium', module: 'ssl' });
            socket.destroy();
            resolve(result);
        });
    });
}

/* ---------- DNS Enumeration ---------- */
async function enumerateDNS(domain) {
    const findings = [];
    const records = {};

    const types = [
        { type: 'A', fn: 'resolve4' },
        { type: 'AAAA', fn: 'resolve6' },
        { type: 'MX', fn: 'resolveMx' },
        { type: 'NS', fn: 'resolveNs' },
        { type: 'TXT', fn: 'resolveTxt' },
        { type: 'CNAME', fn: 'resolveCname' },
        { type: 'SOA', fn: 'resolveSoa' },
    ];

    for (const t of types) {
        try {
            records[t.type] = await dns[t.fn](domain);
        } catch (e) {
            records[t.type] = null;
        }
    }

    // Check for SPF
    if (records.TXT) {
        const txtFlat = records.TXT.flat().map(String);
        const spfRecords = txtFlat.filter(r => /v=spf1/i.test(r));
        const hasSPF = spfRecords.length > 0;
        if (!hasSPF) findings.push({ title: 'No SPF record found', detail: 'Email spoofing possible', severity: 'medium', module: 'dns' });
        if (spfRecords.length > 1) findings.push({ title: 'Multiple SPF records found', detail: spfRecords.join(' | '), severity: 'medium', module: 'dns' });
        for (const spf of spfRecords) {
            if (/\+all/i.test(spf)) findings.push({ title: 'SPF permits all senders (+all)', detail: spf, severity: 'high', module: 'dns' });
            if (/~all/i.test(spf)) findings.push({ title: 'SPF uses softfail (~all)', detail: spf, severity: 'low', module: 'dns' });
        }

        const hasDMARC = txtFlat.some(r => /v=DMARC1/i.test(r));
        if (!hasDMARC) {
            // Check _dmarc subdomain
            try {
                const dmarc = await dns.resolveTxt(`_dmarc.${domain}`);
                const dmarcRecords = dmarc.flat().map(String).filter(r => /v=DMARC1/i.test(r));
                if (!dmarcRecords.length) throw new Error();
                for (const rec of dmarcRecords) {
                    if (/p=none/i.test(rec)) findings.push({ title: 'DMARC policy is monitoring only (p=none)', detail: rec, severity: 'medium', module: 'dns' });
                    if (!/rua=/i.test(rec)) findings.push({ title: 'DMARC record missing aggregate report URI (rua)', detail: rec, severity: 'info', module: 'dns' });
                }
            } catch (e) {
                findings.push({ title: 'No DMARC record found', detail: 'Email spoofing possible', severity: 'medium', module: 'dns' });
            }
        }
    }

    // Zone transfer attempt
    try {
        if (records.NS) {
            findings.push({ title: `${records.NS.length} nameservers found`, detail: records.NS.join(', '), severity: 'info', module: 'dns' });
        }
    } catch (e) { }

    return { domain, records, findings };
}

/* ---------- Subdomain Discovery ---------- */
async function discoverSubdomains(domain, send) {
    const findings = [];
    const found = [];

    // Method 1: Common subdomain brute-force via DNS
    const wordlist = [
        'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns3',
        'blog', 'dev', 'staging', 'api', 'app', 'cdn', 'static', 'media', 'shop',
        'store', 'portal', 'vpn', 'remote', 'test', 'beta', 'demo', 'docs', 'help',
        'support', 'status', 'm', 'mobile', 'img', 'images', 'assets', 'git',
        'jenkins', 'ci', 'jira', 'confluence', 'wiki', 'dashboard', 'cloud',
        'login', 'sso', 'auth', 'oauth', 'secure', 'gateway', 'proxy',
        'monitor', 'nagios', 'grafana', 'kibana', 'elastic', 'prometheus',
        'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'cache',
        'backup', 'bak', 'old', 'new', 'v2', 'v3', 'sandbox', 'stage',
        'internal', 'intranet', 'extranet', 'uat', 'qa', 'preprod'
    ];

    const BATCH = 10;
    for (let i = 0; i < wordlist.length; i += BATCH) {
        const batch = wordlist.slice(i, i + BATCH);
        if (send) send('status', { module: 'subdomains', message: `DNS brute-force ${i+1}-${Math.min(i+BATCH, wordlist.length)}/${wordlist.length}...` });
        const results = await Promise.allSettled(
            batch.map(async (sub) => {
                const fqdn = `${sub}.${domain}`;
                try {
                    const addrs = await dns.resolve4(fqdn);
                    return { subdomain: fqdn, ip: addrs, source: 'dns-bruteforce' };
                } catch (e) { return null; }
            })
        );
        for (const r of results) {
            if (r.status === 'fulfilled' && r.value) found.push(r.value);
        }
    }

    // Method 2: Certificate Transparency logs
    if (send) send('status', { module: 'subdomains', message: 'Querying Certificate Transparency logs...' });
    try {
        const ctResp = await axios.get(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 15000 });
        if (Array.isArray(ctResp.data)) {
            const ctDomains = new Set();
            for (const entry of ctResp.data) {
                const names = (entry.name_value || '').split('\n');
                for (const name of names) {
                    const clean = name.trim().toLowerCase().replace(/^\*\./, '');
                    if (clean.endsWith(domain) && clean !== domain && !clean.includes('*')) {
                        ctDomains.add(clean);
                    }
                }
            }
            for (const sub of ctDomains) {
                if (!found.some(f => f.subdomain === sub)) {
                    found.push({ subdomain: sub, ip: null, source: 'crt.sh' });
                }
            }
        }
    } catch (e) { }

    if (found.length > 0) {
        findings.push({ title: `${found.length} subdomains discovered for ${domain}`, severity: 'info', module: 'subdomains' });
    }

    return { domain, found, findings };
}

/* ---------- Start Server ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗           ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗         ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝         ║
║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝          ║
║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║               ║
║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝              ║
║                                                              ║
║  CyberPulse v3.1 — Advanced Web Vulnerability Scanner       ║
║  Server running at http://localhost:${PORT}                     ║
║                                                              ║
║  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    `);
});
