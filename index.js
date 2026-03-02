#!/usr/bin/env node

import fetch from "node-fetch";
import { JSDOM } from "jsdom";
import { program } from "commander";
import chalk from "chalk";
import fs from "fs";
import https from "https";
import path from "path";
import * as XLSX from "xlsx";
import * as acorn from "acorn";

// =========================
// Configuration & Utilities
// =========================

// Regexes
const endpointRegex = /\/[a-zA-Z0-9_?&=\/\-#\.]+/g;
const jsFileRegex = /(?:\/|https?:\/\/)[a-zA-Z0-9_?&=\/\-#\.]+\.js(?:\?[^"'%60]*)?/g;

// Heuristic classification
const endpointCategories = [
  { label: "API", test: p => /^\/api\b|\/v\d+\/|\/graphql\b|\/rest\b/i.test(p) },
  { label: "Admin", test: p => /\/admin\b|\/dashboard\b|\/manage\b/i.test(p) },
  { label: "Auth", test: p => /\/login\b|\/logout\b|\/oauth\b|\/sso\b/i.test(p) },
  { label: "Static", test: p => /\.(css|png|jpg|jpeg|gif|svg|ico|webp|woff2?|ttf|map)(\?|$)/i.test(p) },
  { label: "API docs", test: p => /\/swagger\b|\/redoc\b|\/openapi\b/i.test(p) },
];

// Parameter risk heuristics - expanded list of 15+ risky parameter patterns
const riskyParams = [
  // Authentication & Credentials
  /^password\b/i, /^passwd\b/i, /^pwd\b/i, /^pass\b/i,
  /^secret\b/i, /^api[_-]?key\b/i, /^apikey\b/i, /^auth\b/i,
  /^token\b/i, /^bearer\b/i, /^credential\b/i,
  
  // Session & Identity
  /^session[_-]?id\b/i, /^sessionid\b/i, /^sid\b/i,
  /^jwt\b/i, /^jti\b/i,
  /^csrf[_-]?token\b/i, /^csrf\b/i,
  
  // Query & Navigation (potential XSS)
  /^url\b/i, /^redirect\b/i, /^redirect[_-]?url\b/i, /^return[_-]?url\b/i,
  /^next\b/i, /^dest(ination)?\b/i, /^go[_-]?to\b/i, /^target\b/i,
  
  // User & Personal Data
  /^email\b/i, /^username\b/i, /^user[_-]?id\b/i, /^user[_-]?name\b/i,
  /^id\b/i, /^user\b/i, /^uid\b/i, /^userid\b/i,
  /^ssn\b/i, /^social[_-]?security\b/i,
  /^credit[_-]?card\b/i, /^cc\b/i, /^card\b/i,
  /^phone\b/i, /^telephone\b/i, /^mobile\b/i,
  /^date[_-]?of[_-]?birth\b/i, /^dob\b/i,
  
  // Search & Query
  /^q\b/i, /^query\b/i, /^search\b/i, /^keyword\b/i,
  
  // Admin & API Version
  /^admin\b/i, /^api[_-]?version\b/i, /^version\b/i, /^v\d+\b/i,
  
  // Debug & Internal
  /^debug\b/i, /^internal\b/i, /^private\b/i, /^secret\b/i
];

// Basic technology signatures (expandable)
const techSignatures = [
  { name: "Express", detector: ({ headers }) => /express/i.test(headers.get("x-powered-by") || "") },
  { name: "Next.js", detector: ({ html }) => /next\.js|__NEXT_DATA__/i.test(html) },
  { name: "React", detector: ({ html, assets }) => /react/i.test(html) || assets.some(a => /react(-dom)?/i.test(a)) },
  { name: "Angular", detector: ({ html, assets }) => /ng-version|angular/i.test(html) || assets.some(a => /angular/i.test(a)) },
  { name: "Vue.js", detector: ({ html, assets }) => /vue\.js|data-v-/i.test(html) || assets.some(a => /vue/i.test(a)) },
  { name: "Astro", detector: ({ html, assets }) => /astro/i.test(html) || assets.some(a => /_astro\//i.test(a)) },
  { name: "WordPress", detector: ({ html }) => /wp-content|wp-includes/i.test(html) },
  { name: "jQuery", detector: ({ assets }) => assets.some(a => /jquery.*\.js/i.test(a)) },
  { name: "Bootstrap", detector: ({ assets }) => assets.some(a => /bootstrap.*\.(css|js)/i.test(a)) },
  { name: "Netlify", detector: ({ html, assets }) => /netlify/i.test(html) || assets.some(a => /\/\.netlify\/scripts\//i.test(a)) },
  { name: "Vercel", detector: ({ headers }) => /vercel/i.test(headers.get("server") || "") },
];

// Resolve relative/protocol-relative URLs against a base
function resolveUrl(src, baseUrl) {
  try {
    return new URL(src, baseUrl).href;
  } catch {
    return null;
  }
}

// Concurrency runner with retry
async function runWithConcurrency(tasks, limit = 8) {
  const results = [];
  let i = 0;

  async function worker() {
    while (i < tasks.length) {
      const idx = i++;
      try {
        results[idx] = await tasks[idx]();
      } catch (e) {
        results[idx] = { error: e };
      }
    }
  }

  const workers = Array.from({ length: Math.max(1, limit) }, worker);
  await Promise.all(workers);
  return results;
}

async function fetchWithRetry(url, options, retries = 2, backoffMs = 400) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok && res.status >= 500 && attempt < retries) {
        await new Promise(r => setTimeout(r, backoffMs * (attempt + 1)));
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) await new Promise(r => setTimeout(r, backoffMs * (attempt + 1)));
    }
  }
  throw lastErr;
}

// =====================
// Data Stores per Scan
// =====================
function createStores() {
  return {
    endpoints: new Set(),
    parameters: new Map(),
    jsFiles: new Set(),
    technologies: new Set(),
    endpointTags: new Map(), // endpoint -> category labels
    riskyParameters: new Set(),
    findings: new Map(), // source -> [{ type, snippet, severity }]
    keys: [] // [{ source, type, key, snippet, severity }]
    ,requests: [] // [{ source, method, url, params, snippet }]
  };
}

// =====================
// Filename Generation
// =====================
/**
 * Generate a report filename based on the target (URL or path)
 * Extracts hostname from URL or uses directory/filename from local path
 */
function generateReportFilename(target, format = 'json') {
  let reportName = 'web-recon-report';
  const timestamp = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const extension = format === 'xlsx' ? 'xlsx' : 'json';
  
  try {
    // Check if target is a URL
    if (target.startsWith('http://') || target.startsWith('https://')) {
      const url = new URL(target);
      const hostname = url.hostname
        .replace(/^www\./, '') // Remove www. prefix
        .replace(/\./g, '-'); // Replace dots with hyphens
      reportName = `${hostname}_${timestamp}`;
    } else {
      // Local file or directory
      const isDir = fs.statSync(target).isDirectory();
      let name = isDir 
        ? path.basename(target) 
        : path.basename(target, '.js');
      
      // Sanitize name (remove special characters)
      name = name.replace(/[^a-zA-Z0-9_-]/g, '-').replace(/-+/g, '-');
      reportName = `${name}_${timestamp}`;
    }
  } catch (err) {
    // Fallback to generic name if parsing fails
    reportName = `web-recon-report_${timestamp}`;
  }
  
  return `${reportName}.${extension}`;
}

function addKey(stores, source, type, key, snippet, severity = "critical") {
  // Compute confidence score and store
  const keyStr = String(key).slice(0, 500);
  const snippetStr = String(snippet).slice(0, 500);
  const confidence = computeKeyConfidence(keyStr, snippetStr, type);
  stores.keys.push({ source, type, key: keyStr, snippet: snippetStr, severity, confidence });
}

function addRequest(stores, source, method, url, params, snippet) {
  stores.requests.push({ source, method: (method || "GET").toUpperCase(), url, params: params || [], snippet: String(snippet).slice(0, 500) });
}

function addFinding(stores, source, type, snippet, severity = "medium") {
  if (!stores.findings.has(source)) stores.findings.set(source, []);
  stores.findings.get(source).push({ type, snippet: snippet.slice(0, 500), severity });
}

function safeSnippet(text, matchIndex, context = 120) {
  if (!text) return "";
  if (typeof matchIndex === "number") {
    const start = Math.max(0, matchIndex - context);
    const end = Math.min(text.length, matchIndex + context);
    return text.slice(start, end).replace(/\s+/g, " ");
  }
  return String(text).replace(/\s+/g, " ");
}

// =====================
// Entropy & Confidence Scoring
// =====================
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Compute confidence score for a detected key based on entropy, length, and context
function computeKeyConfidence(key, snippet, detectorLabel) {
  let score = 0.0;
  
  // Base scores by detector type (high-confidence patterns get high base)
  const detectorScores = {
    googleApiKey: 0.95,      // Very specific prefix (AIza)
    awsAccessKeyId: 0.92,    // Specific prefix (AKIA/ASIA/AROA)
    stripeKey: 0.90,         // Specific prefix (sk_live/sk_test)
    sendgridKey: 0.88,       // Specific prefix (SG.)
    slackToken: 0.87,        // Specific prefix (xoxb/xoxp)
    githubToken: 0.86,       // Specific prefix (ghp_, gho_)
    twilioKey: 0.85,         // Specific prefix (AC/SK)
    pemPrivateKey: 0.98,     // Very specific block markers
    jwtLiteral: 0.80,        // JWT-like but could be benign base64
    hardcodedSecrets: 0.65,  // Generic, more false positives
    adminInternalKey: 0.60   // Heuristic-based, prone to FPs
  };
  
  score = detectorScores[detectorLabel] || 0.50;
  
  // Entropy modifier: high entropy = higher confidence (secrets are usually high-entropy)
  const keyEntropy = calculateEntropy(key);
  if (keyEntropy < 2.0) score *= 0.3;       // Low entropy = low confidence
  else if (keyEntropy < 3.0) score *= 0.6;  // Medium entropy = reduced confidence
  else if (keyEntropy >= 4.0) score *= 1.1; // High entropy = boosted confidence (capped at 1.0)
  
  // Length modifier: typical API keys are 20-200 chars
  const keyLen = key.length;
  if (keyLen < 12) score *= 0.4;       // Too short for most secrets
  else if (keyLen > 500) score *= 0.6; // Suspiciously long
  else if (keyLen >= 20 && keyLen <= 60) score *= 1.05; // Typical range
  
  // Context modifier: if nearby variable names suggest API/secret, boost confidence
  if (snippet && /\b(api[_-]?key|secret|token|auth|bearer|credential|password|key|private)\b/i.test(snippet)) {
    score *= 1.2;
  }
  
  return Math.min(score, 1.0); // Cap at 1.0
}

function addSheetWithOptions(wb, data, sheetName) {
  const ws = XLSX.utils.json_to_sheet(data.length ? data : []);
  if (data.length) {
    const range = XLSX.utils.decode_range(ws["!ref"]);
    ws["!autofilter"] = { ref: XLSX.utils.encode_range({ s: { r: 0, c: 0 }, e: range.e }) };
    ws["!freeze"] = { xSplit: 0, ySplit: 1, topLeftCell: "A2", activePane: "bottomLeft" };
  }
  XLSX.utils.book_append_sheet(wb, ws, sheetName);
}

// Export helper for XLSX
function exportResultsXLSX(outputFile, stores) {
  const wb = XLSX.utils.book_new();

  // Endpoints sheet
  const endpointsData = Array.from(stores.endpoints).map(e => ({
    Endpoint: e,
    Tags: (stores.endpointTags.get(e) || []).join(", ")
  }));
  addSheetWithOptions(wb, endpointsData, "Endpoints");

  // Parameters sheet
  const paramsData = Array.from(stores.parameters.entries()).map(([param, sources]) => {
    const counts = sources.reduce((acc, src) => {
      acc[src] = (acc[src] || 0) + 1;
      return acc;
    }, {});
    const summary = Object.entries(counts)
      .map(([src, count]) => `${src} (${count})`)
      .join(", ");
    return {
      Parameter: param,
      Occurrences: sources.length,
      Sources: summary,
      Risky: stores.riskyParameters.has(param) ? "Yes" : "No"
    };
  });
  addSheetWithOptions(wb, paramsData, "Parameters");

  // JS Files sheet
  const jsData = Array.from(stores.jsFiles).map(f => ({ JSFile: f }));
  addSheetWithOptions(wb, jsData, "JS Files");

  // Discovered Requests sheet
  const reqRows = (stores.requests || []).map(r => ({
    Source: r.source,
    Method: r.method,
    URL: r.url,
    Params: (r.params || []).join(', '),
    Snippet: r.snippet
  }));
  addSheetWithOptions(wb, reqRows, "Discovered Requests");

  // Technologies sheet
  const techData = Array.from(stores.technologies).map(t => ({ Technology: t }));
  addSheetWithOptions(wb, techData, "Technologies");

  // Findings sheet (flatten map)
  const findingsRows = [];
  for (const [src, items] of stores.findings.entries()) {
    for (const it of items) {
      findingsRows.push({
        Source: src,
        Type: it.type,
        Severity: it.severity,
        Snippet: it.snippet
      });
    }
  }
  addSheetWithOptions(wb, findingsRows, "Findings");

  // Identified Keys sheet (include confidence scores)
  const keysRows = (stores.keys || []).map(k => ({
    Source: k.source,
    Type: k.type,
    Severity: k.severity,
    Confidence: k.confidence ? `${(k.confidence * 100).toFixed(1)}%` : "N/A",
    Key: k.key,
    Snippet: k.snippet
  }));
  addSheetWithOptions(wb, keysRows, "Identified Keys");

  // Summary sheet
  const summaryData = [
    { Metric: "Endpoints", Count: stores.endpoints.size },
    { Metric: "Parameters", Count: stores.parameters.size },
    { Metric: "Risky Parameters", Count: stores.riskyParameters.size },
    { Metric: "JS Files", Count: stores.jsFiles.size },
    { Metric: "Technologies", Count: stores.technologies.size },
    { Metric: "Findings", Count: findingsRows.length },
    { Metric: "Identified Keys", Count: (stores.keys || []).length },
    { Metric: "Discovered Requests", Count: (stores.requests || []).length }
  ];
  addSheetWithOptions(wb, summaryData, "Summary");

  XLSX.writeFile(wb, outputFile);
  console.log(chalk.green(`Results exported to ${outputFile} (XLSX with filters & frozen headers)`));
}

// Process content to extract endpoints, parameters, tech hints
function processContent(content, source, stores) {
  if (!content) return;

  for (const match of content.matchAll(endpointRegex)) {
    const endpoint = match[0];
    stores.endpoints.add(endpoint);

    // categorize endpoint
    const cats = endpointCategories.filter(c => c.test(endpoint)).map(c => c.label);
    if (cats.length) stores.endpointTags.set(endpoint, cats);

    // parameters
    const query = endpoint.split("?")[1];
    if (query) {
      query.split("&").forEach(param => {
        const [key] = param.split("=");
        if (key) {
          if (!stores.parameters.has(key)) stores.parameters.set(key, []);
          stores.parameters.get(key).push(source);
          // risky param heuristic
          if (riskyParams.some(rx => rx.test(key))) stores.riskyParameters.add(key);
        }
      });
    }
  }

  for (const match of content.matchAll(jsFileRegex)) {
    stores.jsFiles.add(match[0]);
  }
}

// =====================
// Advanced Security Patterns
// =====================
const securityPatterns = {
  // Critical / high severity patterns
  domXss: { re: /(innerHTML|outerHTML|document\.write|insertAdjacentHTML|insertBefore|replaceChild)\s*\(/g, severity: "critical", desc: "DOM sink (innerHTML, document.write, etc.)" },
  dynamicEval: { re: /(eval|new Function|Function\()/g, severity: "critical", desc: "Dynamic code evaluation (eval / Function)" },
  execDanger: { re: /(execScript|document\.write\(|setTimeout\(\s*['"`])/g, severity: "critical", desc: "Exec-like functions / string timeouts" },
  hardcodedSecrets: { re: /(api[_-]?key|secret|token|auth|bearer)[^"'`]{0,60}['"`][A-Za-z0-9_\-]{6,}/gi, severity: "critical", desc: "Hardcoded API keys / secrets" },
  // Provider-specific / high-confidence API key patterns
  googleApiKey: { re: /AIza[0-9A-Za-z\-_]{35}/g, severity: "critical", desc: "Google / Firebase API key (starts with AIza)" },
  awsAccessKeyId: { re: /(?:AKIA|ASIA|AROA)[A-Z0-9]{16}/g, severity: "critical", desc: "AWS Access Key ID (AKIA/ASIA/AROA prefix)" },
  awsSecretAccessKey: { re: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|awsSecretAccessKey)[\s'"=:]{0,20}([A-Za-z0-9/+=]{40})/gi, severity: "critical", desc: "AWS Secret Access Key (40 base64-like chars)" },
  stripeKey: { re: /sk_(live|test)_[0-9a-zA-Z]{24,}/g, severity: "critical", desc: "Stripe secret key (sk_live_ or sk_test_)" },
  sendgridKey: { re: /SG\.[A-Za-z0-9_-]{20,}/g, severity: "critical", desc: "SendGrid API key (SG.)" },
  slackToken: { re: /xox[baprs]-[0-9A-Za-z-]+/g, severity: "critical", desc: "Slack token (xoxb/xoxp/xoxa etc.)" },
  githubToken: { re: /gh[pousr]_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9_]{36,}/g, severity: "critical", desc: "GitHub tokens (ghp_, gho_, ghs_, ghp_, etc.)" },
  twilioKey: { re: /(?:AC|SK)[0-9a-fA-F]{32}/g, severity: "high", desc: "Twilio Account/Key SID (AC..., SK...)" },
  pemPrivateKey: { re: /-----BEGIN (?:RSA |)PRIVATE KEY-----[\s\S]{20,}-----END (?:RSA |)PRIVATE KEY-----/g, severity: "critical", desc: "PEM private key block detected" },
  // Generic admin/internal key heuristics: look for param/var names containing admin/internal or x-api-key followed by a high-entropy value
  adminInternalKey: { re: /(?:x-?api-?key|api[_-]?key|admin[_-]?key|internal[_-]?key|service[_-]?token)[\s"'`:=]{0,30}[A-Za-z0-9\-_.]{16,}/gi, severity: "critical", desc: "Admin/Internal/API key parameter detected" },
  jwtLiteral: { re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+/g, severity: "high", desc: "JWT-like literal" },
  openRedirect: { re: /(location\.href|window\.location|document\.location)\s*=\s*[A-Za-z0-9_'"`$.(){}\s-]*[+?&]?[A-Za-z0-9_'"`$.(){}\s-]*/g, severity: "high", desc: "Assignment to location from possibly untrusted input" },
  weakCrypto: { re: /(MD5|md5|SHA1|sha1|crypto\.createHash\(\s*['"`](?:md5|sha1)['"`]\s*\))/gi, severity: "high", desc: "Weak cryptographic hash usage" },
  protoPollution: { re: /(__proto__|constructor\.prototype|Object\.prototype\[\s*'__proto__'\s*\])/g, severity: "high", desc: "Prototype pollution indicators" },

  // Medium severity patterns
  websocket: { re: /(wss?:\/\/[a-zA-Z0-9_.\-:\/]+)/g, severity: "medium", desc: "WebSocket endpoints" },
  urlParsing: { re: /(new URL\(|URLSearchParams|location\.search|location\.hash)/g, severity: "medium", desc: "URL parsing / query handling" },
  corsHints: { re: /(Access-Control-Allow-Origin|mode:\s*['"`]no-cors['"`]|allow-origin:\s*\*|cors)/gi, severity: "high", desc: "CORS misconfiguration hints" },
  fileUpload: { re: /(input\[type=['"`]file['"`]\]|FormData|file\.name|file\.size|accept=.*file)/gi, severity: "medium", desc: "File upload handling" },
  postMessage: { re: /postMessage\(/g, severity: "medium", desc: "postMessage usage (check origin validation)" },
  cryptoSubtle: { re: /crypto\.subtle\./g, severity: "medium", desc: "WebCrypto API usage (check correct usage)" },
  base64Use: { re: /(atob|btoa)\(/g, severity: "medium", desc: "Base64 operations (possible hidden payloads)" },

  // Low severity / informational
  debugLogs: { re: /console\.(log|error|warn|debug)\(/g, severity: "low", desc: "Console debug output" },
  todoFixme: { re: /(TODO|FIXME)/g, severity: "low", desc: "TODO / FIXME comments" },
  deprecated: { re: /(escape\(|unescape\()/g, severity: "low", desc: "Deprecated functions (escape/unescape)" },
  weakRandom: { re: /Math\.random\(/g, severity: "low", desc: "Weak randomness (Math.random)" },
  obfuscationPatterns: { re: /(eval\(function\(p,a,c,k,e,d\)|\\x[0-9A-Fa-f]{2,}|\\u[0-9A-Fa-f]{4,})/g, severity: "high", desc: "Obfuscated/packed code indicators" },
  antiDebug: { re: /(debugger;|toString\(\)\s*===\s*function\(\)|detectDevTools|devtools)/gi, severity: "medium", desc: "Anti-debug or devtools detection" },
  dynamicURLFetch: { re: /(fetch|axios|XMLHttpRequest)\s*\(\s*[^'"]*\+/g, severity: "medium", desc: "Dynamic URL construction in fetch/axios/XHR" },
};

// =====================
// AST-based Request Extraction
// =====================
function extractRequestsFromAST(content, source, stores, baseUrl) {
  try {
    // Try to parse with acorn; skip if parse fails (bad/minified code)
    const ast = acorn.parse(content, { ecmaVersion: 2020, sourceType: "module" });
    
    // Helper to extract string literals
    const extractString = (node) => {
      if (node.type === "Literal" && typeof node.value === "string") return node.value;
      if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
        // simple template with no interpolations
        return node.quasis[0]?.value?.raw || null;
      }
      return null;
    };

    // Helper to evaluate simple string concatenations (BinaryExpression with +)
    const evaluateStringConcat = (node, depth = 0) => {
      if (depth > 5) return null; // limit recursion
      if (node.type === "Literal" && typeof node.value === "string") return node.value;
      if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
        return node.quasis[0]?.value?.raw || null;
      }
      if (node.type === "BinaryExpression" && node.operator === "+") {
        const left = evaluateStringConcat(node.left, depth + 1);
        const right = evaluateStringConcat(node.right, depth + 1);
        if (typeof left === "string" && typeof right === "string") {
          return left + right;
        }
      }
      return null;
    };

    // Helper to extract object properties (simple literals only)
    const extractObjectProps = (node) => {
      const props = {};
      if (node.type === "ObjectExpression") {
        for (const prop of (node.properties || [])) {
          const key = prop.key?.name || extractString(prop.key);
          if (key && prop.value) {
            const val = extractString(prop.value);
            if (val) props[key] = val;
          }
        }
      }
      return props;
    };

    // Walk the AST and look for call expressions
    const walk = (node) => {
      if (!node || typeof node !== "object") return;

      // fetch("url", { method: "POST", body: ... })
      if (node.type === "CallExpression") {
        const callee = node.callee;
        const args = node.arguments || [];

        // fetch(...)
        if (callee.type === "Identifier" && callee.name === "fetch" && args[0]) {
          // Try direct string first, then concatenated strings
          let url = extractString(args[0]);
          if (!url) url = evaluateStringConcat(args[0]);
          const opts = extractObjectProps(args[1]);
          if (url) {
            const method = opts.method || "GET";
            const bodyStr = opts.body || "";
            const params = parseParamsFromBody(bodyStr);
            const fullUrl = resolveUrl(url, baseUrl || source) || url;
            const snippet = safeSnippet(content, node.start || 0, 160);
            addRequest(stores, source, method, fullUrl, params, snippet);
          }
        }

        // axios.post(...) or axios.get(...) etc
        if (
          callee.type === "MemberExpression" &&
          callee.object?.name === "axios" &&
          (callee.property?.name === "post" || callee.property?.name === "get" || callee.property?.name === "put" || callee.property?.name === "delete")
        ) {
          const method = callee.property.name.toUpperCase();
          let url = extractString(args[0]);
          if (!url) url = evaluateStringConcat(args[0]);
          const bodyStr = args[1] ? extractString(args[1]) : "";
          if (url) {
            const params = parseParamsFromBody(bodyStr || "");
            const fullUrl = resolveUrl(url, baseUrl || source) || url;
            const snippet = safeSnippet(content, node.start || 0, 160);
            addRequest(stores, source, method, fullUrl, params, snippet);
          }
        }

        // $.post(...) or $.get(...)
        if (
          callee.type === "MemberExpression" &&
          callee.object?.name === "$" &&
          (callee.property?.name === "post" || callee.property?.name === "get")
        ) {
          const method = callee.property.name.toUpperCase();
          let url = extractString(args[0]);
          if (!url) url = evaluateStringConcat(args[0]);
          const bodyStr = args[1] ? extractString(args[1]) : "";
          if (url) {
            const params = parseParamsFromBody(bodyStr || "");
            const fullUrl = resolveUrl(url, baseUrl || source) || url;
            const snippet = safeSnippet(content, node.start || 0, 160);
            addRequest(stores, source, method, fullUrl, params, snippet);
          }
        }

        // XMLHttpRequest.open(method, url)
        if (
          callee.type === "MemberExpression" &&
          (callee.object?.name === "xhr" || callee.object?.type === "NewExpression") &&
          callee.property?.name === "open" &&
          args[0] && args[1]
        ) {
          const method = extractString(args[0]) || "GET";
          let url = extractString(args[1]);
          if (!url) url = evaluateStringConcat(args[1]);
          if (url) {
            const fullUrl = resolveUrl(url, baseUrl || source) || url;
            const snippet = safeSnippet(content, node.start || 0, 160);
            addRequest(stores, source, method, fullUrl, [], snippet);
          }
        }
      }

      // Recurse into child nodes
      for (const key in node) {
        if (key !== "start" && key !== "end" && key !== "loc") {
          const child = node[key];
          if (Array.isArray(child)) {
            child.forEach(walk);
          } else if (child && typeof child === "object") {
            walk(child);
          }
        }
      }
    };

    walk(ast);
  } catch (e) {
    // Parse error (likely minified/bad code); fall back to regex-based extraction
    // The regex-based request detection in analyzeJSContent will still run
  }
}

// Helper to parse parameters from a body string (reused by both regex and AST methods)
function parseParamsFromBody(bodyStr) {
  if (!bodyStr) return [];
  bodyStr = String(bodyStr).trim();
  // try JSON object
  if ((bodyStr.startsWith("{") && bodyStr.endsWith("}")) || (bodyStr.startsWith("[") && bodyStr.endsWith("]"))) {
    try {
      const obj = JSON.parse(bodyStr);
      if (obj && typeof obj === 'object') return Object.keys(obj);
    } catch (e) {
      // fallthrough to regex-based extraction
    }
  }
  // URLSearchParams or querystring
  const urlParamsMatch = bodyStr.match(/[?&]?([A-Za-z0-9_\-\.]+)=/g);
  if (urlParamsMatch) return Array.from(new Set(urlParamsMatch.map(s => s.replace(/[?&]=?$/, '').replace(/=$/, '').replace(/=.*$/, ''))));
  // simple key: value pairs in object literal
  const keys = [];
  const keyRe = /["'`]?([A-Za-z0-9_\$\-]+)["'`]?\s*:\s*/g;
  let m;
  while ((m = keyRe.exec(bodyStr)) !== null) {
    keys.push(m[1]);
  }
  return Array.from(new Set(keys));
}

// Analyze JS content for security patterns
function analyzeJSContent(content, source, stores, baseUrl) {
  if (!content) return;
  // Basic content processing (endpoints + jsFiles)
  processContent(content, source, stores);

  // Try AST-based request extraction first (more accurate for static calls)
  extractRequestsFromAST(content, source, stores, baseUrl);
  
  // Also use regex-based detection as fallback for dynamic URLs and other patterns
  detectRequestsViaRegex(content, source, stores, baseUrl);

  for (const [label, { re, severity, desc }] of Object.entries(securityPatterns)) {
    // Ensure global regex
    const flags = re.flags && re.flags.includes("g") ? re.flags : (re.flags || "") + "g";
    const gRe = new RegExp(re.source, flags);
    let match;
    while ((match = gRe.exec(content)) !== null) {
      const index = match.index || 0;
      const snippet = safeSnippet(content, index, 200);
      addFinding(stores, source, label, snippet, severity);
      // If this label corresponds to a sensitive key pattern, capture the matched token
      try {
  const keyLabels = new Set(["googleApiKey", "awsAccessKeyId", "awsSecretAccessKey", "stripeKey", "sendgridKey", "slackToken", "githubToken", "twilioKey", "adminInternalKey", "pemPrivateKey", "hardcodedSecrets", "jwtLiteral"]);
        if (keyLabels.has(label)) {
          // prefer first capturing group if present
          const matchedKey = match[1] || match[0];
          addKey(stores, source, label, matchedKey, snippet, severity);
        }
      } catch {
        // ignore key capture errors
      }
      // avoid infinite loop on zero-length match
      if (gRe.lastIndex === match.index) gRe.lastIndex++;
    }
  }

  // --- Deprecated: Regex-based request detection now replaced by AST-based extraction ---
  // For HTML forms, still use regex to extract form method and action
  try {
    const formRe = /<form[^>]*method=["'`]?\s*(post|get)\s*["'`]?[^>]*action=["'`]([^"'`]+)["'`][^>]*>/gi;
    let m;
    while ((m = formRe.exec(content)) !== null) {
      const method = (m[1] || 'POST').toUpperCase();
      const action = m[2];
      const fullUrl = resolveUrl(action, baseUrl || source) || action;
      // attempt to extract input names inside the form tag (lookahead from current index)
      const formSnippet = content.slice(m.index, Math.min(content.length, m.index + 1000));
      const inputRe = /<input[^>]*name=["'`]([^"'`]+)["'`]/gi;
      const params = [];
      let im;
      while ((im = inputRe.exec(formSnippet)) !== null) params.push(im[1]);
      addRequest(stores, source, method, fullUrl, params, safeSnippet(formSnippet, 0, 200));
      if (formRe.lastIndex === m.index) formRe.lastIndex++;
    }
  } catch (e) {
    // ignore form detection errors
  }
}

// --- Request discovery via regex patterns (fallback for dynamically constructed URLs) ---
function detectRequestsViaRegex(content, source, stores, baseUrl) {
  try {
    // helper to extract param names from JS object or querystring-like bodies
    const parseParamsFromBody = (bodyStr) => {
      if (!bodyStr) return [];
      bodyStr = String(bodyStr).trim();
      // try JSON object
      if ((bodyStr.startsWith("{") && bodyStr.endsWith("}")) || (bodyStr.startsWith("[") && bodyStr.endsWith("]"))) {
        try {
          const obj = JSON.parse(bodyStr);
          if (obj && typeof obj === 'object') return Object.keys(obj);
        } catch (e) {
          // fallthrough to regex-based extraction
        }
      }
      // URLSearchParams or querystring
      const urlParamsMatch = bodyStr.match(/[?&]?([A-Za-z0-9_\-\.]+)=/g);
      if (urlParamsMatch) return Array.from(new Set(urlParamsMatch.map(s => s.replace(/[?&]=?$/, '').replace(/=$/, '').replace(/=.*$/, ''))));
      // simple key: value pairs in object literal
      const keys = [];
      const keyRe = /["'`]?([A-Za-z0-9_\$\-]+)["'`]?\s*:\s*/g;
      let m;
      while ((m = keyRe.exec(bodyStr)) !== null) {
        keys.push(m[1]);
      }
      return Array.from(new Set(keys));
    };

    // Detect static fetch() calls: fetch("url", {...})
    const staticFetchRe = /fetch\s*\(\s*["'`]([^"'`]{2,})["'`]\s*(?:,\s*({[^}]*}))?/g;
    let m;
    while ((m = staticFetchRe.exec(content)) !== null) {
      const url = m[1];
      const opts = m[2] || "{}";
      try {
        const optsObj = JSON.parse(opts);
        const method = optsObj.method || "GET";
        const params = parseParamsFromBody(optsObj.body || "");
        const fullUrl = resolveUrl(url, baseUrl || source) || url;
        const snippet = safeSnippet(content, m.index, 160);
        addRequest(stores, source, method, fullUrl, params, snippet);
      } catch (e) {
        // fallback to basic parsing
        const fullUrl = resolveUrl(url, baseUrl || source) || url;
        const snippet = safeSnippet(content, m.index, 160);
        addRequest(stores, source, "GET", fullUrl, [], snippet);
      }
    }

    // Detect axios calls: axios.post("url", data) or axios.get("url")
    const axiosRe = /axios\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]{2,})["'`]\s*(?:,\s*(.+?))?\s*\)/g;
    while ((m = axiosRe.exec(content)) !== null) {
      const method = m[1].toUpperCase();
      const url = m[2];
      const bodyStr = m[3] || "";
      const params = parseParamsFromBody(bodyStr);
      const fullUrl = resolveUrl(url, baseUrl || source) || url;
      const snippet = safeSnippet(content, m.index, 160);
      addRequest(stores, source, method, fullUrl, params, snippet);
    }

    // Detect jQuery AJAX: $.post("url", data) or $.get("url")
    const jqueryRe = /\$\.(post|get|ajax)\s*\(\s*["'`]([^"'`]{2,})["'`]\s*(?:,\s*(.+?))?\s*\)/g;
    while ((m = jqueryRe.exec(content)) !== null) {
      const method = m[1].toUpperCase() === "AJAX" ? "POST" : m[1].toUpperCase();
      const url = m[2];
      const bodyStr = m[3] || "";
      const params = parseParamsFromBody(bodyStr);
      const fullUrl = resolveUrl(url, baseUrl || source) || url;
      const snippet = safeSnippet(content, m.index, 160);
      addRequest(stores, source, method, fullUrl, params, snippet);
    }

    // Detect XMLHttpRequest: xhr.open("GET", "url")
    const xhrRe = /xhr\.open\s*\(\s*["'`](\w+)["'`]\s*,\s*["'`]([^"'`]{2,})["'`]/g;
    while ((m = xhrRe.exec(content)) !== null) {
      const method = m[1].toUpperCase();
      const url = m[2];
      const fullUrl = resolveUrl(url, baseUrl || source) || url;
      const snippet = safeSnippet(content, m.index, 160);
      addRequest(stores, source, method, fullUrl, [], snippet);
    }

    // For best-effort detection of dynamically constructed URLs, use regex as fallback
    const dynamicFetchRe = /(fetch|axios\.post|axios\.get|\$\.post|\$\.get)\s*\(\s*[^)]*\+[^)]*\)/g;
    while ((m = dynamicFetchRe.exec(content)) !== null) {
      // Extract rough endpoint from context
      const context = content.slice(Math.max(0, m.index - 50), Math.min(content.length, m.index + 100));
      const urlMatch = context.match(/["'`]([^"'`]{3,})["'`]/);
      if (urlMatch) {
        addRequest(stores, source, "GET", urlMatch[1], [], safeSnippet(content, m.index, 160));
      }
      if (dynamicFetchRe.lastIndex === m.index) dynamicFetchRe.lastIndex++;
    }
  } catch (e) {
    // ignore regex detection errors
  }
}

// Technology detection from headers, html, assets
function detectTechnologies({ headers, html, assets }, stores) {
  for (const sig of techSignatures) {
    try {
      if (sig.detector({ headers, html, assets })) {
        stores.technologies.add(sig.name);
      }
    } catch {
      // ignore detector errors
    }
  }
  if (headers) {
    const powered = headers.get("x-powered-by");
    const server = headers.get("server");
    if (powered) stores.technologies.add(`x-powered-by: ${powered}`);
    if (server) stores.technologies.add(`server: ${server}`);
  }
}

// =====================
// Deduplication Functions
// =====================

/**
 * Deduplicate requests by method + URL combination
 * Returns new array with only unique requests (keeps first occurrence)
 */
function deduplicateRequests(requests) {
  if (!requests || requests.length === 0) return [];
  
  const seen = new Map(); // Key: "METHOD:URL"
  const dedupedRequests = [];
  
  for (const req of requests) {
    const key = `${(req.method || 'GET').toUpperCase()}:${req.url}`;
    
    if (!seen.has(key)) {
      seen.set(key, true);
      dedupedRequests.push(req);
    }
  }
  
  return dedupedRequests;
}

/**
 * Apply deduplication to all stores before export
 * - Deduplicate requests by method + URL
 * - Keep endpoints as Set (automatically deduplicated)
 * - Keep parameters as Map (automatically deduplicated)
 */
function deduplicateStores(stores) {
  const dedup = {
    ...stores,
    requests: deduplicateRequests(stores.requests || [])
  };
  return dedup;
}

// Export results (JSON + XLSX only)
function exportResults(format, outputFile, stores) {
  // Apply deduplication before export
  const dedupStores = deduplicateStores(stores);

  if (format === "json") {
    const data = {
      endpoints: Array.from(dedupStores.endpoints),
      endpointTags: Object.fromEntries(dedupStores.endpointTags),
      parameters: Object.fromEntries(dedupStores.parameters),
      riskyParameters: Array.from(dedupStores.riskyParameters),
      keys: dedupStores.keys || [],
      jsFiles: Array.from(dedupStores.jsFiles),
      technologies: Array.from(dedupStores.technologies),
      findings: Object.fromEntries([...dedupStores.findings.entries()].map(([k, v]) => [k, v])),
      requests: dedupStores.requests || [],
      deduplicationStats: {
        requestsBeforeDedup: stores.requests ? stores.requests.length : 0,
        requestsAfterDedup: dedupStores.requests ? dedupStores.requests.length : 0
      }
    };

    fs.writeFileSync(outputFile, JSON.stringify(data, null, 2));
    console.log(chalk.green(`Results exported to ${outputFile} (JSON)`));
    return;
  }

  if (format === "xlsx") {
    exportResultsXLSX(outputFile, dedupStores);
    return;
  }

  console.error(chalk.red("❌ Unsupported format. Use: json or xlsx only."));
}

// Build HTTPS agent based on TLS options
function buildAgent({ insecure, caPath }) {
  if (insecure) {
    return new https.Agent({ rejectUnauthorized: false });
  }
  if (caPath) {
    const ca = fs.readFileSync(caPath);
    return new https.Agent({ ca });
  }
  return undefined;
}

// Analyze a single target
async function analyzeTarget(url, options) {
  const {
    silent, verbose, concurrency, format, output, insecure, ca,
  } = options;

  const stores = createStores();
  const agent = buildAgent({ insecure, caPath: ca });
  const fetchOpts = agent ? { agent } : {};

  try {
    const res = await fetchWithRetry(url, fetchOpts);
    const html = await res.text();
    const dom = new JSDOM(html);

    // Process page HTML first (endpoints, inline scripts)
    processContent(html, "Page content", stores);

  // Also run the JS/security pattern analyzer over the raw HTML so keys and secrets in
  // attributes or inline data are detected (e.g., Google API keys in meta/script tags).
  analyzeJSContent(html, "Page content (html)", stores, url);

    // Analyze inline scripts
    const inlineScripts = dom.window.document.querySelectorAll("script:not([src])");
    inlineScripts.forEach((s, idx) => {
      const srcLabel = `Inline script ${idx + 1} (page)`;
      const content = s.textContent || "";
      analyzeJSContent(content, srcLabel, stores, url);
    });

    // Technology detection
    const assetsFromHTML = Array.from(html.matchAll(jsFileRegex)).map(m => resolveUrl(m[0], url)).filter(Boolean);
    detectTechnologies({ headers: res.headers, html, assets: assetsFromHTML }, stores);

    // Collect script URLs (resolved) and filter to target origin only
    const scripts = dom.window.document.getElementsByTagName("script");
    const scriptUrls = [];
    const targetOrigin = new URL(url).origin;

    for (const script of scripts) {
      if (script.src) {
        const full = resolveUrl(script.src, url);
        if (full) {
          try {
            const u = new URL(full);
            if (u.origin === targetOrigin) {
              scriptUrls.push(full);
              stores.jsFiles.add(full);
            } else {
              if (verbose) console.log(chalk.gray(`Skipping third-party JS: ${full}`));
            }
          } catch {
            // ignore bad URL
          }
        }
      }
    }

    // Fetch scripts with concurrency and retry, then analyze content
    const tasks = scriptUrls.map(src => async () => {
      try {
        const jsRes = await fetchWithRetry(src, fetchOpts);
        const jsText = await jsRes.text();
  processContent(jsText, src, stores);       // generic extraction
  analyzeJSContent(jsText, src, stores, src);     // advanced detections (with base URL)
      } catch (err) {
        if (!silent) console.error(chalk.red(`Error fetching ${src}: ${err.message}`));
      }
    });

    if (verbose) console.log(chalk.gray(`Fetching ${scriptUrls.length} target JS assets with concurrency=${concurrency}...`));
    await runWithConcurrency(tasks, concurrency);

    // Output human-readable results
    if (!silent) {
      console.log(chalk.blue.bold(`\nEndpoints Found (${stores.endpoints.size}):`));
      stores.endpoints.forEach(e => {
        const tags = stores.endpointTags.get(e);
        const tagText = tags ? ` ${chalk.gray(`[${tags.join(", ")}]`)}` : "";
        console.log(`  ${e}${tagText}`);
      });

      console.log(chalk.green.bold(`\nParameters Found (${stores.parameters.size}):`));
      stores.parameters.forEach((sources, param) => {
        const counts = sources.reduce((acc, src) => {
          acc[src] = (acc[src] || 0) + 1;
          return acc;
        }, {});
        const summary = Object.entries(counts).map(([src, count]) => `${src} (${count})`).join(", ");
        const risk = stores.riskyParameters.has(param) ? chalk.red(" [risky]") : "";
        console.log(`  ${param}${risk} → ${summary}`);
      });

      console.log(chalk.yellow.bold(`\nJS Files (target origin) Found (${stores.jsFiles.size}):`));
      stores.jsFiles.forEach(f => console.log(`  ${f}`));

      console.log(chalk.magenta.bold(`\nTechnologies Detected (${stores.technologies.size}):`));
      stores.technologies.forEach(t => console.log(`  ${t}`));

      // Findings summary
      let totalFindings = 0;
      for (const items of stores.findings.values()) totalFindings += items.length;
      // Identified keys section (if any)
      if (stores.keys && stores.keys.length) {
        const mask = v => {
          try {
            v = String(v);
            if (v.length <= 12) return v;
            return `${v.slice(0,4)}...${v.slice(-4)}`;
          } catch {
            return "[unavailable]";
          }
        };

        // Filter keys by confidence unless --all-confidence flag is set
        const confidenceThreshold = 0.5;
        const keysToDisplay = options.allConfidence 
          ? stores.keys 
          : stores.keys.filter(k => (k.confidence || 0) >= confidenceThreshold);
        
        console.log(chalk.red.bold(`\nIdentified Keys (${keysToDisplay.length}/${stores.keys.length}):`));
        for (const k of keysToDisplay) {
          const sev = k.severity === "critical" ? chalk.bgRed.white(" CRITICAL ") : (k.severity === "high" ? chalk.red(" HIGH ") : chalk.yellow(" MED "));
          const conf = k.confidence ? ` [${(k.confidence * 100).toFixed(0)}%]` : "";
          console.log(`  ${sev} ${k.type}${conf} @ ${k.source} → ${mask(k.key)} \n    ${chalk.gray(k.snippet)}`);
        }
        
        // Note if there are low-confidence matches filtered out
        if (!options.allConfidence && keysToDisplay.length < stores.keys.length) {
          const lowConfCount = stores.keys.length - keysToDisplay.length;
          console.log(chalk.gray(`  (${lowConfCount} low-confidence matches filtered; use --all-confidence to show all)`));
        }
      }          console.log(chalk.red.bold(`\nSecurity Findings (${totalFindings}):`));
      for (const [src, items] of stores.findings.entries()) {
        console.log(chalk.gray(`\n  Source: ${src} (${items.length} findings)`));
        for (const it of items) {
          const sev = it.severity === "critical" ? chalk.bgRed.white(" CRITICAL ") :
                      it.severity === "high" ? chalk.red(" HIGH ") :
                      it.severity === "medium" ? chalk.yellow(" MED ") : chalk.blue(" LOW ");
          console.log(`    ${sev} ${it.type} → ${it.snippet}`);
        }
      }

      console.log(chalk.cyan.bold(`\nSummary:`));
      console.log(`  Endpoints: ${stores.endpoints.size}`);
      console.log(`  Parameters: ${stores.parameters.size} (risky: ${stores.riskyParameters.size})`);
      console.log(`  JS Files: ${stores.jsFiles.size}`);
      console.log(`  Technologies: ${stores.technologies.size}`);
      console.log(`  Findings: ${totalFindings}`);
      // Identified keys summary with confidence filtering
      const keysList = stores.keys || [];
      const confidenceThreshold = 0.5;
      const keysToSummarize = options.allConfidence 
        ? keysList 
        : keysList.filter(k => (k.confidence || 0) >= confidenceThreshold);
      const keysCount = keysToSummarize.length;
      const totalKeysCount = keysList.length;
      if (totalKeysCount > 0) {
        const typeCounts = keysToSummarize.reduce((acc, k) => {
          acc[k.type] = (acc[k.type] || 0) + 1;
          return acc;
        }, {});
        const typeSummary = Object.entries(typeCounts).map(([t, c]) => `${t} (${c})`).join(", ");
        const countDisplay = keysCount === totalKeysCount ? keysCount : `${keysCount}/${totalKeysCount}`;
        console.log(chalk.red.bold(`  Identified Keys: ${countDisplay} -> ${typeSummary}`));
      } else {
        console.log(chalk.red.bold(`  Identified Keys: 0`));
      }
    }

    // Export if requested
    if (output) {
      exportResults(format, output, stores);
    } else {
      // Auto-generate filename based on hostname
      const autoFilename = generateReportFilename(url, format);
      exportResults(format, autoFilename, stores);
    }

  } catch (err) {
    console.error(chalk.red(`Failed to fetch ${url}: ${err.message}`));
  }
}

// Analyze local JavaScript file or directory
async function analyzeLocalPath(filePath, options) {
  const { silent, format, output } = options;
  const stores = createStores();
  const stats = fs.statSync(filePath);

  if (stats.isFile() && filePath.endsWith('.js')) {
    // Single JavaScript file
    if (!silent) console.log(chalk.white.bold(`\n=== Analyzing: ${filePath} ===`));
    const content = fs.readFileSync(filePath, "utf-8");
    analyzeJSContent(content, filePath, stores, `file://${path.resolve(filePath)}`);
    processContent(content, filePath, stores);
    detectTechnologies({ html: content }, stores);
  } else if (stats.isDirectory()) {
    // Directory: recursively find .js files
    if (!silent) console.log(chalk.white.bold(`\n=== Analyzing directory: ${filePath} ===`));
    const jsFiles = [];
    const findJsFiles = (dir) => {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const itemStats = fs.statSync(fullPath);
        if (itemStats.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
          findJsFiles(fullPath);
        } else if (itemStats.isFile() && item.endsWith('.js')) {
          jsFiles.push(fullPath);
        }
      }
    };
    findJsFiles(filePath);

    if (jsFiles.length === 0) {
      console.warn(chalk.yellow(`⚠ No JavaScript files found in ${filePath}`));
      return;
    }

    if (!silent) console.log(chalk.gray(`Found ${jsFiles.length} JavaScript file(s)`));

    for (const jsFile of jsFiles) {
      const relPath = path.relative(process.cwd(), jsFile);
      if (!silent) console.log(chalk.gray(`  📄 ${relPath}`));
      const content = fs.readFileSync(jsFile, "utf-8");
      analyzeJSContent(content, jsFile, stores, `file://${path.resolve(jsFile)}`);
      processContent(content, jsFile, stores);
    }
    detectTechnologies({ html: "" }, stores);
  } else {
    console.error(chalk.red(`✗ Path is neither a .js file nor a directory: ${filePath}`));
    process.exit(1);
  }

  // Display results
  if (!silent) displayResults(stores, options);

  // Export if requested
  if (output) {
    exportResults(format, output, stores);
  } else {
    // Auto-generate filename based on local path
    const autoFilename = generateReportFilename(filePath, format);
    exportResults(format, autoFilename, stores);
  }
}

// Helper function to display results (extracted from analyzeTarget)
function displayResults(stores, options) {
  const totalFindings = Array.from(stores.findings.values()).reduce((sum, arr) => sum + arr.length, 0);

  if (stores.endpoints.size || stores.parameters.size || stores.keys.length || stores.findings.size || stores.requests.length) {
    console.log(chalk.blue.bold("\n📊 Summary:"));
    console.log(`  Endpoints: ${stores.endpoints.size}`);
    console.log(`  Parameters: ${stores.parameters.size}`);
    console.log(`  JS Files: ${stores.jsFiles.size}`);
    console.log(`  Technologies: ${stores.technologies.size}`);
    console.log(`  Findings: ${totalFindings}`);

    const keysList = stores.keys || [];
    const confidenceThreshold = 0.5;
    const keysToSummarize = options.allConfidence 
      ? keysList 
      : keysList.filter(k => (k.confidence || 0) >= confidenceThreshold);
    const keysCount = keysToSummarize.length;
    const totalKeysCount = keysList.length;
    if (totalKeysCount > 0) {
      const typeCounts = keysToSummarize.reduce((acc, k) => {
        acc[k.type] = (acc[k.type] || 0) + 1;
        return acc;
      }, {});
      const typeSummary = Object.entries(typeCounts).map(([t, c]) => `${t} (${c})`).join(", ");
      const countDisplay = keysCount === totalKeysCount ? keysCount : `${keysCount}/${totalKeysCount}`;
      console.log(chalk.red.bold(`  Identified Keys: ${countDisplay} -> ${typeSummary}`));
    } else {
      console.log(chalk.red.bold(`  Identified Keys: 0`));
    }
  }
}

// Read targets: single URL, file list, stdin, or local file/directory
async function loadTargets({ urlArg, listFile, stdin }) {
  const targets = [];
  if (urlArg) targets.push(urlArg);
  if (listFile) {
    const lines = fs.readFileSync(listFile, "utf-8").split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    targets.push(...lines);
  }
  if (stdin) {
    const input = await new Promise(resolve => {
      let data = "";
      process.stdin.setEncoding("utf-8");
      process.stdin.on("data", chunk => (data += chunk));
      process.stdin.on("end", () => resolve(data));
    });
    const lines = input.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    targets.push(...lines);
  }
  return Array.from(new Set(targets));
}

// =================
// CLI Definition
// =================
program
  .name("web-recon")
  .description("Extract endpoints, parameters, keys, technologies and perform advanced security analysis from URLs or local JavaScript files/directories")
  .argument("[target]", "Target URL, .js file, or directory to analyze (optional if using -l or --stdin)")
  .option("-l, --list <file>", "File containing list of URLs or local paths")
  .option("--stdin", "Read URLs/paths from stdin (one per line)")
  .option("-o, --output <file>", "Export results to file")
  .option("-f, --format <type>", "Export format: json or xlsx", (value) => {
    value = value.toLowerCase();
    if (!["json", "xlsx"].includes(value)) {
      console.error(chalk.red("Invalid format. Use: json or xlsx"));
      process.exit(1);
    }
    return value;
  }, "json")
  .option("-c, --concurrency <n>", "Concurrent JS fetches per target", v => parseInt(v, 10), 8)
  .option("--insecure", "Disable TLS verification (rejectUnauthorized=false)")
  .option("--ca <file>", "Custom Root CA bundle file (PEM)")
  .option("--all-confidence", "Display all detected keys regardless of confidence score")
  .option("--silent", "Suppress console output (export only)")
  .option("--verbose", "Verbose logging")
  .action(async (urlArg, options) => {
    const targets = await loadTargets({ urlArg, listFile: options.list, stdin: options.stdin });
    if (!targets.length) {
      console.error(chalk.red("No targets provided. Use a URL, file path, directory path, -l <file>, or --stdin."));
      process.exit(1);
    }

    for (const target of targets) {
      // Detect if target is a URL or local path
      const isUrl = target.startsWith('http://') || target.startsWith('https://');
      const isLocalPath = !isUrl && fs.existsSync(target);

      if (!options.silent) {
        if (isUrl) {
          console.log(chalk.white.bold(`\n=== Scanning: ${target} ===`));
        } else if (isLocalPath) {
          console.log(chalk.white.bold(`\n=== Analyzing: ${target} ===`));
        } else {
          console.error(chalk.red(`✗ Target not found (not a URL or local path): ${target}`));
          continue;
        }
      }

      if (isUrl) {
        // Analyze web URL
        await analyzeTarget(target, options);
      } else if (isLocalPath) {
        // Analyze local file or directory
        await analyzeLocalPath(target, options);
      }
    }
  });

program.parse(process.argv);

// =====================
// Exports for Testing
// =====================
export {
  createStores,
  addKey,
  addFinding,
  addRequest,
  calculateEntropy,
  computeKeyConfidence,
  safeSnippet,
  resolveUrl,
  processContent,
  analyzeJSContent,
  extractRequestsFromAST,
  detectTechnologies,
  generateReportFilename,
  analyzeTarget,
  analyzeLocalPath,
  displayResults,
  exportResults,
  exportResultsXLSX
};

