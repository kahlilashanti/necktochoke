/**
 * Netlify Function - Security Scanner
 *
 * Serverless function that performs security scans on URLs
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const dns = require('dns').promises;

// Security headers for all responses
const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

// Rate limiting configuration
const RATE_LIMIT = {
  maxRequests: 5,           // Maximum scans per window
  windowMs: 60 * 60 * 1000  // 1 hour in milliseconds
};

// In-memory store for rate limiting (resets on cold starts)
const rateLimitStore = new Map();

/**
 * Clean up old rate limit entries to prevent memory leaks
 */
function cleanupRateLimitStore() {
  const now = Date.now();
  for (const [ip, data] of rateLimitStore.entries()) {
    // Remove entries older than the rate limit window
    if (now - data.firstRequestTime > RATE_LIMIT.windowMs) {
      rateLimitStore.delete(ip);
    }
  }
}

/**
 * Check if IP is rate limited
 * Returns { limited: boolean, retryAfter: number }
 */
function checkRateLimit(ip) {
  // Clean up old entries periodically (every 100 requests)
  if (Math.random() < 0.01) {
    cleanupRateLimitStore();
  }

  const now = Date.now();
  const clientData = rateLimitStore.get(ip);

  if (!clientData) {
    // First request from this IP
    rateLimitStore.set(ip, {
      count: 1,
      firstRequestTime: now
    });
    return { limited: false, retryAfter: 0 };
  }

  // Check if we're still in the rate limit window
  const timeSinceFirst = now - clientData.firstRequestTime;

  if (timeSinceFirst > RATE_LIMIT.windowMs) {
    // Window expired, reset counter
    rateLimitStore.set(ip, {
      count: 1,
      firstRequestTime: now
    });
    return { limited: false, retryAfter: 0 };
  }

  // Still in window, check count
  if (clientData.count >= RATE_LIMIT.maxRequests) {
    // Rate limited
    const retryAfter = Math.ceil((RATE_LIMIT.windowMs - timeSinceFirst) / 1000); // seconds
    return { limited: true, retryAfter };
  }

  // Increment count
  clientData.count++;
  return { limited: false, retryAfter: 0 };
}

/**
 * SSRF Protection - Block requests to internal/private IP ranges
 */
function isPrivateIP(ip) {
  // IPv4 private ranges
  const ipv4Parts = ip.split('.').map(Number);

  if (ipv4Parts.length === 4 && ipv4Parts.every(n => n >= 0 && n <= 255)) {
    // 127.0.0.0/8 - Loopback
    if (ipv4Parts[0] === 127) return true;

    // 10.0.0.0/8 - Private
    if (ipv4Parts[0] === 10) return true;

    // 172.16.0.0/12 - Private
    if (ipv4Parts[0] === 172 && ipv4Parts[1] >= 16 && ipv4Parts[1] <= 31) return true;

    // 192.168.0.0/16 - Private
    if (ipv4Parts[0] === 192 && ipv4Parts[1] === 168) return true;

    // 169.254.0.0/16 - Link-local
    if (ipv4Parts[0] === 169 && ipv4Parts[1] === 254) return true;

    // 0.0.0.0/8 - Current network
    if (ipv4Parts[0] === 0) return true;
  }

  // IPv6 loopback and private
  if (ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) {
    return true;
  }

  return false;
}

async function validateUrl(urlString) {
  let parsedUrl;

  try {
    parsedUrl = new URL(urlString);
  } catch (error) {
    throw new Error('Invalid URL format');
  }

  // Only allow https
  if (parsedUrl.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed');
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // Block localhost variations
  if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname.endsWith('.local')) {
    throw new Error('Cannot scan localhost or internal hostnames');
  }

  // If it's an IP address, check if it's private
  if (isPrivateIP(hostname)) {
    throw new Error('Cannot scan private IP addresses');
  }

  // Resolve hostname to IP and check if it resolves to private IP
  try {
    const addresses = await dns.resolve4(hostname).catch(() => []);
    const addresses6 = await dns.resolve6(hostname).catch(() => []);

    for (const ip of [...addresses, ...addresses6]) {
      if (isPrivateIP(ip)) {
        throw new Error('Cannot scan domains that resolve to private IP addresses');
      }
    }
  } catch (error) {
    // If DNS resolution fails, let the scan attempt continue
    // (it will fail naturally when trying to connect)
  }

  return parsedUrl.toString();
}

// Common exposed files that should never be publicly accessible
const EXPOSED_FILES = [
  '/.env',
  '/.git/config',
  '/.aws/credentials',
  '/config.json',
  '/config.yml',
  '/config.yaml',
  '/.npmrc',
  '/credentials.json',
  '/secrets.json',
  '/database.yml',
  '/.htpasswd',
  '/web.config',
  '/phpinfo.php',
  '/.ssh/id_rsa',
  '/backup.sql',
  '/dump.sql'
];

/**
 * Make HTTP/HTTPS request and return response details
 */
function makeRequest(url, path = '/') {
  return new Promise((resolve, reject) => {
    const targetUrl = new URL(path, url);
    const protocol = targetUrl.protocol === 'https:' ? https : http;

    const options = {
      method: 'GET',
      timeout: 5000,
      headers: {
        'User-Agent': 'NeckToChoke-Scanner/1.0'
      }
    };

    const req = protocol.get(targetUrl.toString(), options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
        // Prevent massive responses
        if (data.length > 100000) {
          req.destroy();
        }
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

/**
 * Check security headers
 */
async function checkSecurityHeaders(url) {
  const vulnerabilities = [];

  try {
    const response = await makeRequest(url);
    const headers = response.headers;

    // Check for HTTPS
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'https:') {
      vulnerabilities.push({
        severity: 'high',
        title: 'No HTTPS',
        description: 'Your site is not using HTTPS. All traffic is sent in plain text, including passwords and sensitive data.',
        recommendation: 'Enable HTTPS with a free SSL certificate from Let\'s Encrypt.'
      });
    }

    // Check for Strict-Transport-Security (HSTS)
    if (!headers['strict-transport-security']) {
      vulnerabilities.push({
        severity: 'medium',
        title: 'Missing HSTS Header',
        description: 'The Strict-Transport-Security header is missing. This means browsers won\'t be forced to use HTTPS.',
        recommendation: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
      });
    }

    // Check for X-Frame-Options
    if (!headers['x-frame-options']) {
      vulnerabilities.push({
        severity: 'medium',
        title: 'Missing X-Frame-Options',
        description: 'Your site can be embedded in iframes, making it vulnerable to clickjacking attacks.',
        recommendation: 'Add the header: X-Frame-Options: DENY or SAMEORIGIN'
      });
    }

    // Check for X-Content-Type-Options
    if (!headers['x-content-type-options']) {
      vulnerabilities.push({
        severity: 'low',
        title: 'Missing X-Content-Type-Options',
        description: 'Browsers might incorrectly guess file types, potentially leading to XSS attacks.',
        recommendation: 'Add the header: X-Content-Type-Options: nosniff'
      });
    }

    // Check for Content-Security-Policy
    if (!headers['content-security-policy']) {
      vulnerabilities.push({
        severity: 'medium',
        title: 'Missing Content Security Policy',
        description: 'No CSP header found. This makes your site more vulnerable to XSS attacks.',
        recommendation: 'Add a Content-Security-Policy header to control what resources can load.'
      });
    }

    // Check for X-XSS-Protection
    if (!headers['x-xss-protection']) {
      vulnerabilities.push({
        severity: 'low',
        title: 'Missing X-XSS-Protection',
        description: 'The X-XSS-Protection header is missing, though it\'s mostly deprecated in favor of CSP.',
        recommendation: 'Add the header: X-XSS-Protection: 1; mode=block (or rely on CSP)'
      });
    }

    // Check for Server header exposure
    if (headers['server']) {
      vulnerabilities.push({
        severity: 'low',
        title: 'Server Information Exposure',
        description: `Your server is advertising itself as: ${headers['server']}. This gives attackers information about your stack.`,
        recommendation: 'Remove or obscure the Server header to avoid revealing your technology stack.'
      });
    }

  } catch (error) {
    vulnerabilities.push({
      severity: 'info',
      title: 'Could Not Connect',
      description: `Unable to connect to ${url}: ${error.message}`,
      recommendation: 'Make sure the URL is correct and publicly accessible.'
    });
  }

  return vulnerabilities;
}

/**
 * Check for exposed sensitive files
 */
async function checkExposedFiles(url) {
  const vulnerabilities = [];
  const foundFiles = [];

  for (const file of EXPOSED_FILES) {
    try {
      const response = await makeRequest(url, file);

      // If we get a 200 response, the file is exposed
      if (response.statusCode === 200) {
        foundFiles.push(file);
      }
    } catch (error) {
      // Expected - file not found or connection error
    }
  }

  if (foundFiles.length > 0) {
    vulnerabilities.push({
      severity: 'critical',
      title: 'Exposed Sensitive Files',
      description: `We found ${foundFiles.length} sensitive file(s) that are publicly accessible: ${foundFiles.join(', ')}`,
      recommendation: 'These files should NEVER be publicly accessible. Remove them or block access via your web server config.'
    });
  }

  return vulnerabilities;
}

/**
 * Main security scan function
 */
async function scanUrl(url) {
  console.log(`Scanning: ${url}`);

  const results = {
    url: url,
    scannedAt: new Date().toISOString(),
    vulnerabilities: []
  };

  // Run all checks
  const headerVulns = await checkSecurityHeaders(url);
  const fileVulns = await checkExposedFiles(url);

  results.vulnerabilities = [...headerVulns, ...fileVulns];

  // Calculate summary
  const critical = results.vulnerabilities.filter(v => v.severity === 'critical').length;
  const high = results.vulnerabilities.filter(v => v.severity === 'high').length;
  const medium = results.vulnerabilities.filter(v => v.severity === 'medium').length;
  const low = results.vulnerabilities.filter(v => v.severity === 'low').length;

  results.summary = {
    total: results.vulnerabilities.length,
    critical,
    high,
    medium,
    low
  };

  return results;
}

/**
 * Netlify Function Handler
 */
exports.handler = async (event, context) => {
  const startTime = Date.now();

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    console.log('[ANALYTICS] Method not allowed:', event.httpMethod);
    return {
      statusCode: 405,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    // Get client IP for rate limiting
    const clientIP = event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
                     event.headers['client-ip'] ||
                     'unknown';

    // Check rate limit
    const { limited, retryAfter } = checkRateLimit(clientIP);
    if (limited) {
      const minutes = Math.ceil(retryAfter / 60);
      console.log('[ANALYTICS] Rate limit hit:', {
        ip: clientIP,
        retryAfter: minutes + ' minutes'
      });
      return {
        statusCode: 429,
        headers: {
          ...SECURITY_HEADERS,
          'Retry-After': retryAfter.toString()
        },
        body: JSON.stringify({
          error: `Slow down there. You've used your ${RATE_LIMIT.maxRequests} free scans. Come back in ${minutes} minute${minutes === 1 ? '' : 's'}.`,
          retryAfter: retryAfter
        })
      };
    }

    // Parse request body
    const body = JSON.parse(event.body);
    const { url, type } = body;

    if (!url) {
      console.log('[ANALYTICS] Missing URL in request');
      return {
        statusCode: 400,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({ error: 'URL is required' })
      };
    }

    // Validate URL format and check for SSRF
    let validatedUrl;
    try {
      validatedUrl = await validateUrl(url);
    } catch (error) {
      console.log('[ANALYTICS] Invalid URL:', {
        url: url,
        error: error.message
      });
      return {
        statusCode: 400,
        headers: SECURITY_HEADERS,
        body: JSON.stringify({ error: error.message })
      };
    }

    console.log('[ANALYTICS] Scan started:', {
      url: validatedUrl,
      type: type,
      ip: clientIP
    });

    // Run the scan
    const results = await scanUrl(validatedUrl);

    const duration = Date.now() - startTime;
    console.log('[ANALYTICS] Scan completed:', {
      url: validatedUrl,
      duration: duration + 'ms',
      vulnerabilities: {
        total: results.summary.total,
        critical: results.summary.critical,
        high: results.summary.high,
        medium: results.summary.medium,
        low: results.summary.low
      }
    });

    return {
      statusCode: 200,
      headers: SECURITY_HEADERS,
      body: JSON.stringify(results)
    };

  } catch (error) {
    console.error('[ANALYTICS] Scan error:', {
      error: error.message,
      stack: error.stack
    });
    return {
      statusCode: 500,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ error: 'Scan failed: ' + error.message })
    };
  }
};
