/**
 * NeckToChoke - Security Scanner Server
 *
 * Plain Node.js HTTP server with security scanning capabilities.
 * Serves static files and provides a /scan API endpoint.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const dns = require('dns').promises;

const PORT = 8080;

// Security headers to add to all responses
const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

// MIME types for serving static files
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

/**
 * Security Scanner Functions
 */

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

    // Check for X-Frame-Options (skip if CSP frame-ancestors is present)
    const cspHeader = headers['content-security-policy'] || '';
    const hasFrameAncestors = cspHeader.includes('frame-ancestors');

    if (!headers['x-frame-options'] && !hasFrameAncestors) {
      vulnerabilities.push({
        severity: 'medium',
        title: 'Missing X-Frame-Options',
        description: 'Your site can be embedded in iframes, making it vulnerable to clickjacking attacks.',
        recommendation: 'Add the header: X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive'
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

      // Only flag as exposed if:
      // 1. Status code is 200 (not 404, 403, etc.)
      // 2. Response has content (not empty or minimal)
      // 3. Response doesn't look like an error page
      const hasContent = response.body && response.body.length > 20;
      const looksLikeErrorPage = response.body && (
        response.body.toLowerCase().includes('not found') ||
        response.body.toLowerCase().includes('404') ||
        response.body.toLowerCase().includes('error')
      );

      if (response.statusCode === 200 && hasContent && !looksLikeErrorPage) {
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
 * Handle POST request body
 */
function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk.toString();
      // Prevent massive payloads
      if (body.length > 10000) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });

    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', (error) => {
      reject(error);
    });
  });
}

/**
 * Read counter from counter.json
 */
function readCounter() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'counter.json'), 'utf8');
    const json = JSON.parse(data);
    return json.count || 0;
  } catch (error) {
    console.error('Error reading counter:', error);
    return 0;
  }
}

/**
 * Write counter to counter.json
 */
function writeCounter(count) {
  try {
    fs.writeFileSync(
      path.join(__dirname, 'counter.json'),
      JSON.stringify({ count }, null, 2),
      'utf8'
    );
    return true;
  } catch (error) {
    console.error('Error writing counter:', error);
    return false;
  }
}

/**
 * Create HTTP server
 */
const server = http.createServer(async (req, res) => {
  console.log(`${req.method} ${req.url}`);

  // Handle /count GET endpoint
  if (req.method === 'GET' && req.url === '/count') {
    try {
      const count = readCounter();
      res.writeHead(200, {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      });
      res.end(JSON.stringify({ count }));
    } catch (error) {
      console.error('Count error:', error);
      res.writeHead(500, {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      });
      res.end(JSON.stringify({ error: 'Failed to read counter' }));
    }
    return;
  }

  // Handle /increment POST endpoint
  if (req.method === 'POST' && req.url === '/increment') {
    try {
      const currentCount = readCounter();
      const newCount = currentCount + 1;
      const success = writeCounter(newCount);

      if (!success) {
        throw new Error('Failed to write counter');
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      });
      res.end(JSON.stringify({ count: newCount }));
    } catch (error) {
      console.error('Increment error:', error);
      res.writeHead(500, {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      });
      res.end(JSON.stringify({ error: 'Failed to increment counter' }));
    }
    return;
  }

  // Handle /scan POST endpoint
  if (req.method === 'POST' && req.url === '/scan') {
    try {
      const body = await getRequestBody(req);
      const { url, type } = body;

      if (!url) {
        res.writeHead(400, {
          'Content-Type': 'application/json',
          ...SECURITY_HEADERS
        });
        res.end(JSON.stringify({ error: 'URL is required' }));
        return;
      }

      // Validate URL format and check for SSRF
      let validatedUrl;
      try {
        validatedUrl = await validateUrl(url);
      } catch (error) {
        res.writeHead(400, {
          'Content-Type': 'application/json',
          ...SECURITY_HEADERS
        });
        res.end(JSON.stringify({ error: error.message }));
        return;
      }

      // Run the scan
      const results = await scanUrl(validatedUrl);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      });
      res.end(JSON.stringify(results));

    } catch (error) {
      console.error('Scan error:', error);
      res.writeHead(500, {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      });
      res.end(JSON.stringify({ error: 'Scan failed: ' + error.message }));
    }
    return;
  }

  // Serve static files for all other requests
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, filePath);

  const extname = String(path.extname(filePath)).toLowerCase();
  const contentType = MIME_TYPES[extname] || 'application/octet-stream';

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === 'ENOENT') {
        res.writeHead(404, {
          'Content-Type': 'text/plain',
          ...SECURITY_HEADERS
        });
        res.end('404 - File Not Found', 'utf-8');
      } else {
        res.writeHead(500, SECURITY_HEADERS);
        res.end(`Server Error: ${error.code}`, 'utf-8');
      }
    } else {
      const headers = {
        'Content-Type': contentType,
        ...SECURITY_HEADERS
      };

      // Add CSP for HTML files
      if (extname === '.html') {
        headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' data: https://cdn.jsdelivr.net; connect-src 'self'";
      }

      res.writeHead(200, headers);
      res.end(content, 'utf-8');
    }
  });
});

/**
 * Start server
 */
server.listen(PORT, () => {
  console.log(`🔒 NeckToChoke is running at http://localhost:${PORT}`);
  console.log(`   Security for people who don't know what security is.`);
});
