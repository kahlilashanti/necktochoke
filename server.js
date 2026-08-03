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

const PORT = 8080;

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
 * Create HTTP server
 */
const server = http.createServer(async (req, res) => {
  console.log(`${req.method} ${req.url}`);

  // Handle /scan POST endpoint
  if (req.method === 'POST' && req.url === '/scan') {
    try {
      const body = await getRequestBody(req);
      const { url, type } = body;

      if (!url) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'URL is required' }));
        return;
      }

      // Validate URL format
      try {
        new URL(url);
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid URL format' }));
        return;
      }

      // Run the scan
      const results = await scanUrl(url);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(results));

    } catch (error) {
      console.error('Scan error:', error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
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
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 - File Not Found', 'utf-8');
      } else {
        res.writeHead(500);
        res.end(`Server Error: ${error.code}`, 'utf-8');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
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
