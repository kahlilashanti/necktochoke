/**
 * Netlify Function - Counter Endpoint
 *
 * Returns the current scan counter value
 */

const { getCount } = require('../../counter-storage');

// Security headers for all responses
const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

/**
 * Netlify Function Handler
 */
exports.handler = async (event, context) => {
  // Only allow GET requests
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const count = await getCount();

    return {
      statusCode: 200,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ count })
    };
  } catch (error) {
    console.error('Counter error:', error);
    return {
      statusCode: 500,
      headers: SECURITY_HEADERS,
      body: JSON.stringify({ error: 'Failed to read counter' })
    };
  }
};
