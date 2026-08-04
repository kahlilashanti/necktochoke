/**
 * Netlify Function - Get Scan Counter
 *
 * Returns the current number of scans performed
 */

const fs = require('fs');
const path = require('path');

// Path to counter file
const COUNTER_FILE = path.join(__dirname, '../../counter.json');

/**
 * Read current count from counter.json
 */
function readCount() {
  try {
    const data = fs.readFileSync(COUNTER_FILE, 'utf8');
    const json = JSON.parse(data);
    return json.count || 0;
  } catch (error) {
    console.error('Error reading counter:', error);
    // If file doesn't exist or is corrupted, return 0
    return 0;
  }
}

/**
 * Netlify Function Handler
 */
exports.handler = async (event, context) => {
  // Only allow GET requests
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const count = readCount();

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-cache'
      },
      body: JSON.stringify({ count })
    };
  } catch (error) {
    console.error('Error in count function:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ error: 'Failed to read counter' })
    };
  }
};
