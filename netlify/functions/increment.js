/**
 * Netlify Function - Increment Scan Counter
 *
 * Increments the scan counter when a scan completes successfully
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
    return 0;
  }
}

/**
 * Write new count to counter.json
 */
function writeCount(count) {
  try {
    fs.writeFileSync(COUNTER_FILE, JSON.stringify({ count }, null, 2), 'utf8');
    return true;
  } catch (error) {
    console.error('Error writing counter:', error);
    return false;
  }
}

/**
 * Netlify Function Handler
 */
exports.handler = async (event, context) => {
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
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
    // Read current count
    const currentCount = readCount();

    // Increment
    const newCount = currentCount + 1;

    // Write back
    const success = writeCount(newCount);

    if (!success) {
      throw new Error('Failed to write counter');
    }

    console.log('[ANALYTICS] Counter incremented:', {
      from: currentCount,
      to: newCount
    });

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ count: newCount })
    };
  } catch (error) {
    console.error('Error in increment function:', error);
    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({ error: 'Failed to increment counter' })
    };
  }
};
