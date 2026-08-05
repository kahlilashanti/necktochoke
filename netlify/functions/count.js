/**
 * Netlify Function - Get Scan Counter
 *
 * Returns the current number of scans performed
 * Uses Netlify Blobs for persistent serverless storage
 */

const { getStore } = require('@netlify/blobs');

// Starting count value
const STARTING_COUNT = 1551;

/**
 * Get the counter store from Netlify Blobs
 * @param {object} context - Netlify function context
 * @returns {object} - Netlify Blobs store instance
 */
function getCounterStore(context) {
  return getStore({
    name: 'counter',
    siteID: context.site?.id,
    token: context.token
  });
}

/**
 * Read current count from Netlify Blobs
 * @param {object} store - Netlify Blobs store instance
 * @returns {Promise<number>} - Current count value
 */
async function readCount(store) {
  try {
    // Get count from blob storage
    const countStr = await store.get('scanCount');

    // If no count exists yet, return starting count
    if (!countStr) {
      return STARTING_COUNT;
    }

    // Parse and return the count
    const count = parseInt(countStr, 10);
    return isNaN(count) ? STARTING_COUNT : count;
  } catch (error) {
    console.error('Error reading counter from blobs:', error);
    return STARTING_COUNT;
  }
}

/**
 * Netlify Function Handler
 * Returns the current scan count from blob storage
 * Includes fallback for local development (returns starting count)
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
    // Check if running locally (context.site will be undefined)
    const isLocal = !context.site || !context.site.id;

    if (isLocal) {
      // Local development: return starting count
      // Netlify Blobs don't work locally, so we just return a static value
      console.log('[LOCAL] Returning starting count:', STARTING_COUNT);
      return {
        statusCode: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-cache'
        },
        body: JSON.stringify({ count: STARTING_COUNT })
      };
    }

    // Production: use Netlify Blobs
    const store = getCounterStore(context);
    const count = await readCount(store);

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
