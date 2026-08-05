/**
 * Netlify Function - Increment Scan Counter
 *
 * Increments the scan counter when a scan completes successfully
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
 * Write new count to Netlify Blobs
 * @param {object} store - Netlify Blobs store instance
 * @param {number} count - New count value to save
 * @returns {Promise<boolean>} - Success status
 */
async function writeCount(store, count) {
  try {
    // Save count to blob storage as string
    await store.set('scanCount', count.toString());
    return true;
  } catch (error) {
    console.error('Error writing counter to blobs:', error);
    return false;
  }
}

/**
 * Netlify Function Handler
 * Increments the scan counter and returns new count
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
    // Get the counter store
    const store = getCounterStore(context);

    // Read current count
    const currentCount = await readCount(store);

    // Increment by 1
    const newCount = currentCount + 1;

    // Write new count back to storage
    const success = await writeCount(store, newCount);

    if (!success) {
      throw new Error('Failed to write counter to blob storage');
    }

    // Log the increment for analytics
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
