/**
 * Counter Storage Module
 *
 * Handles counter storage for both local dev and Netlify production.
 * - Local: Uses counter.json file
 * - Netlify: Uses Netlify Blobs
 */

const fs = require('fs');
const path = require('path');

// Detect if we're running in Netlify
const isNetlify = process.env.NETLIFY === 'true';

// Import Netlify Blobs only when needed
let getStore;
if (isNetlify) {
  try {
    const blobs = require('@netlify/blobs');
    getStore = blobs.getStore;
  } catch (error) {
    console.error('Failed to import @netlify/blobs:', error);
  }
}

// Local file path for counter
const COUNTER_FILE = path.join(__dirname, 'counter.json');

// Starting count
const STARTING_COUNT = 1629;

/**
 * Get the current counter value
 * @returns {Promise<number>}
 */
async function getCount() {
  if (isNetlify) {
    // Netlify: Use Blobs
    try {
      if (!getStore) {
        throw new Error('Netlify Blobs not available');
      }
      const store = getStore('counters');
      const count = await store.get('scan-count');
      return count ? parseInt(count, 10) : STARTING_COUNT;
    } catch (error) {
      console.error('Error reading count from Netlify Blobs:', error);
      return STARTING_COUNT;
    }
  } else {
    // Local: Use file
    try {
      if (fs.existsSync(COUNTER_FILE)) {
        const data = fs.readFileSync(COUNTER_FILE, 'utf8');
        const json = JSON.parse(data);
        return json.count || STARTING_COUNT;
      }
      return STARTING_COUNT;
    } catch (error) {
      console.error('Error reading counter file:', error);
      return STARTING_COUNT;
    }
  }
}

/**
 * Increment the counter and return the new value
 * @returns {Promise<number>}
 */
async function incrementCount() {
  const currentCount = await getCount();
  const newCount = currentCount + 1;

  if (isNetlify) {
    // Netlify: Use Blobs
    try {
      if (!getStore) {
        throw new Error('Netlify Blobs not available');
      }
      const store = getStore('counters');
      await store.set('scan-count', newCount.toString());
      return newCount;
    } catch (error) {
      console.error('Error writing count to Netlify Blobs:', error);
      return currentCount; // Return old count on error
    }
  } else {
    // Local: Use file
    try {
      fs.writeFileSync(COUNTER_FILE, JSON.stringify({ count: newCount }, null, 2));
      return newCount;
    } catch (error) {
      console.error('Error writing counter file:', error);
      return currentCount; // Return old count on error
    }
  }
}

module.exports = {
  getCount,
  incrementCount
};
