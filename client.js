/**
 * NeckToChoke Client-Side Logic
 *
 * Handles user interactions:
 * - Option selection (URL, GitHub, or "No idea")
 * - URL validation and auto-https
 * - Porn detection
 * - Making API calls to scan endpoints
 * - Displaying security scan results
 * - Copy to clipboard functionality
 */

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', () => {

  /* ===================================
     DOM Elements
     =================================== */

  const optionButtons = document.querySelectorAll('.option-button');
  const inputSection = document.getElementById('inputSection');
  const inputPrompt = document.getElementById('inputPrompt');
  const userInput = document.getElementById('userInput');
  const scanButton = document.getElementById('scanButton');
  const loadingMessage = document.getElementById('loadingMessage');
  const resultsSection = document.getElementById('resultsSection');
  const resultsContent = document.getElementById('resultsContent');
  const urlError = document.getElementById('urlError');
  const scrollIndicator = document.querySelector('.scroll-indicator');

  let selectedType = 'url'; // Track which option was selected

  // Scan button starts disabled
  scanButton.disabled = true;

  /* ===================================
     Hide Scroll Indicator on Interaction
     =================================== */

  function hideScrollIndicator() {
    if (scrollIndicator) {
      scrollIndicator.classList.add('hidden');
    }
  }

  // Hide on scroll
  window.addEventListener('scroll', hideScrollIndicator, { once: true });

  // Hide on any option button click
  optionButtons.forEach(button => {
    button.addEventListener('click', hideScrollIndicator, { once: true });
  });

  /* ===================================
     Porn Keywords Detection
     =================================== */

  const PORN_KEYWORDS = [
    'porn', 'xxx', 'sex', 'adult', 'nsfw', 'nude', 'naked', 'hentai',
    'xvideos', 'pornhub', 'redtube', 'xhamster', 'youporn', 'tube8',
    'onlyfans', 'chaturbate', 'cam4', 'livejasmin'
  ];

  function isPornUrl(url) {
    const urlLower = url.toLowerCase();
    return PORN_KEYWORDS.some(keyword => urlLower.includes(keyword));
  }

  /* ===================================
     URL Validation and Auto-HTTPS
     =================================== */

  function validateAndFixUrl(input) {
    let url = input.trim();

    if (!url) {
      return { valid: false, error: '' };
    }

    // Check for porn
    if (isPornUrl(url)) {
      return { valid: false, error: 'Really? Get your priorities straight.' };
    }

    // Auto-add https:// if no protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    // Reject http:// - we only do https
    if (url.startsWith('http://')) {
      return {
        valid: false,
        error: 'We only scan HTTPS sites. Fix that first, then come back.',
        fixedUrl: url.replace('http://', 'https://')
      };
    }

    // Validate URL format
    try {
      new URL(url);
      return { valid: true, url: url, error: '' };
    } catch (error) {
      return { valid: false, error: 'That doesn\'t look like a valid URL.' };
    }
  }

  /* ===================================
     Input Change Handler - Enable/Disable Button
     =================================== */

  userInput.addEventListener('input', () => {
    const result = validateAndFixUrl(userInput.value);

    if (result.valid) {
      // Valid URL - enable button, clear error
      scanButton.disabled = false;
      urlError.textContent = '';
      urlError.classList.remove('active');
      // Auto-update the input with https:// if we added it
      if (result.url !== userInput.value.trim()) {
        userInput.value = result.url;
      }
    } else {
      // Invalid URL - disable button, show error
      scanButton.disabled = true;
      if (result.error) {
        urlError.textContent = result.error;
        urlError.classList.add('active');
      } else {
        urlError.classList.remove('active');
      }
    }
  });

  /* ===================================
     Option Selection Handler
     =================================== */

  optionButtons.forEach(button => {
    button.addEventListener('click', () => {
      // Get the selected option type from parent card
      const optionType = button.parentElement.dataset.option;
      selectedType = optionType;

      // Show input section
      inputSection.classList.add('active');

      // Hide previous results if any
      loadingMessage.classList.remove('active');
      resultsSection.classList.remove('active');
      urlError.classList.remove('active');

      // Clear input field and disable button
      userInput.value = '';
      scanButton.disabled = true;

      // Set appropriate prompt based on option selected
      switch (optionType) {
        case 'url':
          inputPrompt.textContent = 'Paste your website link below:';
          userInput.placeholder = 'yourapp.com or mysite.lovable.app';
          break;

        case 'github':
          inputPrompt.textContent = 'Paste your GitHub link:';
          userInput.placeholder = 'github.com/username/repo';
          break;

        case 'noIdea':
          // Option 3 routes to same flow as option 1 with friendlier copy
          inputPrompt.textContent = "No worries! Just paste the link to what you built:";
          userInput.placeholder = 'yourapp.com';
          break;

        default:
          inputPrompt.textContent = 'Paste your link here:';
          userInput.placeholder = 'yourapp.com';
      }

      // Focus on input field for better UX
      userInput.focus();

      // Smooth scroll to input section
      inputSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  });

  /* ===================================
     Scan Button Handler
     =================================== */

  scanButton.addEventListener('click', async () => {
    const result = validateAndFixUrl(userInput.value);

    if (!result.valid) {
      alert(result.error || 'Please enter a valid URL');
      return;
    }

    const url = result.url;

    // Show loading message
    loadingMessage.classList.add('active');
    resultsSection.classList.remove('active');
    scanButton.disabled = true;
    userInput.disabled = true;

    // Scroll to loading message
    setTimeout(() => {
      loadingMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);

    try {
      // Make API call to scan endpoint
      const response = await fetch('/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: url,
          type: selectedType
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Scan failed');
      }

      // Hide loading, show results
      loadingMessage.classList.remove('active');
      displayResults(data);

    } catch (error) {
      console.error('Scan error:', error);
      loadingMessage.classList.remove('active');
      alert(`Scan failed: ${error.message}`);
    } finally {
      userInput.disabled = false;
      // Keep button disabled until they change the input
    }
  });

  /* ===================================
     Display Results
     =================================== */

  function displayResults(data) {
    // Clear previous results
    resultsContent.innerHTML = '';

    // Create summary section
    const summary = createSummary(data.summary);
    resultsContent.appendChild(summary);

    // Store all advice for copying
    let allAdvice = [];

    // Display vulnerabilities
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      data.vulnerabilities.forEach(vuln => {
        const vulnElement = createVulnerabilityCard(vuln);
        resultsContent.appendChild(vulnElement);

        // Collect advice
        allAdvice.push({
          title: vuln.title,
          description: vuln.description,
          fix: vuln.recommendation
        });
      });
    } else {
      const noIssues = document.createElement('div');
      noIssues.className = 'vulnerability success';
      noIssues.innerHTML = `
        <h4>No Issues Found</h4>
        <p>We didn't find any obvious security problems. That doesn't mean you're 100% safe, but it's a good start.</p>
      `;
      resultsContent.appendChild(noIssues);
    }

    // Add action buttons at the end
    if (allAdvice.length > 0) {
      const actionsDiv = createActionButtons(data, allAdvice);
      resultsContent.appendChild(actionsDiv);
    }

    // Show results section
    resultsSection.classList.add('active');

    // Scroll to results
    setTimeout(() => {
      resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
  }

  /* ===================================
     Create Action Buttons
     =================================== */

  function createActionButtons(data, allAdvice) {
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'action-buttons';

    // Format advice for AI bot
    let adviceText = `Security scan results for ${data.url}\n\n`;
    adviceText += `Found ${data.summary.total} issue${data.summary.total === 1 ? '' : 's'}:\n\n`;

    allAdvice.forEach((item, index) => {
      adviceText += `${index + 1}. ${item.title}\n`;
      adviceText += `   Problem: ${item.description}\n`;
      adviceText += `   Fix: ${item.fix}\n\n`;
    });

    actionsDiv.innerHTML = `
      <h3>What now?</h3>
      <div class="button-group">
        <button class="action-button copy-button" id="copyAdvice">
          Copy advice for my AI bot
        </button>
        <button class="action-button fix-button" id="fixIt">
          Just fix it for me
        </button>
      </div>
    `;

    // Add click handlers after inserting into DOM
    setTimeout(() => {
      const copyButton = document.getElementById('copyAdvice');
      const fixButton = document.getElementById('fixIt');

      if (copyButton) {
        copyButton.addEventListener('click', () => {
          navigator.clipboard.writeText(adviceText).then(() => {
            copyButton.textContent = 'Copied!';
            setTimeout(() => {
              copyButton.textContent = 'Copy advice for my AI bot';
            }, 2000);
          }).catch(err => {
            alert('Failed to copy. Try selecting and copying manually.');
          });
        });
      }

      if (fixButton) {
        fixButton.addEventListener('click', () => {
          const message = `Alright, we'll fix it for you.\n\nJust kidding. We're not actually going to touch your code - that's terrifying.\n\nBut we copied the advice to your clipboard. Paste it into ChatGPT/Claude/Cursor and they'll help you fix it.\n\nOr hire a real security professional. Seriously.`;
          alert(message);

          // Also copy the advice
          navigator.clipboard.writeText(adviceText).then(() => {
            console.log('Advice copied to clipboard');
          });
        });
      }
    }, 100);

    return actionsDiv;
  }

  /* ===================================
     Create Summary Card
     =================================== */

  function createSummary(summary) {
    const summaryDiv = document.createElement('div');
    summaryDiv.className = 'summary';

    let scoreClass = 'good';
    let scoreText = 'Pretty Good';

    if (summary.critical > 0) {
      scoreClass = 'danger';
      scoreText = 'Yikes';
    } else if (summary.high > 0) {
      scoreClass = 'danger';
      scoreText = 'Not Great';
    } else if (summary.medium > 0) {
      scoreClass = 'warning';
      scoreText = 'Could Be Better';
    }

    summaryDiv.innerHTML = `
      <h3>Security Score</h3>
      <div class="score ${scoreClass}">${scoreText}</div>
      <p>${summary.total} issue${summary.total === 1 ? '' : 's'} found</p>
      ${summary.critical > 0 ? `<p style="color: #ff4444;">${summary.critical} critical</p>` : ''}
      ${summary.high > 0 ? `<p style="color: #ff6666;">${summary.high} high</p>` : ''}
      ${summary.medium > 0 ? `<p style="color: #ffaa00;">${summary.medium} medium</p>` : ''}
      ${summary.low > 0 ? `<p style="color: #888;">${summary.low} low</p>` : ''}
    `;

    return summaryDiv;
  }

  /* ===================================
     Create Vulnerability Card
     =================================== */

  function createVulnerabilityCard(vuln) {
    const card = document.createElement('div');

    // Map severity to CSS class
    const severityClass = vuln.severity === 'critical' || vuln.severity === 'high'
      ? 'vulnerability'
      : vuln.severity === 'medium'
        ? 'vulnerability warning'
        : vuln.severity === 'info'
          ? 'vulnerability info'
          : 'vulnerability';

    card.className = severityClass;

    const severityBadge = `<span style="
      display: inline-block;
      padding: 0.2rem 0.5rem;
      background-color: ${getSeverityColor(vuln.severity)};
      color: #fff;
      font-size: 0.8rem;
      font-weight: 700;
      text-transform: uppercase;
      margin-bottom: 0.5rem;
    ">${vuln.severity}</span>`;

    card.innerHTML = `
      ${severityBadge}
      <h4>${escapeHtml(vuln.title)}</h4>
      <p><strong>What this means:</strong> ${escapeHtml(vuln.description)}</p>
      <p><strong>How to fix it:</strong> ${escapeHtml(vuln.recommendation)}</p>
    `;

    return card;
  }

  /* ===================================
     Utility Functions
     =================================== */

  function getSeverityColor(severity) {
    switch (severity) {
      case 'critical': return '#cc0000';
      case 'high': return '#ff4444';
      case 'medium': return '#ffaa00';
      case 'low': return '#666';
      case 'info': return '#4444ff';
      default: return '#666';
    }
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /* ===================================
     Enter Key Support for Input Field
     =================================== */

  userInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !scanButton.disabled) {
      scanButton.click();
    }
  });

});
