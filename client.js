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

  const optionCards = document.querySelectorAll('.option-card');
  const optionButtons = document.querySelectorAll('.option-button');
  const loadingMessage = document.getElementById('loadingMessage');
  const loadingText = document.getElementById('loadingText');
  const loadingSubtext = document.getElementById('loadingSubtext');
  const progressBar = document.getElementById('progressBar');
  const resultsSection = document.getElementById('resultsSection');
  const resultsContent = document.getElementById('resultsContent');
  const scrollIndicator = document.querySelector('.scroll-indicator');
  const safetyButton = document.getElementById('safetyButton');
  const safetyNotice = document.getElementById('safetyNotice');
  const closeNotice = document.getElementById('closeNotice');

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
     Progress Bar Animation
     =================================== */

  const progressMessages = [
    { progress: 0, text: "Checking if you left the door unlocked..." },
    { progress: 20, text: "Looking for exposed passwords and secrets..." },
    { progress: 40, text: "Testing your security headers..." },
    { progress: 60, text: "Checking if hackers can read your data..." },
    { progress: 80, text: "Almost done. Tallying up the damage..." },
    { progress: 95, text: "Preparing your results..." }
  ];

  function startProgressBar() {
    if (!progressBar) return;

    let currentIndex = 0;
    progressBar.style.width = '0%';

    const interval = setInterval(() => {
      if (currentIndex < progressMessages.length) {
        const msg = progressMessages[currentIndex];
        progressBar.style.width = msg.progress + '%';
        if (loadingSubtext) {
          loadingSubtext.textContent = msg.text;
        }
        currentIndex++;
      } else {
        clearInterval(interval);
      }
    }, 1000); // Change message every second

    return interval;
  }

  function stopProgressBar(interval) {
    if (interval) clearInterval(interval);
    if (progressBar) progressBar.style.width = '100%';
  }

  /* ===================================
     Safety Notice Toggle
     =================================== */

  if (safetyButton && safetyNotice && closeNotice) {
    safetyButton.addEventListener('click', () => {
      safetyNotice.classList.add('active');
      safetyNotice.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });

    closeNotice.addEventListener('click', () => {
      safetyNotice.classList.remove('active');
    });
  }

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
     Option Selection Handler
     =================================== */

  optionButtons.forEach(button => {
    button.addEventListener('click', () => {
      const card = button.parentElement;
      const optionType = card.dataset.option;

      // Hide all other cards
      optionCards.forEach(c => {
        if (c !== card) {
          c.style.display = 'none';
        }
      });

      // Activate this card
      card.classList.add('active');

      // Hide previous results if any
      loadingMessage.classList.remove('active');
      resultsSection.classList.remove('active');

      // Get input and button for this specific card
      const input = card.querySelector('.option-input');
      const scanButton = card.querySelector('.scan-button');
      const urlError = card.querySelector('.url-error');

      // Focus on input field
      setTimeout(() => input.focus(), 100);

      // Input validation for this card
      input.addEventListener('input', () => {
        const result = validateAndFixUrl(input.value);

        if (result.valid) {
          // Valid URL - enable button, clear error
          scanButton.disabled = false;
          urlError.textContent = '';
          urlError.classList.remove('active');
          // Auto-update the input with https:// if we added it
          if (result.url !== input.value.trim()) {
            input.value = result.url;
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

      // Enter key support
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !scanButton.disabled) {
          scanButton.click();
        }
      });

      // Scan button handler for this card
      scanButton.addEventListener('click', async () => {
        const result = validateAndFixUrl(input.value);

        if (!result.valid) {
          alert(result.error || 'Please enter a valid URL');
          return;
        }

        const url = result.url;

        // Show loading message
        loadingMessage.classList.add('active');
        resultsSection.classList.remove('active');
        scanButton.disabled = true;
        input.disabled = true;

        // Start progress bar animation
        const progressInterval = startProgressBar();

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
              type: optionType
            })
          });

          const data = await response.json();

          if (!response.ok) {
            throw new Error(data.error || 'Scan failed');
          }

          // Stop progress bar and hide loading
          stopProgressBar(progressInterval);
          setTimeout(() => {
            loadingMessage.classList.remove('active');
            displayResults(data);
          }, 500); // Brief pause to show 100% complete

        } catch (error) {
          console.error('Scan error:', error);
          stopProgressBar(progressInterval);
          loadingMessage.classList.remove('active');
          alert(`Scan failed: ${error.message}`);
        } finally {
          input.disabled = false;
          // Keep button disabled until they change the input
        }
      });
    }, { once: true }); // Only attach option button handler once per button
  });

  /* ===================================
     Display Results
     =================================== */

  function displayResults(data) {
    // Clear previous results
    resultsContent.innerHTML = '';

    // Create "Why should I care?" section
    const whyShouldICare = createWhyShouldICare(data);
    resultsContent.appendChild(whyShouldICare);

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

    // Add "Scan Another Site" button
    const resetButton = createResetButton();
    resultsContent.appendChild(resetButton);

    // Show results section
    resultsSection.classList.add('active');

    // Scroll to results
    setTimeout(() => {
      resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 100);
  }

  /* ===================================
     Create "Why Should I Care?" Section
     =================================== */

  function createWhyShouldICare(data) {
    const whyDiv = document.createElement('div');
    whyDiv.className = 'why-care-section';

    let message = '';
    const hasExposedFiles = data.vulnerabilities.some(v => v.title.includes('Exposed Sensitive Files'));
    const hasNoHttps = data.vulnerabilities.some(v => v.title.includes('No HTTPS'));
    const hasCritical = data.summary.critical > 0;
    const hasHigh = data.summary.high > 0;

    if (hasExposedFiles) {
      message = "🚨 Based on what we found, <strong>your passwords and secrets are public.</strong> Right now, anyone can download your .env file, API keys, or database credentials. This is like leaving your wallet on the sidewalk with a sign that says 'free money.'";
    } else if (hasNoHttps) {
      message = "⚠️ Based on what we found, <strong>everything your users type is visible.</strong> Passwords, credit cards, messages - it's all being sent in plain text. Anyone on the same WiFi can read it. This is illegal in many places and will get you sued.";
    } else if (hasCritical) {
      message = "🔥 Based on what we found, <strong>you have critical security holes.</strong> The kind that get you hacked, not 'maybe someday' but 'probably already happened.' Fix these immediately or take your site down.";
    } else if (hasHigh) {
      message = "⚠️ Based on what we found, <strong>your site is an easy target.</strong> You're missing basic protections that keep the script kiddies out. It's like leaving your front door unlocked in a bad neighborhood.";
    } else if (data.summary.medium > 0) {
      message = "⚡ Based on what we found, <strong>you're vulnerable to common attacks.</strong> Hackers could hijack your site, inject malicious code, or trick your users. Not good, but fixable.";
    } else if (data.summary.low > 0) {
      message = "✅ Based on what we found, <strong>you're mostly good!</strong> A few minor things to tighten up, but nothing urgent. You're better off than 90% of AI-built sites.";
    } else {
      message = "🎉 Based on what we found, <strong>nice work!</strong> We didn't find any obvious security issues. You're in good shape. (But this isn't a guarantee - consider a professional audit for anything important.)";
    }

    whyDiv.innerHTML = `
      <h3>Why should I care?</h3>
      <p>${message}</p>
    `;

    return whyDiv;
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
     Create Reset Button
     =================================== */

  function createResetButton() {
    const resetDiv = document.createElement('div');
    resetDiv.className = 'reset-section';

    resetDiv.innerHTML = `
      <button class="reset-button" id="resetButton">
        Scan Another Site
      </button>
    `;

    // Add click handler after inserting into DOM
    setTimeout(() => {
      const resetBtn = document.getElementById('resetButton');
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          // Hide results and loading
          resultsSection.classList.remove('active');
          loadingMessage.classList.remove('active');

          // Show all option cards again
          optionCards.forEach(card => {
            card.style.display = 'block';
            card.classList.remove('active');
          });

          // Reset all inputs and buttons in cards
          optionCards.forEach(card => {
            const input = card.querySelector('.option-input');
            const scanButton = card.querySelector('.scan-button');
            const urlError = card.querySelector('.url-error');

            if (input) input.value = '';
            if (scanButton) scanButton.disabled = true;
            if (urlError) {
              urlError.textContent = '';
              urlError.classList.remove('active');
            }
          });

          // Scroll back to top
          window.scrollTo({ top: 0, behavior: 'smooth' });
        });
      }
    }, 100);

    return resetDiv;
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

});
