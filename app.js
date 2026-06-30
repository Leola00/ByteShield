(function () {
  'use strict';

  const SAMPLE_SCAM = `URGENT: Your bank account has been suspended due to suspicious activity. Verify your identity immediately or your funds will be frozen within 24 hours.

Click here to confirm: http://secure-bank-verify.xyz/login

Reply with your OTP code if you received one. Do NOT call the bank — this is faster.`;

  const RING_CIRCUMFERENCE = 327;

  const PHISHING_PATTERNS = [
    { re: /urgent|immediately|act now|within \d+ hours?|last chance|expires today/i, flag: 'Creates artificial urgency to bypass careful thinking', weight: 18 },
    { re: /verify your (identity|account)|confirm your (details|information)|update your (payment|billing)/i, flag: 'Requests identity or account verification — common phishing tactic', weight: 20 },
    { re: /otp|one.?time|verification code|pin code|security code/i, flag: 'Asks for OTP or security codes — never share these', weight: 25 },
    { re: /password|credentials|login details|ssn|social security/i, flag: 'Requests sensitive credentials or personal identifiers', weight: 22 },
    { re: /wire transfer|send money|bitcoin|crypto|gift card|western union/i, flag: 'Payment method commonly used in scams (wire, crypto, gift cards)', weight: 20 },
    { re: /account (suspended|locked|compromised|frozen|closed)/i, flag: 'Claims account is suspended or compromised to create panic', weight: 18 },
    { re: /click here|tap here|follow this link/i, flag: 'Pushes user to click a link rather than use official channels', weight: 12 },
    { re: /do not call|don't call|cannot call/i, flag: 'Discourages verification through official phone support', weight: 15 },
    { re: /congratulations|you('ve| have) won|lottery|prize|inheritance/i, flag: 'Unexpected prize or windfall — classic scam pattern', weight: 20 },
    { re: /irs|tax refund|government|customs|fedex|dhl|usps/i, flag: 'Impersonates government agency or delivery service', weight: 14 },
    { re: /apple id|microsoft|paypal|amazon|netflix|bank of/i, flag: 'References well-known brand — verify sender independently', weight: 10 },
    { re: /dear customer|dear user|dear member|valued customer/i, flag: 'Generic greeting instead of your actual name', weight: 8 },
  ];

  const URL_PATTERNS = [
    { test: (url) => /bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|short/i.test(url), flag: 'Uses URL shortener — hides true destination', weight: 15 },
    { test: (url) => {
      try {
        const host = new URL(url).hostname.replace(/^www\./, '');
        const suspicious = ['secure-', '-verify', '-login', '-update', '-support', 'account-', 'banking-'];
        return suspicious.some((s) => host.includes(s)) && !host.endsWith('.gov');
      } catch { return false; }
    }, flag: 'Domain mimics legitimate service (secure/login/verify pattern)', weight: 22 },
    { test: (url) => {
      try {
        const host = new URL(url).hostname;
        return /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host);
      } catch { return false; }
    }, flag: 'Uses raw IP address instead of trusted domain', weight: 20 },
    { test: (url) => /[^a-z0-9.-]/.test(new URL(url).hostname) || url.includes('@'), flag: 'Suspicious URL structure or credential injection', weight: 18 },
    { test: (url) => {
      try {
        const host = new URL(url).hostname;
        const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'whatsapp'];
        const tld = host.split('.').slice(-2).join('.');
        return brands.some((b) => host.includes(b) && !['paypal.com', 'amazon.com', 'apple.com', 'microsoft.com', 'google.com', 'facebook.com', 'instagram.com', 'whatsapp.com'].some(( legit) => host === legit || host.endsWith('.' + legit)));
      } catch { return false; }
    }, flag: 'Possible typosquatting — domain resembles a known brand', weight: 25 },
    { test: (url) => !/^https:\/\//i.test(url), flag: 'Not using HTTPS — data may be transmitted insecurely', weight: 12 },
    { test: (url) => (url.match(/\./g) || []).length > 3, flag: 'Unusually long subdomain chain — possible phishing redirect', weight: 14 },
  ];

  let activeTab = 'text';
  let screenshotFile = null;

  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.tab-panel');
  const btnScan = document.getElementById('btn-scan');
  const btnSample = document.getElementById('btn-sample');
  const results = document.getElementById('results');
  const resultsPlaceholder = document.getElementById('results-placeholder');
  const uploadZone = document.getElementById('upload-zone');
  const uploadTrigger = document.getElementById('upload-trigger');
  const inputScreenshot = document.getElementById('input-screenshot');
  const uploadEmpty = document.getElementById('upload-empty');
  const uploadPreview = document.getElementById('upload-preview');
  const previewImg = document.getElementById('preview-img');
  const uploadRemove = document.getElementById('upload-remove');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  function switchTab(name) {
    activeTab = name;
    tabs.forEach((t) => {
      const active = t.dataset.tab === name;
      t.classList.toggle('tab--active', active);
      t.setAttribute('aria-selected', active);
    });
    panels.forEach((p) => {
      const show = p.dataset.panel === name;
      p.hidden = !show;
      p.classList.toggle('tab-panel--active', show);
    });
  }

  btnSample.addEventListener('click', () => {
    switchTab('text');
    document.getElementById('input-text').value = SAMPLE_SCAM;
    showToast('Sample scam loaded — run analysis to see results');
  });

  uploadTrigger.addEventListener('click', () => inputScreenshot.click());
  inputScreenshot.addEventListener('change', handleFileSelect);
  uploadRemove.addEventListener('click', clearScreenshot);

  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('upload-zone--drag');
  });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('upload-zone--drag'));
  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('upload-zone--drag');
    if (e.dataTransfer.files[0]) setScreenshot(e.dataTransfer.files[0]);
  });

  function handleFileSelect(e) {
    if (e.target.files[0]) setScreenshot(e.target.files[0]);
  }

  function setScreenshot(file) {
    if (!file.type.startsWith('image/')) {
      showToast('Please upload an image file');
      return;
    }
    screenshotFile = file;
    previewImg.src = URL.createObjectURL(file);
    uploadEmpty.hidden = true;
    uploadPreview.hidden = false;
  }

  function clearScreenshot() {
    screenshotFile = null;
    inputScreenshot.value = '';
    uploadEmpty.hidden = false;
    uploadPreview.hidden = true;
    previewImg.src = '';
  }

  btnScan.addEventListener('click', runAnalysis);

  function getInputContent() {
    switch (activeTab) {
      case 'text':
        return { type: 'Message', text: document.getElementById('input-text').value.trim() };
      case 'email': {
        const subject = document.getElementById('input-email-subject').value.trim();
        const body = document.getElementById('input-email-body').value.trim();
        return { type: 'Email', text: [subject && `Subject: ${subject}`, body].filter(Boolean).join('\n\n') };
      }
      case 'url':
        return { type: 'URL', text: document.getElementById('input-url').value.trim() };
      case 'screenshot':
        return { type: 'Screenshot', text: '', hasImage: !!screenshotFile };
      default:
        return { type: 'Unknown', text: '' };
    }
  }

  function analyzeText(text) {
    const flags = [];
    let score = 8;

    PHISHING_PATTERNS.forEach(({ re, flag, weight }) => {
      if (re.test(text)) {
        flags.push(flag);
        score += weight;
      }
    });

    const urls = text.match(/https?:\/\/[^\s<>"']+/gi) || [];
    urls.forEach((url) => {
      URL_PATTERNS.forEach(({ test, flag, weight }) => {
        if (test(url)) {
          if (!flags.includes(flag)) flags.push(flag);
          score += weight;
        }
      });
    });

    if (text.length > 0 && text.length < 40 && /click|verify|urgent/i.test(text)) {
      flags.push('Very short message with high-pressure language');
      score += 10;
    }

    return { flags, score: Math.min(98, score) };
  }

  function analyzeUrl(url) {
    const flags = [];
    let score = 15;

    if (!url) {
      return { flags: ['No URL provided'], score: 0, invalid: true };
    }

    try {
      new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      return { flags: ['Invalid or malformed URL'], score: 85, invalid: false };
    }

    const fullUrl = url.startsWith('http') ? url : `https://${url}`;

    URL_PATTERNS.forEach(({ test, flag, weight }) => {
      if (test(fullUrl)) {
        flags.push(flag);
        score += weight;
      }
    });

    if (flags.length === 0) {
      flags.push('No obvious URL red flags detected — still verify independently');
      score = 22;
    }

    return { flags, score: Math.min(98, score) };
  }

  function analyzeScreenshot() {
    const flags = [
      'Screenshot uploaded — text extracted via OCR in production',
      'Demo mode: assuming conversation contains payment request',
      'Unknown sender identity cannot be verified from image alone',
      'Urgency language commonly found in scam screenshots',
    ];
    return {
      flags,
      score: 72,
      explanation: 'In production, ByteShield would use vision AI to read the screenshot, identify the messaging platform, extract all text, and cross-reference known scam patterns. This demo simulates a medium-high risk result for uploaded images.',
    };
  }

  function scoreToLevel(score) {
    if (score < 35) return { level: 'Low', class: 'low', verdict: 'Likely safe, but always verify independently' };
    if (score < 65) return { level: 'Medium', class: 'medium', verdict: 'Suspicious — proceed with caution' };
    return { level: 'High', class: 'high', verdict: 'Likely scam or phishing — do not interact' };
  }

  function getRecommendations(score, type) {
    const recs = [];
    if (score >= 65) {
      recs.push('Do not click any links or reply to this message');
      recs.push('Do not share passwords, OTP codes, or payment details');
      recs.push('Contact the organization directly using their official website or app');
      recs.push('Report the message to your bank, carrier, or local cybercrime authority');
    } else if (score >= 35) {
      recs.push('Verify the sender through an official channel before taking action');
      recs.push('Hover over links to inspect the real destination (on desktop)');
      recs.push('Search for similar scam reports online');
      recs.push('When in doubt, ignore the message and call official support');
    } else {
      recs.push('Content appears relatively safe based on pattern analysis');
      recs.push('Still verify sender identity if anything feels off');
      recs.push('Never share sensitive codes or credentials unprompted');
    }
    if (type === 'URL') {
      recs.unshift('Type the official website address manually instead of clicking the link');
    }
    if (type === 'Screenshot') {
      recs.unshift('Ask the sender to verify their identity through a known contact method');
    }
    return recs;
  }

  function buildExplanation(text, flags, score, type) {
    const { level } = scoreToLevel(score);
    const parts = [
      `ByteShield analyzed this ${type.toLowerCase()} and assigned a ${level.toLowerCase()} risk score of ${score}/100.`,
    ];
    if (flags.length > 0) {
      parts.push(`We identified ${flags.length} concern${flags.length > 1 ? 's' : ''} including ${flags[0].toLowerCase()}.`);
    }
    if (score >= 65) {
      parts.push('Multiple indicators match known financial fraud and phishing campaigns. The combination of urgency, credential requests, and suspicious links is a strong scam signal.');
    } else if (score >= 35) {
      parts.push('Some patterns resemble social engineering tactics. Legitimate organizations rarely pressure you to act immediately via unsolicited messages.');
    } else {
      parts.push('No major phishing patterns were detected, but social engineering can be subtle. Trust your instincts if something feels wrong.');
    }
    return parts.join(' ');
  }

  async function runAnalysis() {
    const input = getInputContent();

    if (activeTab === 'screenshot') {
      if (!input.hasImage) {
        showToast('Please upload a screenshot first');
        return;
      }
    } else if (!input.text) {
      showToast('Please enter content to analyze');
      return;
    }

    btnScan.classList.add('scanning');
    btnScan.textContent = 'Analyzing…';

    await delay(1400);

    let analysis;
    if (activeTab === 'url') {
      analysis = analyzeUrl(input.text);
    } else if (activeTab === 'screenshot') {
      analysis = analyzeScreenshot();
    } else {
      analysis = analyzeText(input.text);
    }

    if (analysis.invalid) {
      showToast('Please enter content to analyze');
      btnScan.classList.remove('scanning');
      btnScan.innerHTML = '<span class="btn__icon" aria-hidden="true">🛡️</span> Run security analysis';
      return;
    }

    const { level, class: levelClass, verdict } = scoreToLevel(analysis.score);
    const recommendations = getRecommendations(analysis.score, input.type);
    const explanation = analysis.explanation || buildExplanation(input.text, analysis.flags, analysis.score, input.type);

    renderResults(analysis.score, level, levelClass, verdict, analysis.flags, recommendations, explanation);

    btnScan.classList.remove('scanning');
    btnScan.innerHTML = '<span class="btn__icon" aria-hidden="true">🛡️</span> Run security analysis';
  }

  function renderResults(score, level, levelClass, verdict, flags, recommendations, explanation) {
    resultsPlaceholder.hidden = true;
    results.hidden = false;

    document.getElementById('results-time').textContent = new Date().toLocaleString();
    document.getElementById('risk-score').textContent = score;

    const ring = document.getElementById('risk-ring');
    ring.className = 'risk-gauge__fill risk-gauge__fill--' + levelClass;
    ring.style.strokeDashoffset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;

    const badge = document.getElementById('risk-level');
    badge.textContent = level + ' risk';
    badge.className = 'risk-badge risk-badge--' + levelClass;

    document.getElementById('risk-verdict').textContent = verdict;

    const flagList = document.getElementById('flag-list');
    flagList.innerHTML = flags.map((f) => `<li>${escapeHtml(f)}</li>`).join('');

    const recList = document.getElementById('rec-list');
    recList.innerHTML = recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join('');

    document.getElementById('ai-explanation').textContent = explanation;

    results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function showToast(message) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.hidden = false;
    toast.classList.add('toast--visible');
    setTimeout(() => {
      toast.classList.remove('toast--visible');
      setTimeout(() => { toast.hidden = true; }, 300);
    }, 2800);
  }

  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
