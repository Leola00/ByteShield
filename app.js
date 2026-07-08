(function () {
  'use strict';

  const SAMPLE_SCAM = `URGENT: Your bank account has been suspended due to suspicious activity. Verify your identity immediately or your funds will be frozen within 24 hours.

Click here to confirm: http://secure-bank-verify.xyz/login

Reply with your OTP code if you received one. Do NOT call the bank — this is faster.`;

  const RING_MAX = 100;

  const GAUGE_COLORS = { low: '#059669', medium: '#d97706', high: '#dc2626' };

  const EVAL_METRICS = [
    { key: 'senderAuthenticity', label: 'مصدر الرسالة' },
    { key: 'languageAnalysis', label: 'محتوى الرسالة' },
    { key: 'linkSafety', label: 'الروابط' },
    { key: 'financialFraudIndicators', label: 'المرفقات' },
  ];

  const SAUDI_TZ = 'Asia/Riyadh';

  function formatSaudiDateTime(date = new Date()) {
    return new Intl.DateTimeFormat('ar-SA', {
      timeZone: SAUDI_TZ,
      calendar: 'gregory',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    }).format(date);
  }

  let lastAnalysisContext = '';
  let lastSocReport = null;
  let lastUserReport = null;
  let socReportLoading = false;
  let lastEvidenceText = '';
  let lastContentType = 'Message';
  let activeMode = 'user';
  let chatHistory = [];

  function getApiUrl(path) {
    const { protocol, hostname, port } = window.location;
    if (port === '3000') return path;
    const host = hostname || 'localhost';
    return `http://${host}:3000${path}`;
  }

  function getAnalyzeUrl() {
    return getApiUrl('/analyze');
  }

  function getAnalyzeFileUrl() {
    return getApiUrl('/analyze-file');
  }

  function getSocReportUrl() {
    return getApiUrl('/soc-report');
  }

  function getAnalyticsUrl() {
    return getApiUrl('/api/analytics');
  }

  function getFinancialForecastUrl() {
    return getApiUrl('/api/financial-forecast');
  }

  function getPredictUrlEndpoint() {
    return getApiUrl('/predict-url');
  }

  function getScoreTier(score) {
    if (score <= 30) {
      return {
        levelClass: 'low',
        statusEn: 'Safe',
        statusAr: 'آمن',
        tierLabel: 'منخفض المخاطر',
        badge: 'آمن',
        defaultMessage: '✅ تبدو هذه الرسالة آمنة',
      };
    }
    if (score <= 60) {
      return {
        levelClass: 'medium',
        statusEn: 'Suspicious',
        statusAr: 'مشبوه',
        tierLabel: 'مشبوه',
        badge: 'مشبوه',
        defaultMessage: '⚠️ هذه الرسالة مشبوهة',
      };
    }
    return {
      levelClass: 'high',
      statusEn: 'High Risk',
      statusAr: 'خطر مرتفع',
      tierLabel: 'خطر مرتفع',
      badge: 'خطر مرتفع',
      defaultMessage: '🚨 احتمال عالٍ للتصيد أو الاحتيال',
    };
  }

  function getDefaultActions(score) {
    if (score <= 30) {
      return [
        'لا يلزم إجراء فوري',
        'ابقَ حذراً دائماً',
        'تحقق من أي طلب غير متوقع عبر القنوات الرسمية',
      ];
    }
    if (score <= 60) {
      return [
        'لا تنقر على أي روابط حتى تتأكد',
        'تحقق من المرسل عبر القنوات الرسمية',
        'لا تشارك بياناتك البنكية أو رموز OTP',
        'ابحث عن تقارير مشابهة للاحتيال',
      ];
    }
    return [
      'لا تنقر على الرابط',
      'لا تشارك بياناتك البنكية أو كلمات المرور',
      'تحقق من المرسل عبر القنوات الرسمية',
      'احظر المرسل إن أمكن',
      'أبلغ عن الرسالة للجهات المختصة',
      'احذف الرسالة إذا تأكدت أنها احتيال',
    ];
  }

  function getDefaultTips(threatType) {
    const tips = {
      phishing: ['لا تثق بالروابط في الرسائل — اكتب عنوان الموقع يدوياً', 'البنوك لا تطلب OTP عبر الرسائل', 'تحقق من هوية المرسل قبل أي إجراء'],
      banking_fraud: ['استخدم فقط التطبيق أو الموقع الرسمي للبنك', 'لا تشارك رمز التحقق مع أي شخص', 'اتصل بالبنك عبر الرقم الرسمي'],
      investment_scam: ['العوائد المضمونة غالباً احتيال', 'تحقق من تراخيص الشركات عبر SAMA', 'لا تحوّل أموالاً لجهات غير موثوقة'],
      delivery_scam: ['تحقق من رقم التتبع عبر موقع الشركة الرسمي', 'لا تدفع رسوماً إضافية عبر روابط مشبوهة', 'تواصل مع شركة الشحن مباشرة'],
      social_engineering: ['لا تتخذ قرارات تحت الضغط', 'تحقق من الهوية عبر قناة ثانية', 'الجهات الرسمية لا تهدد بإغلاق الحساب فوراً'],
    };
    return tips[threatType] || tips.phishing;
  }

  const SUPPORT_CONTACTS = [
    { section: 'الجهات الحكومية', items: [
      { name: 'الهيئة الوطنية للأمن السيبراني (NCA)', number: 'ncsc.gov.sa', link: 'https://ncsc.gov.sa', desc: 'التوعية والإرشادات الأمنية' },
      { name: 'البنك المركزي السعودي (SAMA) — حماية العملاء', number: '8001256666', tel: '8001256666', desc: 'التوعية بالاحتيال المالي وحقوق العملاء' },
      { name: 'منصة الإبلاغ عن الاحتيال المالي (سامر)', number: 'samar.gov.sa', link: 'https://www.sama.gov.sa/ar-sa/consumerprotection/pages/fraudandscams.aspx', desc: 'تقديم بلاغ عن عملية احتيال' },
      { name: 'الإبلاغ عن الجرائم المعلوماتية', number: '9200343222', tel: '9200343222', desc: 'الابتزاز الإلكتروني والجرائم السيبرانية' },
    ]},
    { section: 'خطوط الاحتيال البنكي (قابلة للتعديل)', items: [
      { name: 'مصرف الإنماء', number: '920028000', tel: '920028000', desc: 'خدمة العملاء والتحقق من الرسائل' },
      { name: 'البنك الأهلي السعودي (SNB)', number: '9200001000', tel: '9200001000', desc: 'placeholder — حدّث الرقم الرسمي' },
      { name: 'مصرف الراجحي', number: '920003344', tel: '920003344', desc: 'placeholder — حدّث الرقم الرسمي' },
      { name: 'بنك الرياض', number: '920002470', tel: '920002470', desc: 'placeholder — حدّث الرقم الرسمي' },
      { name: 'بنك سامبا', number: '8001248000', tel: '8001248000', desc: 'placeholder — حدّث الرقم الرسمي' },
    ]},
    { section: 'البريد الإلكتروني للإبلاغ', items: [
      { name: 'الإبلاغ عن التصيد — placeholder', number: 'phishing@example.gov.sa', mailto: 'phishing@example.gov.sa', desc: 'حدّث بريد الإبلاغ الرسمي' },
    ]},
  ];

  const PHISHING_PATTERNS = [
    { re: /urgent|immediately|act now|within \d+ hours?|last chance|expires today|عاجل|فوراً|خلال \d+/i, flag: 'يخلق استعجالاً مصطنعاً لمنعك من التفكير بعناية', weight: 18 },
    { re: /verify your (identity|account)|confirm your (details|information)|update your (payment|billing)|تحقق من|تأكيد حساب/i, flag: 'يطلب التحقق من الهوية أو الحساب — تكتيك تصيد شائع', weight: 20 },
    { re: /otp|one.?time|verification code|pin code|security code|رمز التحقق|رمز OTP/i, flag: 'يطلب رمز OTP أو رموز أمنية — لا تشاركها أبداً', weight: 25 },
    { re: /password|credentials|login details|ssn|social security|كلمة المرور|بيانات الدخول/i, flag: 'يطلب بيانات اعتماد أو معلومات شخصية حساسة', weight: 22 },
    { re: /wire transfer|send money|bitcoin|crypto|gift card|western union|تحويل|bitcoin/i, flag: 'طرق دفع شائعة في الاحتيال (تحويل، عملات رقمية، بطاقات هدايا)', weight: 20 },
    { re: /account (suspended|locked|compromised|frozen|closed)|حساب.*(موقوف|معلق|مجمد)/i, flag: 'يدّعي أن حسابك موقوف أو مخترق لإثارة الذعر', weight: 18 },
    { re: /click here|tap here|follow this link|اضغط هنا|انقر/i, flag: 'يحثك على النقر على رابط بدلاً من القنوات الرسمية', weight: 12 },
    { re: /do not call|don't call|cannot call|لا تتصل/i, flag: 'يمنعك من التحقق عبر الهاتف الرسمي للبنك', weight: 15 },
    { re: /congratulations|you('ve| have) won|lottery|prize|inheritance|مبروك|فزت|جائزة/i, flag: 'جائزة أو مكسب غير متوقع — نمط احتيال كلاسيكي', weight: 20 },
    { re: /irs|tax refund|government|customs|fedex|dhl|usps|البنك|مصرف/i, flag: 'انتحال جهة حكومية أو شركة توصيل أو بنك', weight: 14 },
    { re: /apple id|microsoft|paypal|amazon|netflix|bank of|الإنماء|alinma/i, flag: 'يشير إلى علامة تجارية معروفة — تحقق من المرسل بشكل مستقل', weight: 10 },
    { re: /dear customer|dear user|dear member|valued customer|عزيزي العميل/i, flag: 'تحية عامة بدلاً من اسمك الحقيقي', weight: 8 },
  ];

  const URL_PATTERNS = [
    { test: (url) => /bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|short/i.test(url), flag: 'يستخدم اختصار روابط — يخفي الوجهة الحقيقية', weight: 15 },
    { test: (url) => {
      try {
        const host = new URL(url).hostname.replace(/^www\./, '');
        const suspicious = ['secure-', '-verify', '-login', '-update', '-support', 'account-', 'banking-'];
        return suspicious.some((s) => host.includes(s)) && !host.endsWith('.gov');
      } catch { return false; }
    }, flag: 'النطاق يحاكي خدمة موثوقة (secure/login/verify)', weight: 22 },
    { test: (url) => {
      try {
        const host = new URL(url).hostname;
        return /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host);
      } catch { return false; }
    }, flag: 'يستخدم عنوان IP بدلاً من نطاق موثوق', weight: 20 },
    { test: (url) => /[^a-z0-9.-]/.test(new URL(url).hostname) || url.includes('@'), flag: 'بنية رابط مشبوهة أو حقن بيانات اعتماد', weight: 18 },
    { test: (url) => {
      try {
        const host = new URL(url).hostname;
        const brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram', 'whatsapp'];
        const tld = host.split('.').slice(-2).join('.');
        return brands.some((b) => host.includes(b) && !['paypal.com', 'amazon.com', 'apple.com', 'microsoft.com', 'google.com', 'facebook.com', 'instagram.com', 'whatsapp.com'].some(( legit) => host === legit || host.endsWith('.' + legit)));
      } catch { return false; }
    }, flag: 'احتمال typosquatting — النطاق يشبه علامة تجارية معروفة', weight: 25 },
    { test: (url) => !/^https:\/\//i.test(url), flag: 'لا يستخدم HTTPS — قد تُنقل البيانات بشكل غير آمن', weight: 12 },
    { test: (url) => (url.match(/\./g) || []).length > 3, flag: 'سلسلة نطاقات فرعية طويلة — احتمال إعادة توجيه للتصيد', weight: 14 },
  ];

  const alinmaPage = document.getElementById('alinma-page');
  const byteshieldPanel = document.getElementById('byteshield-panel');
  const openByteshield = document.getElementById('open-byteshield');
  const closeByteshield = document.getElementById('close-byteshield');
  const alinmaHeroTitle = document.getElementById('alinma-hero-title');
  const alinmaHeroDesc = document.getElementById('alinma-hero-desc');
  const byteshieldCardSublabel = document.getElementById('byteshield-card-sublabel');
  const bsHeaderModeBadge = document.getElementById('bs-header-mode-badge');

  const MAIN_HERO = {
    user: {
      title: 'الوصول السريع إلى الخدمات الأساسية',
      desc: 'وفر الوقت مع إمكانية الوصول الفوري إلى خدمات الإنماء الرئيسية',
      sublabel: 'فحص الاحتيال والتصيد',
    },
    soc: {
      title: 'مركز عمليات الأمن — SOC',
      desc: 'تحليل الحوادث، تقارير MITRE ATT&CK، مؤشرات الاختراق، وخطط الاحتواء — للمحللين الأمنيين.',
      sublabel: 'لوحة SOC — تقارير الحوادث',
    },
  };

  openByteshield.addEventListener('click', () => {
    alinmaPage.hidden = true;
    byteshieldPanel.hidden = false;
    document.body.style.overflow = 'hidden';
    byteshieldPanel.scrollTop = 0;
    updateResultsVisibility();
  });

  closeByteshield.addEventListener('click', () => {
    byteshieldPanel.hidden = true;
    alinmaPage.hidden = false;
    document.body.style.overflow = '';
  });

  document.querySelectorAll('.service-card:not(.service-card--byteshield)').forEach((card) => {
    card.addEventListener('click', (e) => {
      e.preventDefault();
      showToast('خدمة تجريبية — ByteShield متاح للفحص الأمني');
    });
  });

  let activeTab = 'text';
  let screenshotFile = null;

  const tabs = document.querySelectorAll('.tab');
  const panels = document.querySelectorAll('.tab-panel');
  const btnScan = document.getElementById('btn-scan');
  const btnSample = document.getElementById('btn-sample');
  const resultsUser = document.getElementById('results-user');
  const resultsSoc = document.getElementById('results-soc');
  const resultsPlaceholder = document.getElementById('results-placeholder');
  const resultsPlaceholderTitle = document.getElementById('results-placeholder-title');
  const resultsPlaceholderHint = document.getElementById('results-placeholder-hint');
  const uploadZone = document.getElementById('upload-zone');
  const uploadTrigger = document.getElementById('upload-trigger');
  const inputScreenshot = document.getElementById('input-screenshot');
  const uploadEmpty = document.getElementById('upload-empty');
  const uploadPreview = document.getElementById('upload-preview');
  const previewImg = document.getElementById('preview-img');
  const uploadFileInfo = document.getElementById('upload-file-info');
  const uploadFileName = document.getElementById('upload-file-name');
  const uploadRemove = document.getElementById('upload-remove');
  const btnAskAi = document.getElementById('btn-ask-ai');
  const btnContactSupport = document.getElementById('btn-contact-support');
  const modalBackdrop = document.getElementById('modal-backdrop');
  const chatModal = document.getElementById('chat-modal');
  const supportModal = document.getElementById('support-modal');
  const btnCloseChat = document.getElementById('btn-close-chat');
  const btnCloseSupport = document.getElementById('btn-close-support');
  const chatMessages = document.getElementById('chat-messages');
  const chatForm = document.getElementById('chat-form');
  const chatInput = document.getElementById('chat-input');
  const btnChatSend = document.getElementById('btn-chat-send');
  const supportContacts = document.getElementById('support-contacts');
  const modeTabs = document.querySelectorAll('.mode-tab');
  const bsIntroUser = document.getElementById('bs-intro-user');
  const bsIntroSoc = document.getElementById('bs-intro-soc');
  const byteshieldPanelEl = document.getElementById('byteshield-panel');
  const socReportEl = document.getElementById('soc-report');
  const socLoadingEl = document.getElementById('soc-loading');
  const socEmptyEl = document.getElementById('soc-empty');
  const recommendCard = document.getElementById('recommend-card');
  const socAnalyticsEl = document.getElementById('soc-analytics');

  modeTabs.forEach((tab) => {
    tab.addEventListener('click', () => switchMode(tab.dataset.mode));
  });

  function switchMode(mode) {
    activeMode = mode;

    modeTabs.forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle('mode-tab--active', active);
      tab.setAttribute('aria-selected', active);
    });

    if (bsIntroUser) bsIntroUser.hidden = mode !== 'user';
    if (bsIntroSoc) bsIntroSoc.hidden = mode !== 'soc';

    const hero = MAIN_HERO[mode] || MAIN_HERO.user;
    if (alinmaHeroTitle) alinmaHeroTitle.textContent = hero.title;
    if (alinmaHeroDesc) alinmaHeroDesc.textContent = hero.desc;
    if (byteshieldCardSublabel) byteshieldCardSublabel.textContent = hero.sublabel;
    if (alinmaPage) alinmaPage.classList.toggle('alinma-page--soc-mode', mode === 'soc');
    if (openByteshield) openByteshield.classList.toggle('service-card--byteshield-soc', mode === 'soc');
    if (bsHeaderModeBadge) {
      bsHeaderModeBadge.textContent = mode === 'soc' ? 'SOC' : 'شخصي';
      bsHeaderModeBadge.classList.toggle('bs-header__mode-badge--soc', mode === 'soc');
    }

    if (byteshieldPanelEl) {
      byteshieldPanelEl.classList.toggle('byteshield-panel--soc-mode', mode === 'soc');
    }

    if (recommendCard && lastUserReport) {
      recommendCard.hidden = mode !== 'user';
    }

    if (socAnalyticsEl) {
      socAnalyticsEl.hidden = mode !== 'soc';
      if (mode === 'soc') updateFinancialImpactDashboard();
    }

    if (mode === 'soc' && !lastSocReport && !socReportLoading) {
      if (socLoadingEl) socLoadingEl.hidden = true;
      if (socReportEl) { socReportEl.hidden = true; socReportEl.innerHTML = ''; }
      if (socEmptyEl) socEmptyEl.hidden = !!lastUserReport;
    }

    updateResultsVisibility();
  }

  async function updateFinancialImpactDashboard() {
    if (activeMode !== 'soc') return;

    const totalEl = document.getElementById('total-detected-incidents');
    const highEl = document.getElementById('high-risk-incidents');
    const savedEl = document.getElementById('total-saved-money');
    if (!totalEl || !highEl || !savedEl) return;

    try {
      const response = await fetch(getAnalyticsUrl());
      const result = await response.json();

      if (!response.ok || !result.success) return;

      const metrics = result.metrics;
      totalEl.textContent = String(metrics.totalIncidents ?? 0);
      highEl.textContent = String(metrics.highRiskCount ?? 0);
      savedEl.textContent = new Intl.NumberFormat('ar-SA', {
        style: 'currency',
        currency: 'SAR',
        maximumFractionDigits: 0,
      }).format(metrics.totalSavedMoneySAR ?? 0);
    } catch (err) {
      console.error('Failed to fetch financial impact data:', err);
    }
  }

  function formatSar(amount) {
    return new Intl.NumberFormat('ar-SA', {
      style: 'currency',
      currency: 'SAR',
      maximumFractionDigits: 0,
    }).format(amount ?? 0);
  }

  function renderFinancialForecast(forecast) {
    if (!forecast || activeMode !== 'soc') return;

    const lossEl = document.getElementById('forecast-predicted-loss');
    const levelEl = document.getElementById('forecast-risk-level');
    const detailEl = document.getElementById('soc-forecast-detail');
    const summaryEl = document.getElementById('forecast-summary-ar');
    const scoreEl = document.getElementById('forecast-risk-score');
    const probEl = document.getElementById('forecast-fraud-prob');
    const baselineEl = document.getElementById('forecast-baseline-loss');

    if (lossEl) lossEl.textContent = formatSar(forecast.predictedLossSAR);
    if (levelEl) levelEl.textContent = `مستوى التوقع: ${forecast.forecastLevel || '—'}`;
    if (summaryEl) summaryEl.textContent = forecast.forecastSummaryAr || '';
    if (scoreEl) scoreEl.textContent = String(forecast.financialRiskScore ?? '—');
    if (probEl) probEl.textContent = `${Math.round((forecast.fraudProbability || 0) * 100)}%`;
    if (baselineEl) baselineEl.textContent = formatSar(forecast.baselineLossSAR);
    if (detailEl) detailEl.hidden = false;
  }

  async function fetchFinancialForecast(text, contentType, report) {
    if (activeMode !== 'soc') return;

    try {
      const response = await fetch(getFinancialForecastUrl(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          contentType,
          riskScore: report.score,
          classification: report.tier?.statusEn || report.tier?.tierLabel,
          riskBreakdown: report.riskBreakdown,
        }),
      });

      const result = await response.json();
      if (!response.ok || !result.success) return;

      renderFinancialForecast(result.data);
    } catch (err) {
      console.error('Failed to fetch financial forecast:', err);
    }
  }

  function updateResultsVisibility() {
    const hasUser = !!lastUserReport;
    const hasSoc = !!lastSocReport;
    const socLoading = socReportLoading;

    if (activeMode === 'user') {
      if (resultsSoc) resultsSoc.hidden = true;
      if (hasUser) {
        if (resultsPlaceholder) resultsPlaceholder.hidden = true;
        if (resultsUser) resultsUser.hidden = false;
        if (recommendCard) recommendCard.hidden = false;
      } else {
        if (resultsPlaceholder) resultsPlaceholder.hidden = false;
        if (resultsUser) resultsUser.hidden = true;
        if (resultsPlaceholderTitle) resultsPlaceholderTitle.textContent = 'ستظهر النتائج هنا';
        if (resultsPlaceholderHint) {
          resultsPlaceholderHint.textContent = 'أرسل المحتوى للحصول على تقرير مبسّط: آمن أم احتيال؟';
        }
      }
    } else {
      if (resultsUser) resultsUser.hidden = true;
      if (recommendCard) recommendCard.hidden = true;
      if (hasSoc || socLoading) {
        if (resultsPlaceholder) resultsPlaceholder.hidden = true;
        if (resultsSoc) resultsSoc.hidden = false;
      } else if (hasUser) {
        if (resultsPlaceholder) resultsPlaceholder.hidden = true;
        if (resultsSoc) resultsSoc.hidden = false;
        if (socEmptyEl) socEmptyEl.hidden = false;
        if (socLoadingEl) socLoadingEl.hidden = true;
      } else {
        if (resultsPlaceholder) resultsPlaceholder.hidden = false;
        if (resultsSoc) resultsSoc.hidden = true;
        if (resultsPlaceholderTitle) resultsPlaceholderTitle.textContent = 'تقرير SOC';
        if (resultsPlaceholderHint) {
          resultsPlaceholderHint.textContent = 'شغّل التحليل لإنشاء تقرير حادث MITRE ATT&CK و IoC.';
        }
      }
    }
  }

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
    showToast('تم تحميل رسالة احتيال نموذجية — شغّل التحليل');
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
    const isImage = file.type.startsWith('image/');
    const isPdf = file.type === 'application/pdf';

    if (!isImage && !isPdf) {
      showToast('يرجى رفع صورة (JPG, PNG) أو ملف PDF');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      showToast('الملف كبير جداً — الحد الأقصى 10 MB');
      return;
    }

    screenshotFile = file;

    if (isImage) {
      previewImg.src = URL.createObjectURL(file);
      previewImg.hidden = false;
      if (uploadFileInfo) uploadFileInfo.hidden = true;
    } else {
      previewImg.src = '';
      previewImg.hidden = true;
      if (uploadFileName) uploadFileName.textContent = file.name;
      if (uploadFileInfo) uploadFileInfo.hidden = false;
    }

    uploadEmpty.hidden = true;
    uploadPreview.hidden = false;
  }

  function clearScreenshot() {
    screenshotFile = null;
    inputScreenshot.value = '';
    uploadEmpty.hidden = false;
    uploadPreview.hidden = true;
    previewImg.src = '';
    previewImg.hidden = false;
    if (uploadFileInfo) uploadFileInfo.hidden = true;
    if (uploadFileName) uploadFileName.textContent = '';
  }

  btnScan.addEventListener('click', runAnalysis);

  btnAskAi.addEventListener('click', openChatModal);
  document.getElementById('btn-quick-chat').addEventListener('click', openChatModal);
  btnContactSupport.addEventListener('click', openSupportModal);
  btnCloseChat.addEventListener('click', closeModals);
  btnCloseSupport.addEventListener('click', closeModals);
  modalBackdrop.addEventListener('click', closeModals);
  chatForm.addEventListener('submit', (e) => { e.preventDefault(); sendChatMessage(); });

  chatModal.addEventListener('click', (e) => e.stopPropagation());
  supportModal.addEventListener('click', (e) => e.stopPropagation());

  closeModals();

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
        return {
          type: 'Screenshot',
          text: screenshotFile ? `[ملف: ${screenshotFile.name}]` : '',
          hasImage: !!screenshotFile,
        };
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
      flags.push('رسالة قصيرة جداً بلغة ضاغطة');
      score += 10;
    }

    return { flags, score: Math.min(98, score) };
  }

  function analyzeUrl(url) {
    const flags = [];
    let score = 15;

    if (!url) {
      return { flags: ['لم يُقدَّم رابط'], score: 0, invalid: true };
    }

    try {
      new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      return { flags: ['رابط غير صالح أو مشوّه'], score: 85, invalid: false };
    }

    const fullUrl = url.startsWith('http') ? url : `https://${url}`;

    URL_PATTERNS.forEach(({ test, flag, weight }) => {
      if (test(fullUrl)) {
        flags.push(flag);
        score += weight;
      }
    });

    if (flags.length === 0) {
      flags.push('لم تُكتشف مؤشرات خطر واضحة — تحقق بشكل مستقل');
      score = 22;
    }

    return { flags, score: Math.min(98, score) };
  }

  function analyzeScreenshot() {
    const flags = [
      'تم رفع اللقطة — استخراج النص عبر OCR في الإنتاج',
      'وضع تجريبي: افتراض وجود طلب دفع في المحادثة',
      'لا يمكن التحقق من هوية المرسل من الصورة وحدها',
      'لغة استعجال شائعة في لقطات الاحتيال',
    ];
    return {
      flags,
      score: 72,
      explanation: 'في الإنتاج، يستخدم ByteShield ذكاءً بصرياً لقراءة اللقطة وتحديد منصة المراسلة واستخراج النص ومقارنته بأنماط الاحتيال المعروفة. هذا العرض التجريبي يحاكي نتيجة خطر متوسط إلى مرتفع.',
    };
  }

  function scoreToLevel(score) {
    const tier = getScoreTier(score);
    const verdicts = {
      low: 'يبدو آمناً نسبياً — تحقق دائماً بشكل مستقل',
      medium: 'مشبوه — توخَّ الحذر قبل أي إجراء',
      high: 'احتيال أو تصيد محتمل — لا تتفاعل',
    };
    return { level: tier.statusAr, class: tier.levelClass, verdict: verdicts[tier.levelClass] };
  }

  function getRecommendations(score, type) {
    const recs = [];
    if (score >= 61) {
      recs.push('لا تنقر على أي روابط ولا ترد على الرسالة');
      recs.push('لا تشارك كلمات المرور أو رموز OTP أو بيانات الدفع');
      recs.push('تواصل مع الجهة مباشرة عبر موقعها أو تطبيق الإنماء الرسمي');
      recs.push('أبلغ البنك أو الجهات المختصة بالجرائم الإلكترونية');
    } else if (score >= 31) {
      recs.push('تحقق من المرسل عبر قناة رسمية قبل أي إجراء');
      recs.push('افحص الرابط قبل النقر للتأكد من الوجهة الحقيقية');
      recs.push('ابحث عن تقارير مشابهة للاحتيال');
      recs.push('عند الشك، تجاهل الرسالة واتصل بالدعم الرسمي');
    } else {
      recs.push('المحتوى يبدو آمناً نسبياً وفق تحليل الأنماط');
      recs.push('تحقق من هوية المرسل إذا شعرت بأي شيء غريب');
      recs.push('لا تشارك الرموز أو البيانات الحساسة أبداً');
    }
    if (type === 'URL') {
      recs.unshift('اكتب عنوان الموقع الرسمي يدوياً بدلاً من النقر على الرابط');
    }
    if (type === 'Screenshot') {
      recs.unshift('اطلب من المرسل التحقق من هويته عبر وسيلة اتصال معروفة');
    }
    return recs;
  }

  function buildExplanation(text, flags, score, type) {
    const { level } = scoreToLevel(score);
    const typeAr = { Message: 'رسالة', Email: 'بريد', URL: 'رابط', Screenshot: 'لقطة' }[type] || type;
    const parts = [
      `حلل ByteShield هذا ${typeAr} وأعطى درجة خطر ${level} (${score}/100).`,
    ];
    if (flags.length > 0) {
      parts.push(`رصد ${flags.length} مؤشر${flags.length > 1 ? 'ات' : ''}، منها: ${flags[0]}.`);
    }
    if (score >= 61) {
      parts.push('عدة مؤشرات تطابق حملات احتيال مالي وتصيد معروفة. الجمع بين الاستعجال وطلب البيانات والروابط المشبوهة إشارة قوية على احتيال.');
    } else if (score >= 31) {
      parts.push('بعض الأنماط تشبه الهندسة الاجتماعية. الجهات الموثوقة نادراً ما تضغط عليك للتصرف فوراً عبر رسائل غير مطلوبة.');
    } else {
      parts.push('لم تُرصد أنماط تصيد رئيسية، لكن الهندسة الاجتماعية قد تكون خفية. ثق بحدسك إذا شعرت بأي شيء غريب.');
    }
    return parts.join(' ');
  }

  function buildLocalReport(text, contentType) {
    const analysis = contentType === 'URL' ? analyzeUrl(text) : analyzeText(text);
    const score = analysis.score;
    const tier = getScoreTier(score);
    const flags = analysis.flags || [];

    return {
      score,
      tier,
      statusMessage: tier.defaultMessage,
      shortExplanation: buildExplanation(text, flags, score, contentType),
      confidence: Math.min(98, Math.max(55, score + 10)),
      reasoning: flags.length ? flags : ['لم تُرصد مؤشرات خطر واضحة'],
      actionChecklist: getRecommendations(score, contentType),
      riskBreakdown: {
        senderAuthenticity: Math.round(score * 0.8),
        languageAnalysis: Math.round(score * 0.7),
        linkSafety: Math.round(score * 0.85),
        financialFraudIndicators: Math.round(score * 0.9),
        socialEngineeringIndicators: Math.round(score * 0.75),
        urgencyDetection: Math.round(score * 0.65),
      },
      detailedAnalysis: buildExplanation(text, flags, score, contentType),
      detectedBanks: [],
      bankAdvice: '',
      threatType: 'phishing',
      securityTips: getDefaultTips('phishing'),
      source: 'local',
      analysisNote: 'تحليل محلي (مفتاح OpenAI غير متاح) — للرسائل استخدم مفتاح API صالحاً للدقة الأعلى',
    };
  }

  function isOpenAiKeyError(message) {
    if (!message) return false;
    const lower = message.toLowerCase();
    return lower.includes('api key') || lower.includes('incorrect api') || lower.includes('401');
  }

  async function runAnalysis() {
    const input = getInputContent();

    if (activeTab === 'screenshot') {
      if (!input.hasImage) {
        showToast('يرجى رفع صورة أو ملف PDF أولاً');
        return;
      }
    } else if (!input.text) {
      showToast('يرجى إدخال محتوى للتحليل');
      return;
    }

    btnScan.classList.add('scanning');
    btnScan.textContent = activeTab === 'url'
      ? 'جاري تحليل الرابط… (قد يستغرق 30 ث)'
      : activeTab === 'screenshot'
        ? 'جاري تحليل الملف… (قد يستغرق دقيقة)'
        : 'جاري التحليل…';

    showSocLoading();

    try {
      if (activeTab === 'screenshot') {
        const formData = new FormData();
        formData.append('file', screenshotFile);

        let response;
        try {
          response = await fetch(getAnalyzeFileUrl(), {
            method: 'POST',
            body: formData,
          });
        } catch {
          showToast('تعذر الاتصال بالخادم — افتح http://localhost:3000');
          return;
        }

        let result;
        try {
          result = await response.json();
        } catch {
          showToast('تعذر قراءة رد الخادم');
          return;
        }

        if (!response.ok || !result.success) {
          const message = result.error || 'فشل تحليل الملف';
          if (message.includes('429') || message.toLowerCase().includes('quota')) {
            showToast('تم تجاوز حد OpenAI — انتظر دقيقة وحاول مجدداً');
          } else if (isOpenAiKeyError(message)) {
            showToast('مفتاح OpenAI غير صالح — حدّث backend/.env');
          } else {
            showToast(message);
          }
          return;
        }

        const ai = result.data;
        const score = Number(ai.riskScore) || 0;
        const report = normalizeAiReport(ai, score, input.text);
        finalizeAnalysis(input.text, input.type, report);
        return;
      }

      const endpoint = activeTab === 'url' ? getPredictUrlEndpoint() : getAnalyzeUrl();
      const payload = activeTab === 'url' ? { url: input.text } : { text: input.text };

      let response;
      try {
        response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch {
        const report = buildLocalReport(input.text, input.type);
        finalizeAnalysis(input.text, input.type, report);
        showToast('تعذر الاتصال بالخادم — تم استخدام التحليل المحلي');
        return;
      }

      let result;
      try {
        result = await response.json();
      } catch {
        if (activeTab !== 'url') {
          const report = buildLocalReport(input.text, input.type);
          finalizeAnalysis(input.text, input.type, report);
          showToast('تعذر قراءة رد الخادم — تم استخدام التحليل المحلي');
          return;
        }
        showToast('تعذر الاتصال بالخادم — افتح http://localhost:3000');
        return;
      }

      if (!response.ok || !result.success) {
        const message = result.error || 'فشل التحليل — تأكد من تشغيل الخادم';

        if (activeTab !== 'url' || isOpenAiKeyError(message)) {
          const report = buildLocalReport(input.text, input.type);
          finalizeAnalysis(input.text, input.type, report);
          if (isOpenAiKeyError(message)) {
            showToast('مفتاح OpenAI غير صالح — تم استخدام التحليل المحلي. حدّث backend/.env');
          } else {
            showToast('فشل التحليل السحابي — تم استخدام التحليل المحلي');
          }
          return;
        }

        if (message.includes('429') || message.toLowerCase().includes('quota') || message.toLowerCase().includes('rate limit')) {
          showToast('تم تجاوز حد OpenAI — انتظر دقيقة وحاول مجدداً');
        } else if (activeTab === 'url') {
          const report = buildLocalReport(input.text, input.type);
          finalizeAnalysis(input.text, input.type, report);
          showToast('تعذر تشغيل نموذج التعلم العميق — تم استخدام التحليل المحلي');
        } else {
          showToast(message);
        }
        return;
      }

      const ai = result.data;
      const score = Number(ai.riskScore) || 0;
      const report = normalizeAiReport(ai, score, input.text);
      finalizeAnalysis(input.text, input.type, report);
    } catch (error) {
      console.error(error);
      showToast('تعذر الاتصال بالخادم — افتح http://localhost:3000 وشغّل الباكند من مجلد backend');
    } finally {
      btnScan.classList.remove('scanning');
      btnScan.textContent = 'بدء التحليل الأمني';
    }
  }

  function normalizeAiReport(ai, score, text) {
    const tier = getScoreTier(score);
    const reasoning = Array.isArray(ai.reasoning) ? ai.reasoning
      : Array.isArray(ai.reasons) ? ai.reasons : [];
    const breakdown = ai.riskBreakdown || {};
    return {
      score,
      tier,
      statusMessage: ai.statusMessage || tier.defaultMessage,
      shortExplanation: ai.shortExplanation || buildExplanation(text, reasoning, score, 'Message'),
      confidence: Number(ai.confidence) || Math.min(98, Math.max(55, score + 10)),
      reasoning,
      actionChecklist: Array.isArray(ai.actionChecklist) && ai.actionChecklist.length
        ? ai.actionChecklist : getDefaultActions(score),
      riskBreakdown: {
        senderAuthenticity: breakdown.senderAuthenticity ?? Math.round(score * 0.8),
        languageAnalysis: breakdown.languageAnalysis ?? Math.round(score * 0.7),
        linkSafety: breakdown.linkSafety ?? Math.round(score * 0.85),
        financialFraudIndicators: breakdown.financialFraudIndicators ?? Math.round(score * 0.9),
        socialEngineeringIndicators: breakdown.socialEngineeringIndicators ?? Math.round(score * 0.75),
        urgencyDetection: breakdown.urgencyDetection ?? Math.round(score * 0.65),
      },
      detailedAnalysis: ai.detailedAnalysis || ai.shortExplanation || '',
      detectedBanks: Array.isArray(ai.detectedBanks) ? ai.detectedBanks : [],
      bankAdvice: ai.bankAdvice || '',
      threatType: ai.threatType || 'phishing',
      securityTips: Array.isArray(ai.securityTips) && ai.securityTips.length
        ? ai.securityTips : getDefaultTips(ai.threatType || 'phishing'),
    };
  }

  function buildScreenshotReport(analysis, text) {
    const score = analysis.score;
    const tier = getScoreTier(score);
    return {
      score,
      tier,
      statusMessage: tier.defaultMessage,
      shortExplanation: analysis.explanation || buildExplanation(text, analysis.flags, score, 'Screenshot'),
      confidence: 72,
      reasoning: analysis.flags,
      actionChecklist: getDefaultActions(score),
      riskBreakdown: {
        senderAuthenticity: 70,
        languageAnalysis: 65,
        linkSafety: 50,
        financialFraudIndicators: 75,
        socialEngineeringIndicators: 80,
        urgencyDetection: 72,
      },
      detailedAnalysis: analysis.explanation || '',
      detectedBanks: [],
      bankAdvice: '',
      threatType: 'social_engineering',
      securityTips: getDefaultTips('social_engineering'),
    };
  }

  function buildChatContext(text, report) {
    return [
      `الرسالة: ${text}`,
      `درجة الخطر: ${report.score}/100`,
      `الحالة: ${report.tier.statusAr}`,
      `الشرح: ${report.shortExplanation}`,
      `الأسباب: ${report.reasoning.join('؛ ')}`,
      `التوصيات: ${report.actionChecklist.join('؛ ')}`,
    ].join('\n');
  }

  function showSocLoading() {
    socReportLoading = true;
    if (socLoadingEl) socLoadingEl.hidden = false;
    if (socReportEl) { socReportEl.hidden = true; socReportEl.innerHTML = ''; }
    if (socEmptyEl) socEmptyEl.hidden = true;
    if (resultsSoc) resultsSoc.hidden = activeMode !== 'soc';
    updateResultsVisibility();
  }

  function buildLocalSocReport(text, report) {
    const score = report.score || 50;
    const severity = score >= 75 ? 'Critical' : score >= 61 ? 'High' : score >= 31 ? 'Medium' : 'Low';
    const urls = text.match(/https?:\/\/[^\s<>"']+/gi) || [];
    const emails = text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/gi) || [];

    return {
      reportId: `BS-IR-LOCAL-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      reportVersion: '1.0',
      frameworks: ['NIST SP 800-61', 'MITRE ATT&CK'],
      incident: {
        title: 'Suspected phishing / fraud incident (local triage)',
        executiveSummary: report.shortExplanation || 'Local pattern-based triage without OpenAI SOC engine.',
        executiveSummaryAr: report.shortExplanation || 'تحليل محلي — فعّل OpenAI لإنشاء تقرير SOC كامل.',
        severity,
        status: score >= 61 ? 'Open' : 'Triaging',
        classification: report.threatType || 'Phishing',
        confidence: report.confidence || 60,
        riskScore: score,
        attackVector: 'Social engineering via unsolicited message',
        impactAssessment: score >= 61 ? 'Potential credential theft or financial fraud' : 'Limited observed impact',
        affectedAssets: ['User messaging channel', 'Potential credentials'],
        timeline: [{ phase: 'Delivery', timestamp: formatSaudiDateTime(), description: 'Suspicious content submitted for analysis' }],
      },
      mitreAttack: {
        tactics: score >= 61 ? ['Initial Access', 'Credential Access'] : ['Initial Access'],
        techniques: score >= 61
          ? [{ id: 'T1566.002', name: 'Phishing: Spearphishing Link', tactic: 'Initial Access', description: 'Suspicious link or credential request detected', confidence: 'Medium' }]
          : [{ id: 'T1566', name: 'Phishing', tactic: 'Initial Access', description: 'Generic phishing indicators', confidence: 'Low' }],
        killChainPhase: 'Delivery',
      },
      indicatorsOfCompromise: {
        urls: urls.map((u) => ({ value: u, severity: 'high', context: 'Extracted from evidence' })),
        domains: [],
        ipAddresses: [],
        emailAddresses: emails.map((e) => ({ value: e, severity: 'medium', context: 'Sender or contact in evidence' })),
        phoneNumbers: [],
        fileHashes: [],
        other: [],
      },
      containmentPlaybook: {
        priority: score >= 61 ? 'P1' : 'P2',
        immediateActions: (report.actionChecklist || []).slice(0, 4).map((action, i) => ({
          step: i + 1,
          action,
          owner: 'SOC Analyst',
          estimatedTime: '15 min',
        })),
        shortTermActions: [{ step: 1, action: 'Block IoCs at email/web proxy', owner: 'Network Team', estimatedTime: '1 hr' }],
        longTermActions: [{ step: 1, action: 'User awareness notification if campaign-wide', owner: 'IR Lead', estimatedTime: '1 day' }],
        escalationCriteria: score >= 61 ? ['Confirmed credential compromise', 'Multiple user reports'] : ['Risk score exceeds threshold'],
        communicationPlan: 'Notify security lead; preserve evidence for IR ticket.',
      },
      detectionAndResponse: {
        detectionRules: [{ name: 'Phishing keyword + URL', logic: 'Match urgency/OTP keywords with external URL', dataSource: 'Email Gateway' }],
        recommendedTools: ['SIEM', 'Email sandbox', 'Web proxy blocklist'],
        huntingQueries: ['Search proxy logs for submitted URLs/domains'],
      },
      references: ['MITRE ATT&CK T1566', 'NIST SP 800-61'],
      analystNotes: 'Generated by local fallback — connect OpenAI for full enterprise SOC report.',
      source: 'local',
    };
  }

  async function fetchAndRenderSocReport(text, contentType, report) {
    showSocLoading();
    lastEvidenceText = text;
    lastContentType = contentType;

    const triage = {
      riskScore: report.score,
      classification: report.tier?.statusEn || report.tier?.tierLabel,
      threatType: report.threatType,
      reasoning: report.reasoning,
    };

    try {
      const response = await fetch(getSocReportUrl(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, contentType, triage }),
      });

      let result;
      try { result = await response.json(); } catch {
        lastSocReport = buildLocalSocReport(text, report);
        renderSocReport(lastSocReport);
        return;
      }

      if (!response.ok || !result.success) {
        lastSocReport = buildLocalSocReport(text, report);
        renderSocReport(lastSocReport);
        return;
      }

      lastSocReport = result.data;
      renderSocReport(lastSocReport);
    } catch {
      lastSocReport = buildLocalSocReport(text, report);
      renderSocReport(lastSocReport);
    }
  }

  function socSeverityClass(severity) {
    const s = String(severity || '').toLowerCase();
    if (s.includes('crit')) return 'critical';
    if (s.includes('high')) return 'high';
    if (s.includes('med')) return 'medium';
    if (s.includes('info')) return 'info';
    return 'low';
  }

  function renderIocTable(title, items) {
    if (!items || !items.length) return '';
    return `
      <div class="soc-section">
        <h4 class="soc-section__title">${escapeHtml(title)}</h4>
        <div class="soc-ioc-table-wrap">
          <table class="soc-ioc-table">
            <thead><tr><th>Indicator</th><th>Severity</th><th>Context</th></tr></thead>
            <tbody>
              ${items.map((item) => `
                <tr>
                  <td class="soc-ioc-table__value" dir="ltr">${escapeHtml(item.value || item)}</td>
                  <td><span class="soc-sev soc-sev--${socSeverityClass(item.severity || 'medium')}">${escapeHtml(item.severity || 'medium')}</span></td>
                  <td>${escapeHtml(item.context || '—')}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  }

  function renderPlaybookSteps(title, steps) {
    if (!steps || !steps.length) return '';
    return `
      <div class="soc-section">
        <h4 class="soc-section__title">${escapeHtml(title)}</h4>
        <ol class="soc-playbook">
          ${steps.map((step) => `
            <li class="soc-playbook__step">
              <div class="soc-playbook__head">
                <span class="soc-playbook__num">${step.step || '•'}</span>
                <strong>${escapeHtml(step.action || step)}</strong>
              </div>
              ${step.owner ? `<span class="soc-playbook__meta">Owner: ${escapeHtml(step.owner)} · ETA: ${escapeHtml(step.estimatedTime || 'N/A')}</span>` : ''}
            </li>`).join('')}
        </ol>
      </div>`;
  }

  function renderSocReport(soc) {
    if (!socReportEl) return;

    socReportLoading = false;
    if (socLoadingEl) socLoadingEl.hidden = true;
    if (socEmptyEl) socEmptyEl.hidden = true;
    socReportEl.hidden = false;
    updateResultsVisibility();

    const inc = soc.incident || {};
    const mitre = soc.mitreAttack || {};
    const ioc = soc.indicatorsOfCompromise || {};
    const playbook = soc.containmentPlaybook || {};
    const detection = soc.detectionAndResponse || {};
    const sevClass = socSeverityClass(inc.severity);

    socReportEl.innerHTML = `
      <header class="soc-header">
        <div class="soc-header__meta">
          <span class="soc-report-id" dir="ltr">${escapeHtml(soc.reportId || 'BS-IR-UNKNOWN')}</span>
          <span class="soc-report-time">${escapeHtml(soc.generatedAt ? formatSaudiDateTime(new Date(soc.generatedAt)) : formatSaudiDateTime())}</span>
        </div>
        <h3 class="soc-header__title">${escapeHtml(inc.title || 'Security Incident Report')}</h3>
        <div class="soc-header__badges">
          <span class="soc-sev soc-sev--${sevClass} soc-sev--lg">${escapeHtml(inc.severity || 'Unknown')}</span>
          <span class="soc-badge soc-badge--status">${escapeHtml(inc.status || 'Open')}</span>
          <span class="soc-badge">${escapeHtml(inc.classification || 'Unclassified')}</span>
          <span class="soc-badge soc-badge--priority">${escapeHtml(playbook.priority || 'P2')}</span>
        </div>
      </header>

      ${inc.executiveSummaryAr ? `<p class="soc-summary-ar">${escapeHtml(inc.executiveSummaryAr)}</p>` : ''}
      <p class="soc-summary">${escapeHtml(inc.executiveSummary || inc.summary || '')}</p>

      <div class="soc-metrics">
        <div class="soc-metric"><span>Risk Score</span><strong>${escapeHtml(String(inc.riskScore ?? '—'))}/100</strong></div>
        <div class="soc-metric"><span>Confidence</span><strong>${escapeHtml(String(inc.confidence ?? '—'))}%</strong></div>
        <div class="soc-metric"><span>Attack Vector</span><strong>${escapeHtml(inc.attackVector || '—')}</strong></div>
        <div class="soc-metric"><span>Kill Chain</span><strong>${escapeHtml(mitre.killChainPhase || '—')}</strong></div>
      </div>

      <div class="soc-section">
        <h4 class="soc-section__title">Impact Assessment</h4>
        <p class="soc-text">${escapeHtml(inc.impactAssessment || '—')}</p>
        ${inc.affectedAssets?.length ? `<ul class="soc-tags">${inc.affectedAssets.map((a) => `<li>${escapeHtml(a)}</li>`).join('')}</ul>` : ''}
      </div>

      <div class="soc-section">
        <h4 class="soc-section__title">MITRE ATT&CK Mapping</h4>
        <div class="soc-mitre-tactics">
          ${(mitre.tactics || []).map((t) => `<span class="soc-mitre-tactic">${escapeHtml(t)}</span>`).join('') || '<span class="soc-muted">No tactics mapped</span>'}
        </div>
        <div class="soc-mitre-techniques">
          ${(mitre.techniques || []).map((tech) => `
            <div class="soc-mitre-card">
              <div class="soc-mitre-card__id" dir="ltr">${escapeHtml(tech.id || 'T????')}</div>
              <div class="soc-mitre-card__body">
                <strong>${escapeHtml(tech.name || '')}</strong>
                <span class="soc-mitre-card__tactic">${escapeHtml(tech.tactic || '')}</span>
                <p>${escapeHtml(tech.description || '')}</p>
                <span class="soc-mitre-card__conf">Confidence: ${escapeHtml(tech.confidence || 'Medium')}</span>
              </div>
            </div>`).join('') || '<p class="soc-muted">No techniques mapped</p>'}
        </div>
      </div>

      ${renderIocTable('URLs', ioc.urls)}
      ${renderIocTable('Domains', ioc.domains)}
      ${renderIocTable('IP Addresses', ioc.ipAddresses)}
      ${renderIocTable('Email Addresses', ioc.emailAddresses)}
      ${renderIocTable('Phone Numbers', ioc.phoneNumbers)}

      ${renderPlaybookSteps('Immediate Containment', playbook.immediateActions)}
      ${renderPlaybookSteps('Short-Term Actions', playbook.shortTermActions)}
      ${renderPlaybookSteps('Long-Term Actions', playbook.longTermActions)}

      ${playbook.escalationCriteria?.length ? `
        <div class="soc-section">
          <h4 class="soc-section__title">Escalation Criteria</h4>
          <ul class="soc-list">${playbook.escalationCriteria.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul>
        </div>` : ''}

      ${playbook.communicationPlan ? `
        <div class="soc-section">
          <h4 class="soc-section__title">Communication Plan</h4>
          <p class="soc-text">${escapeHtml(playbook.communicationPlan)}</p>
        </div>` : ''}

      ${detection.detectionRules?.length ? `
        <div class="soc-section">
          <h4 class="soc-section__title">Detection Rules</h4>
          ${detection.detectionRules.map((rule) => `
            <div class="soc-detection-card">
              <strong>${escapeHtml(rule.name || 'Rule')}</strong>
              <code dir="ltr">${escapeHtml(rule.logic || '')}</code>
              <span class="soc-detection-card__src">Source: ${escapeHtml(rule.dataSource || 'SIEM')}</span>
            </div>`).join('')}
        </div>` : ''}

      ${soc.analystNotes ? `
        <div class="soc-section soc-section--notes">
          <h4 class="soc-section__title">Analyst Notes</h4>
          <p class="soc-text">${escapeHtml(soc.analystNotes)}</p>
        </div>` : ''}

      ${soc.source === 'local' ? '<p class="soc-fallback-note">⚠ Local fallback report — configure OpenAI for full enterprise SOC output.</p>' : ''}
    `;

    updateResultsVisibility();
  }

  function finalizeAnalysis(text, contentType, report) {
    lastUserReport = report;
    lastAnalysisContext = buildChatContext(text, report);
    renderResults(report);
    fetchAndRenderSocReport(text, contentType, report);
    updateFinancialImpactDashboard();
    fetchFinancialForecast(text, contentType, report);
    updateResultsVisibility();
  }

  function renderResults(report) {
    const { score, tier, shortExplanation, confidence, reasoning,
      actionChecklist, riskBreakdown, detailedAnalysis, detectedBanks, bankAdvice, securityTips } = report;

    resultsPlaceholder.hidden = true;
    if (resultsUser) resultsUser.hidden = activeMode !== 'user';

    if (recommendCard) recommendCard.hidden = activeMode !== 'user';

    document.getElementById('results-time').textContent = formatSaudiDateTime();
    document.getElementById('risk-score').textContent = score;

    const ring = document.getElementById('risk-ring');
    const hero = document.getElementById('score-hero');
    ring.setAttribute('class', `risk-gauge__fill risk-gauge__fill--${tier.levelClass}`);
    ring.style.stroke = GAUGE_COLORS[tier.levelClass];
    ring.style.strokeDasharray = String(RING_MAX);
    ring.style.strokeDashoffset = String(RING_MAX);
    hero.className = `score-hero score-hero--${tier.levelClass}`;

    requestAnimationFrame(() => {
      setTimeout(() => { ring.style.strokeDashoffset = String(RING_MAX - score); }, 80);
    });

    document.getElementById('risk-tier-label').textContent = tier.tierLabel;
    document.getElementById('results-status-desc').textContent = report.analysisNote
      ? `${report.analysisNote}\n\n${shortExplanation}`
      : shortExplanation;

    const recSummary = score <= 30 ? 'لا يلزم إجراء فوري' : score <= 60 ? 'توخَّ الحذر وتحقق' : 'إجراءات عاجلة مطلوبة';
    document.getElementById('stat-rec-text').textContent = recSummary;

    const indicatorCount = reasoning.length;
    const warnText = indicatorCount === 0
      ? 'لم تُرصد مؤشرات واضحة'
      : indicatorCount <= 2
        ? 'مؤشرات منخفضة'
        : indicatorCount <= 4
          ? 'مؤشرات متوسطة'
          : 'مؤشرات مرتفعة';
    document.getElementById('stat-warn-text').textContent = `${indicatorCount} — ${warnText}`;

    document.getElementById('recommend-summary').textContent = shortExplanation;
    document.getElementById('recommend-checklist').innerHTML = actionChecklist
      .map((a) => `<li>${escapeHtml(a)}</li>`).join('');

    document.getElementById('eval-bars').innerHTML = EVAL_METRICS.map(({ key, label }) => {
      const riskVal = riskBreakdown[key] ?? score;
      const safetyVal = 100 - riskVal;
      const barClass = safetyVal >= 70 ? 'safe' : safetyVal >= 40 ? 'warn' : 'danger';
      return `<div class="eval-bar">
        <div class="eval-bar__head"><span>${escapeHtml(label)}</span><span>${safetyVal}/100</span></div>
        <div class="eval-bar__track">
          <div class="eval-bar__fill eval-bar__fill--${barClass}" data-width="${safetyVal}" style="width:0"></div>
        </div>
      </div>`;
    }).join('');

    requestAnimationFrame(() => {
      setTimeout(() => {
        document.querySelectorAll('.eval-bar__fill').forEach((el) => {
          el.style.width = `${el.dataset.width}%`;
        });
      }, 250);
    });

    document.getElementById('detailed-analysis').textContent = detailedAnalysis;
    document.getElementById('reason-list').innerHTML = reasoning.length
      ? reasoning.map((r) => `<li>${escapeHtml(r)}</li>`).join('')
      : '<li>لم تُرصد مؤشرات تصيد واضحة</li>';

    updateBankFooter(detectedBanks, bankAdvice, securityTips);

    document.querySelector('.dashboard__results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function updateBankFooter(detectedBanks, bankAdvice, securityTips) {
    const title = document.getElementById('bank-footer-title');
    const tipsList = document.getElementById('bank-footer-tips');

    if (detectedBanks && detectedBanks.length) {
      title.textContent = `إرشادات ${detectedBanks[0]}`;
      const tips = securityTips && securityTips.length ? securityTips : [
        'لا تشارك بياناتك البنكية عبر الرسائل',
        'تحقق من عنوان الموقع الرسمي',
        'لا تُدخل رمز OTP لأي جهة تطلبه عبر SMS',
        'استخدم التطبيق الرسمي فقط',
      ];
      if (bankAdvice) {
        tips.unshift(bankAdvice);
      }
      tipsList.innerHTML = tips.slice(0, 5).map((t) => `<li><span>🛡️</span>${escapeHtml(t)}</li>`).join('');
    } else {
      title.textContent = 'إرشادات البنوك';
      tipsList.innerHTML = `
        <li><span>🛡️</span>لا تشارك بياناتك البنكية عبر الرسائل</li>
        <li><span>🛡️</span>تحقق من عنوان الموقع الرسمي</li>
        <li><span>🛡️</span>لا تُدخل رمز OTP لأي جهة تطلبه عبر SMS</li>
        <li><span>🛡️</span>استخدم التطبيق الرسمي فقط</li>`;
    }
  }

  function renderSupportContacts() {
    supportContacts.innerHTML = SUPPORT_CONTACTS.map((section) => `
      <div class="support-section-title">${escapeHtml(section.section)}</div>
      ${section.items.map((item) => {
        let linkHtml = '';
        if (item.tel) {
          linkHtml = `<a href="tel:${item.tel}">${escapeHtml(item.number)}</a>`;
        } else if (item.mailto) {
          linkHtml = `<a href="mailto:${item.mailto}">${escapeHtml(item.number)}</a>`;
        } else if (item.link) {
          linkHtml = `<a href="${item.link}" target="_blank" rel="noopener">${escapeHtml(item.number)}</a>`;
        } else {
          linkHtml = escapeHtml(item.number);
        }
        return `<div class="support-contact"><strong>${escapeHtml(item.name)}</strong>${linkHtml}<span>${escapeHtml(item.desc)}</span></div>`;
      }).join('')}
    `).join('');
  }

  function openChatModal() {
    supportModal.hidden = true;
    chatHistory = [];
    chatMessages.innerHTML = '';
    appendChatMessage('bot', 'مرحباً! أنا ByteShield AI. لديّ نتيجة تحليلك — اسألني أي شيء: لماذا مشبوهة؟ هل أُبلّغ؟ ماذا لو نقرت الرابط؟');
    modalBackdrop.hidden = false;
    chatModal.hidden = false;
    document.body.style.overflow = 'hidden';
    chatInput.focus();
  }

  function openSupportModal() {
    chatModal.hidden = true;
    renderSupportContacts();
    modalBackdrop.hidden = false;
    supportModal.hidden = false;
    document.body.style.overflow = 'hidden';
  }

  function closeModals() {
    modalBackdrop.hidden = true;
    chatModal.hidden = true;
    supportModal.hidden = true;
    chatHistory = [];
    if (!byteshieldPanel.hidden) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modalBackdrop.hidden) {
      closeModals();
    }
  });

  function appendChatMessage(role, text) {
    const el = document.createElement('div');
    el.className = `chat-msg chat-msg--${role}`;
    el.textContent = text;
    chatMessages.appendChild(el);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return el;
  }

  async function sendChatMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    chatInput.value = '';
    appendChatMessage('user', text);
    chatHistory.push({ role: 'user', content: text });
    btnChatSend.disabled = true;

    const typing = appendChatMessage('bot', 'جاري الكتابة…');
    typing.classList.add('chat-msg--typing');

    try {
      const response = await fetch(getApiUrl('/chat'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: chatHistory, context: lastAnalysisContext }),
      });

      let result;
      try { result = await response.json(); } catch {
        typing.remove();
        showToast('تعذر الاتصال بالمساعد');
        return;
      }

      typing.remove();

      if (!response.ok || !result.success) {
        showToast(result.error || 'فشل الإرسال');
        chatHistory.pop();
        return;
      }

      chatHistory.push({ role: 'assistant', content: result.reply });
      appendChatMessage('bot', result.reply);
    } catch (err) {
      typing.remove();
      console.error(err);
      showToast('تعذر الاتصال بالمساعد');
      chatHistory.pop();
    } finally {
      btnChatSend.disabled = false;
      chatInput.focus();
    }
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