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

  const RECOMMEND_CONTEXT = {
    low: 'المحتوى يبدو آمناً نسبياً — اتبع الخطوات أدناه للتأكد قبل التفاعل.',
    medium: 'توجد علامات مشبوهة — راجع التوصيات قبل الرد أو النقر على أي رابط.',
    high: 'خطر مرتفع — لا تشارك بياناتك واتبع الإجراءات الموصى بها فوراً.',
  };

  const STAT_REC_CONTEXT = {
    low: 'لا يلزم إجراء عاجل — راقب حسابك كالمعتاد.',
    medium: 'خذ وقتاً للتحقق قبل أي إجراء أو مشاركة معلومات.',
    high: 'اتخذ الإجراءات الموصى بها فوراً وأبلغ البنك إن لزم.',
  };

  function scoreTierKey(score) {
    const s = Number(score) || 0;
    if (s <= 30) return 'low';
    if (s <= 60) return 'medium';
    return 'high';
  }

  function getWarnSummary(count) {
    if (count === 0) return 'لم تُرصد مؤشرات واضحة';
    if (count <= 2) return 'مؤشرات قليلة';
    if (count <= 4) return 'مؤشرات متوسطة';
    return 'مؤشرات عالية';
  }

  function getWarnContext(count) {
    if (count === 0) return 'لم يُعثر على أنماط مشبوهة واضحة في النص أو الروابط.';
    if (count <= 2) return `${count} علامة — قد تكون تحذيرات بسيطة أو صياغة غير اعتيادية.`;
    if (count <= 4) return `${count} علامات — عدة مؤشرات تستدعي الحذر والتحقق.`;
    return `${count} علامات — تركيبة قوية من مؤشرات الاحتيال الشائعة.`;
  }

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

  function formatSocDateTime(date = new Date()) {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: SAUDI_TZ,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(date);
  }

  function containsArabic(text) {
    return /[\u0600-\u06FF]/.test(String(text || ''));
  }

  function englishOnlyText(text, fallback = '') {
    const value = String(text || '').trim();
    if (!value || containsArabic(value)) return fallback;
    return value;
  }

  function englishOnlyList(items, fallbacks = []) {
    const cleaned = (items || [])
      .map((item) => englishOnlyText(item))
      .filter(Boolean);
    return cleaned.length ? cleaned : fallbacks;
  }

  const FRAUD_QUEUE_KEY = 'byteshield_fraud_ops_queue'; // legacy key (unused — cases are server-backed)

  let lastAnalysisContext = '';
  let lastSocReport = null;
  let lastUserReport = null;
  let socReportLoading = false;
  let lastEvidenceText = '';
  let lastContentType = 'Message';
  let activeMode = 'user';
  let chatHistory = [];
  let caseNotesMode = 'draft'; // draft | editing | accepted
  let caseNotesAcceptedHtml = '';
  let fraudFilter = 'all';
  let selectedFraudCaseId = null;

  const CASE_NOTE_SECTIONS = [
    'Time of activity:',
    'List of Affected Entities:',
    'Reason for Classification:',
    'Reason for Escalating the Alert:',
    'Recommended Remediation Actions:',
    'List of Attack Indicators:',
  ];

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
    fraud: {
      title: 'Fraud Operations Center',
      desc: 'Triage customer-reported fraud cases and manage the investigation queue.',
      sublabel: 'Fraud Operations \u2014 case queue',
    },
  };

  openByteshield.addEventListener('click', () => {
    alinmaPage.hidden = true;
    byteshieldPanel.hidden = false;
    document.body.style.overflow = 'hidden';
    byteshieldPanel.scrollTop = 0;
    updateResultsVisibility();
    if (activeMode === 'fraud') {
      if (fraudOpsAuthenticated) enterFraudOpsDashboard();
      else showFraudLogin();
    } else {
      hideFraudLogin();
    }
  });

  closeByteshield.addEventListener('click', () => {
    byteshieldPanel.hidden = true;
    alinmaPage.hidden = false;
    document.body.style.overflow = '';
  });

  const navDrawerBackdrop = document.getElementById('nav-drawer-backdrop');
  const navDrawer = document.getElementById('nav-drawer');
  const navDrawerClose = document.getElementById('nav-drawer-close');
  const btnAlinmaMenu = document.getElementById('btn-alinma-menu');
  const btnBsMenu = document.getElementById('bs-menu');
  const menuToggleButtons = [btnAlinmaMenu, btnBsMenu].filter(Boolean);

  function syncBodyOverflow() {
    if (!byteshieldPanel.hidden || (modalBackdrop && !modalBackdrop.hidden)) {
      document.body.style.overflow = 'hidden';
    } else if (!navDrawerBackdrop || navDrawerBackdrop.hidden) {
      document.body.style.overflow = '';
    }
  }

  function updateNavDrawerActiveState() {
    document.querySelectorAll('.nav-drawer__item[data-nav="byteshield"]').forEach((btn) => {
      const active = !byteshieldPanel.hidden && activeMode === btn.dataset.mode;
      btn.classList.toggle('nav-drawer__item--active', active);
      btn.setAttribute('aria-current', active ? 'page' : 'false');
    });
    const landingBtn = document.querySelector('.nav-drawer__item[data-nav="landing"]');
    if (landingBtn) {
      const onLanding = alinmaPage && !alinmaPage.hidden && byteshieldPanel.hidden;
      landingBtn.classList.toggle('nav-drawer__item--active', onLanding);
      landingBtn.setAttribute('aria-current', onLanding ? 'page' : 'false');
    }
  }

  function setMenuExpanded(open) {
    menuToggleButtons.forEach((btn) => btn.setAttribute('aria-expanded', open ? 'true' : 'false'));
  }

  function openNavDrawer() {
    if (!navDrawerBackdrop) return;
    updateNavDrawerActiveState();
    navDrawerBackdrop.hidden = false;
    setMenuExpanded(true);
    document.body.style.overflow = 'hidden';
    navDrawerClose?.focus();
  }

  function closeNavDrawer() {
    if (!navDrawerBackdrop || navDrawerBackdrop.hidden) return;
    navDrawerBackdrop.hidden = true;
    setMenuExpanded(false);
    syncBodyOverflow();
  }

  function showBankLanding() {
    byteshieldPanel.hidden = true;
    alinmaPage.hidden = false;
    closeNavDrawer();
    document.body.style.overflow = '';
  }

  function showByteShieldPanel(mode) {
    alinmaPage.hidden = true;
    byteshieldPanel.hidden = false;
    document.body.style.overflow = 'hidden';
    byteshieldPanel.scrollTop = 0;
    switchMode(mode || activeMode);
    closeNavDrawer();
    updateResultsVisibility();
  }

  menuToggleButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      if (navDrawerBackdrop && !navDrawerBackdrop.hidden) closeNavDrawer();
      else openNavDrawer();
    });
  });

  navDrawerClose?.addEventListener('click', closeNavDrawer);
  navDrawerBackdrop?.addEventListener('click', (e) => {
    if (e.target === navDrawerBackdrop) closeNavDrawer();
  });

  navDrawer?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-nav]');
    if (!btn) return;
    const nav = btn.dataset.nav;
    if (nav === 'landing') {
      showBankLanding();
    } else if (nav === 'byteshield') {
      showByteShieldPanel(btn.dataset.mode || 'user');
    } else if (nav === 'service') {
      showBankLanding();
      showToast(`خدمة «${btn.dataset.serviceLabel || 'البنك'}» — متاحة في تطبيق الإنماء الكامل`);
    }
  });

  document.querySelectorAll('.service-card:not(.service-card--byteshield)').forEach((card) => {
    card.addEventListener('click', (e) => {
      e.preventDefault();
      showToast('هذه الخدمة في ByteShield — افتح بطاقة فحص الاحتيال');
    });
  });

  let activeTab = 'text';
  let screenshotFile = null;

  const tabs = document.querySelectorAll('#user-scan-input .tab');
  const panels = document.querySelectorAll('#user-scan-input .tab-panel');
  const userScanInput = document.getElementById('user-scan-input');
  const socScanInput = document.getElementById('soc-scan-input'); // may be null in new HTML
  const scanSectionDesc = document.getElementById('scan-section-desc');
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
  const btnReportBank = document.getElementById('btn-report-bank');
  const reportBankHint = document.getElementById('report-bank-hint');
  const recommendContext = document.getElementById('recommend-context');
  const statRecContext = document.getElementById('stat-rec-context');
  const statWarnContext = document.getElementById('stat-warn-context');
  const chatMessages = document.getElementById('chat-messages');
  const chatForm = document.getElementById('chat-form');
  const chatInput = document.getElementById('chat-input');
  const btnChatSend = document.getElementById('btn-chat-send');
  const supportContacts = document.getElementById('support-contacts');
  const modeTabs = document.querySelectorAll('.mode-tab');
  const bsIntroUser = document.getElementById('bs-intro-user');
  const bsIntroSoc = document.getElementById('bs-intro-soc');
  // Legacy SOC DOM refs — null in new HTML; kept for no-op safety in SOC helpers below
  const socReportEl = document.getElementById('soc-report');
  const socLoadingEl = document.getElementById('soc-loading');
  const socEmptyEl = document.getElementById('soc-empty');
  const socCaseNotesEl = document.getElementById('soc-case-notes');
  const socCaseNotesEditor = document.getElementById('soc-case-notes-editor');
  const socCaseNotesStatus = document.getElementById('soc-case-notes-status');
  const socCaseNotesToolbar = document.getElementById('soc-case-notes-toolbar');
  const socCaseNotesDisposition = document.getElementById('soc-case-notes-disposition');
  const socDispositionValue = document.getElementById('soc-disposition-value');
  const socDispositionReason = document.getElementById('soc-disposition-reason');
  const btnCaseNotesEdit = document.getElementById('btn-case-notes-edit');
  const btnCaseNotesAccept = document.getElementById('btn-case-notes-accept');
  const recommendCard = document.getElementById('recommend-card');

  // Fraud Ops DOM refs
  const userWorkspace = document.getElementById('user-workspace');
  const fraudOps = document.getElementById('fraud-ops');
  const fraudCaseList = document.getElementById('fraud-case-list');
  const fraudQueueCount = document.getElementById('fraud-queue-count');
  const fraudQueuePager = document.getElementById('fraud-queue-pager');
  const fraudKpiTotal = document.getElementById('fraud-kpi-total');
  const fraudKpiPending = document.getElementById('fraud-kpi-pending');
  const fraudKpiReview = document.getElementById('fraud-kpi-review');
  const fraudKpiClosed = document.getElementById('fraud-kpi-closed');
  const fraudKpiHigh = document.getElementById('fraud-kpi-high');
  const fraudKpiAi = document.getElementById('fraud-kpi-ai');
  const fraudKpiPendingDelta = document.getElementById('fraud-kpi-pending-delta');
  const fraudKpiReviewDelta = document.getElementById('fraud-kpi-review-delta');
  const fraudKpiClosedDelta = document.getElementById('fraud-kpi-closed-delta');
  const fraudKpiHighDelta = document.getElementById('fraud-kpi-high-delta');
  const fraudKpiAiDelta = document.getElementById('fraud-kpi-ai-delta');
  const fraudViewDashboard = document.getElementById('fraud-view-dashboard');
  const fraudViewQueue = document.getElementById('fraud-view-queue');
  const fraudViewCampaigns = document.getElementById('fraud-view-campaigns');
  const fraudViewAll = document.getElementById('fraud-view-all');
  const fraudQueuePageBadge = document.getElementById('fraud-queue-page-badge');
  const fraudCampaignsPageBadge = document.getElementById('fraud-campaigns-page-badge');
  const fraudStatusFilter = document.getElementById('fraud-status-filter');
  const btnFraudBackServices = document.getElementById('btn-fraud-back-services');
  const btnFraudCampaignsRefresh = document.getElementById('btn-fraud-campaigns-refresh');
  const btnFraudAllRefresh = document.getElementById('btn-fraud-all-refresh');
  const fraudSelectAll = document.getElementById('fraud-select-all');
  const fraudQueuePages = document.getElementById('fraud-queue-pages');
  const allCasesList = document.getElementById('all-cases-list');
  const allCasesSearch = document.getElementById('all-cases-search');
  const allStatusFilter = document.getElementById('all-status-filter');
  const allCategoryFilter = document.getElementById('all-category-filter');
  const allRiskFilter = document.getElementById('all-risk-filter');
  const allSourceFilter = document.getElementById('all-source-filter');
  const allCasesPager = document.getElementById('all-cases-pager');
  const allCasesPages = document.getElementById('all-cases-pages');
  const allSelectAll = document.getElementById('all-select-all');
  const allKpiTotal = document.getElementById('all-kpi-total');
  const allKpiPending = document.getElementById('all-kpi-pending');
  const allKpiReview = document.getElementById('all-kpi-review');
  const allKpiResolved = document.getElementById('all-kpi-resolved');
  const allKpiClosed = document.getElementById('all-kpi-closed');
  const allKpiTotalPct = document.getElementById('all-kpi-total-pct');
  const allKpiPendingPct = document.getElementById('all-kpi-pending-pct');
  const allKpiReviewPct = document.getElementById('all-kpi-review-pct');
  const allKpiResolvedPct = document.getElementById('all-kpi-resolved-pct');
  const allKpiClosedPct = document.getElementById('all-kpi-closed-pct');
  const allStatusDonut = document.getElementById('all-status-donut');
  const allDonutTotal = document.getElementById('all-donut-total');
  const allStatusPendingPct = document.getElementById('all-status-pending-pct');
  const allStatusReviewPct = document.getElementById('all-status-review-pct');
  const allStatusClosedPct = document.getElementById('all-status-closed-pct');
  const allRiskBars = document.getElementById('all-risk-bars');
  const btnAllAdvancedSearch = document.getElementById('btn-all-advanced-search');
  const btnAllExport = document.getElementById('btn-all-export');
  const btnAllBulk = document.getElementById('btn-all-bulk');
  const btnAllPlaybook = document.getElementById('btn-all-playbook');
  const fraudCampaignPageList = document.getElementById('fraud-campaign-page-list');
  const fraudCampaignSearch = document.getElementById('fraud-campaign-search');
  const fraudCampaignSort = document.getElementById('fraud-campaign-sort');
  const fraudCampaignPager = document.getElementById('fraud-campaign-pager');
  const fraudCampaignDetailEmpty = document.getElementById('fraud-campaign-detail-empty');
  const fraudCampaignDetailBody = document.getElementById('fraud-campaign-detail-body');
  const fraudCampDetailTitle = document.getElementById('fraud-camp-detail-title');
  const fraudCampDetailRisk = document.getElementById('fraud-camp-detail-risk');
  const fraudCampDetailUrl = document.getElementById('fraud-camp-detail-url');
  const fraudCampDetailIcon = document.getElementById('fraud-camp-detail-icon');
  const fraudCampStatReports = document.getElementById('fraud-camp-stat-reports');
  const fraudCampStatToday = document.getElementById('fraud-camp-stat-today');
  const fraudCampStatSenders = document.getElementById('fraud-camp-stat-senders');
  const fraudCampStatFirst = document.getElementById('fraud-camp-stat-first');
  const fraudCampStatLast = document.getElementById('fraud-camp-stat-last');
  const fraudCampStatCategory = document.getElementById('fraud-camp-stat-category');
  const fraudCampDetailDesc = document.getElementById('fraud-camp-detail-desc');
  const fraudCampDetailIocs = document.getElementById('fraud-camp-detail-iocs');
  const fraudCampTrend = document.getElementById('fraud-camp-trend');
  const fraudCampRegions = document.getElementById('fraud-camp-regions');
  const btnFraudCampViewCases = document.getElementById('btn-fraud-camp-view-cases');
  const campKpiActive = document.getElementById('camp-kpi-active');
  const campKpiReports = document.getElementById('camp-kpi-reports');
  const campKpiHigh = document.getElementById('camp-kpi-high');
  const campKpiResolved = document.getElementById('camp-kpi-resolved');
  const campKpiAvg = document.getElementById('camp-kpi-avg');
  const campKpiActiveDelta = document.getElementById('camp-kpi-active-delta');
  const campKpiReportsDelta = document.getElementById('camp-kpi-reports-delta');
  const campKpiHighDelta = document.getElementById('camp-kpi-high-delta');
  const campKpiResolvedDelta = document.getElementById('camp-kpi-resolved-delta');
  const campKpiAvgDelta = document.getElementById('camp-kpi-avg-delta');
  const fraudAlertBadge = document.getElementById('fraud-alert-badge');
  const fraudRiskDonut = document.getElementById('fraud-risk-donut');
  const fraudDonutTotal = document.getElementById('fraud-donut-total');
  const fraudRiskHighPct = document.getElementById('fraud-risk-high-pct');
  const fraudRiskMediumPct = document.getElementById('fraud-risk-medium-pct');
  const fraudRiskLowPct = document.getElementById('fraud-risk-low-pct');
  const fraudThreatBars = document.getElementById('fraud-threat-bars');
  const fraudAlertsList = document.getElementById('fraud-alerts-list');
  const fraudAiInsights = document.getElementById('fraud-ai-insights');
  const fraudDrawerBackdrop = document.getElementById('fraud-drawer-backdrop');
  const fraudCaseDetail = document.getElementById('fraud-case-detail');
  const btnFraudCloseDrawer = document.getElementById('btn-fraud-close-drawer');
  const btnFraudOpenCopilot = document.getElementById('btn-fraud-open-copilot');
  const btnFraudExport = document.getElementById('btn-fraud-export');
  const fraudDetailEmpty = document.getElementById('fraud-detail-empty');
  const fraudDetailBody = document.getElementById('fraud-detail-body');
  const fraudDetailId = document.getElementById('fraud-detail-id');
  const fraudDetailTitle = document.getElementById('fraud-detail-title');
  const fraudDetailStatus = document.getElementById('fraud-detail-status');
  const fraudDetailRisk = document.getElementById('fraud-detail-risk');
  const fraudDetailTime = document.getElementById('fraud-detail-time');
  const fraudDetailType = document.getElementById('fraud-detail-type');
  const fraudDetailScore = document.getElementById('fraud-detail-score');
  const fraudDetailThreat = document.getElementById('fraud-detail-threat');
  const fraudDetailSummary = document.getElementById('fraud-detail-summary');
  const fraudDetailEvidence = document.getElementById('fraud-detail-evidence');
  const fraudDetailIocs = document.getElementById('fraud-detail-iocs');
  const fraudDetailScreenshotWrap = document.getElementById('fraud-detail-screenshot-wrap');
  const fraudDetailScreenshot = document.getElementById('fraud-detail-screenshot');
  const fraudCampaignsList = document.getElementById('fraud-campaigns-list');
  const fraudSearch = document.getElementById('fraud-search');
  const fraudCategoryFilter = document.getElementById('fraud-category-filter');
  const fraudRecAction = document.getElementById('fraud-rec-action');
  const fraudRecRationale = document.getElementById('fraud-rec-rationale');
  const fraudRecConfidence = document.getElementById('fraud-rec-confidence');
  const fraudModifyPanel = document.getElementById('fraud-modify-panel');
  const fraudModifyAction = document.getElementById('fraud-modify-action');
  const fraudModifyNote = document.getElementById('fraud-modify-note');
  const btnFraudRefresh = document.getElementById('btn-fraud-refresh');
  const btnFraudApprove = document.getElementById('btn-fraud-approve');
  const btnFraudModify = document.getElementById('btn-fraud-modify');
  const btnFraudReject = document.getElementById('btn-fraud-reject');
  const btnFraudModifySave = document.getElementById('btn-fraud-modify-save');
  const fraudCopilotMessages = document.getElementById('fraud-copilot-messages');
  const fraudCopilotForm = document.getElementById('fraud-copilot-form');
  const fraudCopilotInput = document.getElementById('fraud-copilot-input');
  const fraudDocExecutive = document.getElementById('fraud-doc-executive');
  const fraudDocTechnical = document.getElementById('fraud-doc-technical');
  const fraudDocCustomer = document.getElementById('fraud-doc-customer');
  const fraudDocManagement = document.getElementById('fraud-doc-management');
  const fraudDocNotes = document.getElementById('fraud-doc-notes');

  let fraudCasesCache = [];
  let fraudCampaignsCache = [];
  let selectedFraudCase = null;
  let fraudCopilotHistory = [];
  let fraudSearchQuery = '';
  let fraudCategory = 'all';
  let fraudView = 'dashboard';
  let fraudQuickFilter = null;
  let selectedCampaignId = null;
  let campaignSearchQuery = '';
  let campaignSort = 'newest';
  let allCasesCache = [];
  let allSearchQuery = '';
  let allStatus = 'all';
  let allCategory = 'all';
  let allRisk = 'all';
  let allSource = 'all';
  let lastScreenshotDataUrl = null;
  let fraudOpsAuthenticated = false;
  const FRAUD_AUTH_KEY = 'byteshield_fraud_ops_auth';

  try {
    fraudOpsAuthenticated = sessionStorage.getItem(FRAUD_AUTH_KEY) === '1'
      || localStorage.getItem(FRAUD_AUTH_KEY) === '1';
  } catch {
    fraudOpsAuthenticated = false;
  }

  const fraudLogin = document.getElementById('fraud-login');
  const fraudLoginForm = document.getElementById('fraud-login-form');
  const fraudLoginUser = document.getElementById('fraud-login-user');
  const fraudLoginPass = document.getElementById('fraud-login-pass');
  const fraudLoginRemember = document.getElementById('fraud-login-remember');
  const fraudLoginError = document.getElementById('fraud-login-error');
  const fraudLoginTogglePass = document.getElementById('fraud-login-toggle-pass');
  const fraudLoginSso = document.getElementById('fraud-login-sso');
  const fraudLoginForgot = document.getElementById('fraud-login-forgot');
  const btnFraudLogout = document.getElementById('btn-fraud-logout');

  modeTabs.forEach((tab) => {
    tab.addEventListener('click', () => switchMode(tab.dataset.mode));
  });

  function setFraudAuth(authenticated, remember) {
    fraudOpsAuthenticated = !!authenticated;
    try {
      if (authenticated) {
        sessionStorage.setItem(FRAUD_AUTH_KEY, '1');
        if (remember) localStorage.setItem(FRAUD_AUTH_KEY, '1');
        else localStorage.removeItem(FRAUD_AUTH_KEY);
      } else {
        sessionStorage.removeItem(FRAUD_AUTH_KEY);
        localStorage.removeItem(FRAUD_AUTH_KEY);
      }
    } catch {
      /* ignore storage errors */
    }
  }

  function showFraudLogin() {
    if (fraudLogin) fraudLogin.hidden = false;
    if (fraudOps) fraudOps.hidden = true;
    if (byteshieldPanel) byteshieldPanel.classList.add('byteshield-panel--fraud-login');
  }

  function hideFraudLogin() {
    if (fraudLogin) fraudLogin.hidden = true;
    if (byteshieldPanel) byteshieldPanel.classList.remove('byteshield-panel--fraud-login');
  }

  function enterFraudOpsDashboard() {
    hideFraudLogin();
    if (fraudOps) fraudOps.hidden = false;
    renderFraudOpsDashboard();
  }

  function switchMode(mode) {
    // Map legacy 'soc' to 'fraud'
    if (mode === 'soc') mode = 'fraud';
    activeMode = mode;

    modeTabs.forEach((tab) => {
      const active = tab.dataset.mode === mode;
      tab.classList.toggle('mode-tab--active', active);
      tab.setAttribute('aria-selected', active);
    });

    if (bsIntroUser) bsIntroUser.hidden = mode !== 'user';
    if (bsIntroSoc) bsIntroSoc.hidden = true;

    const hero = MAIN_HERO[mode] || MAIN_HERO.user;
    if (alinmaHeroTitle) alinmaHeroTitle.textContent = hero.title;
    if (alinmaHeroDesc) alinmaHeroDesc.textContent = hero.desc;
    if (byteshieldCardSublabel) byteshieldCardSublabel.textContent = hero.sublabel;
    const isFraud = mode === 'fraud';
    if (alinmaPage) alinmaPage.classList.toggle('alinma-page--soc-mode', isFraud);
    if (openByteshield) openByteshield.classList.toggle('service-card--byteshield-soc', isFraud);
    if (bsHeaderModeBadge) {
      bsHeaderModeBadge.textContent = isFraud ? 'Fraud Ops' : '\u0634\u062e\u0635\u064a';
      bsHeaderModeBadge.classList.toggle('bs-header__mode-badge--soc', isFraud);
    }
    if (byteshieldPanel) {
      byteshieldPanel.classList.toggle('byteshield-panel--soc-mode', isFraud);
    }

    if (userWorkspace) userWorkspace.hidden = isFraud;

    if (isFraud) {
      if (fraudOpsAuthenticated) {
        enterFraudOpsDashboard();
      } else {
        showFraudLogin();
      }
    } else {
      hideFraudLogin();
      if (fraudOps) fraudOps.hidden = true;
    }

    if (recommendCard) {
      recommendCard.hidden = mode !== 'user' || !lastUserReport;
    }

    updateScanInputForMode(mode);

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
    if (scoreEl) scoreEl.textContent = String(forecast.financialRiskScore ?? '?');
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
    if (activeMode !== 'user') {
      // Fraud Ops has its own UI — just hide user-mode widgets
      if (resultsUser) resultsUser.hidden = true;
      if (recommendCard) recommendCard.hidden = true;
      if (resultsPlaceholder) resultsPlaceholder.hidden = true;
      return;
    }

    const hasUser = !!lastUserReport;
    if (hasUser) {
      if (resultsPlaceholder) resultsPlaceholder.hidden = true;
      if (resultsUser) resultsUser.hidden = false;
      if (recommendCard) recommendCard.hidden = false;
    } else {
      if (resultsPlaceholder) resultsPlaceholder.hidden = false;
      if (resultsUser) resultsUser.hidden = true;
      if (recommendCard) recommendCard.hidden = true;
      if (resultsPlaceholderTitle) resultsPlaceholderTitle.textContent = '\u0633\u062a\u0638\u0647\u0631 \u0627\u0644\u0646\u062a\u0627\u0626\u062c \u0647\u0646\u0627';
      if (resultsPlaceholderHint) {
        resultsPlaceholderHint.textContent = '\u0623\u0631\u0633\u0644 \u0627\u0644\u0645\u062d\u062a\u0648\u0649 \u0644\u0644\u062d\u0635\u0648\u0644 \u0639\u0644\u0649 \u062a\u0642\u0631\u064a\u0631 \u0645\u0628\u0633\u0651\u0637: \u0622\u0645\u0646 \u0623\u0645 \u0627\u062d\u062a\u064a\u0627\u0644\u061f';
      }
    }
  }
  function updateScanInputForMode(mode) {
    if (userScanInput) userScanInput.hidden = mode !== 'user';
    if (socScanInput) socScanInput.hidden = true;
    if (scanSectionDesc) {
      scanSectionDesc.textContent = '\u0627\u0644\u0635\u0642 \u0627\u0644\u0645\u062d\u062a\u0648\u0649 \u0623\u0648 \u0627\u0631\u0641\u0639 \u0645\u0644\u0641\u064b\u0627 \u0644\u062a\u0642\u064a\u064a\u0645 \u0645\u0633\u062a\u0648\u0649 \u0627\u0644\u062e\u0637\u0631.';
    }
    if (btnSample) btnSample.textContent = '\u062c\u0631\u0628 \u0631\u0633\u0627\u0644\u0629 \u0627\u062d\u062a\u064a\u0627\u0644 \u0646\u0645\u0648\u0630\u062c\u064a\u0629';
    if (btnScan) btnScan.textContent = '🛡️ بدء التحليل الأمني';
  }

  function readFieldValue(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : '';
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
    showToast('\u062a\u0645 \u062a\u062d\u0645\u064a\u0644 \u0631\u0633\u0627\u0644\u0629 \u0627\u062d\u062a\u064a\u0627\u0644 \u0646\u0645\u0648\u0630\u062c\u064a\u0629 \u2014 \u0634\u063a\u0651\u0644 \u0627\u0644\u062a\u062d\u0644\u064a\u0644');
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
      showToast('حجم الملف كبير — الحد الأقصى 10 MB');
      return;
    }

    screenshotFile = file;
    lastScreenshotDataUrl = null;

    if (isImage) {
      const reader = new FileReader();
      reader.onload = () => {
        lastScreenshotDataUrl = typeof reader.result === 'string' ? reader.result : null;
      };
      reader.readAsDataURL(file);
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
    lastScreenshotDataUrl = null;
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
  if (btnCaseNotesEdit) btnCaseNotesEdit.addEventListener('click', toggleCaseNotesEdit);
  if (btnCaseNotesAccept) btnCaseNotesAccept.addEventListener('click', acceptCaseNotes);
  if (btnReportBank) btnReportBank.addEventListener('click', reportToBank);
  if (socCaseNotesToolbar) {
    socCaseNotesToolbar.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-cmd]');
      if (!btn || caseNotesMode !== 'editing') return;
      e.preventDefault();
      document.execCommand(btn.getAttribute('data-cmd'), false, null);
      if (socCaseNotesEditor) socCaseNotesEditor.focus();
    });
  }
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
    const typeAr = { Message: 'رسالة', Email: 'بريد', URL: 'رابط', Screenshot: 'لقطة' }[type] || type;
    const lead = flags.length > 0
      ? `أثناء فحص هذا ${typeAr}، لاحظنا ${flags.length} علامة${flags.length > 1 ? 'ات' : ''} تستدعي الانتباه — منها: ${flags[0]}.`
      : `لم نرصد علامات خطر واضحة في هذا ${typeAr}.`;
    if (score >= 61) {
      return `${lead} ننصح بعدم التفاعل مع المحتوى أو مشاركة أي بيانات حساسة حتى تتأكد من المصدر.`;
    }
    if (score >= 31) {
      return `${lead} تحقق من المرسل والروابط قبل أي إجراء، خاصة إذا طُلب منك التصرف بسرعة.`;
    }
    return `${lead} مع ذلك، تحقق دائماً عبر القنوات الرسمية إذا شعرت بأي شيء غريب.`;
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
      ? '\u062c\u0627\u0631\u064a \u062a\u062d\u0644\u064a\u0644 \u0627\u0644\u0631\u0627\u0628\u0637\u2026 (\u0642\u062f \u064a\u0633\u062a\u063a\u0631\u0642 30 \u062b)'
      : activeTab === 'screenshot'
        ? '\u062c\u0627\u0631\u064a \u062a\u062d\u0644\u064a\u0644 \u0627\u0644\u0645\u0644\u0641\u2026 (\u0642\u062f \u064a\u0633\u062a\u063a\u0631\u0642 \u062f\u0642\u064a\u0642\u0629)'
      : '\u062c\u0627\u0631\u064a \u0627\u0644\u062a\u062d\u0644\u064a\u0644\u2026';

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
      const payload = activeTab === 'url'
        ? { url: input.text }
        : { text: input.text, contentType: input.type };

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
      btnScan.textContent = '🛡️ بدء التحليل الأمني';
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
    if (socCaseNotesEl) socCaseNotesEl.hidden = true;
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
        executiveSummaryAr: '',
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
      analystNotes: 'Generated by local fallback ? connect OpenAI for full enterprise SOC report.',
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
                  <td>${escapeHtml(item.context || '?')}</td>
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
                <span class="soc-playbook__num">${step.step || '?'}</span>
                <strong>${escapeHtml(step.action || step)}</strong>
              </div>
              ${step.owner ? `<span class="soc-playbook__meta">Owner: ${escapeHtml(step.owner)} ? ETA: ${escapeHtml(step.estimatedTime || 'N/A')}</span>` : ''}
            </li>`).join('')}
        </ol>
      </div>`;
  }

  function formatCaseNoteLines(items) {
    if (!items || !items.length) return ['?'];
    return items.map((item) => String(item).trim()).filter(Boolean);
  }

  function collectIocValues(ioc) {
    if (!ioc) return [];
    const buckets = ['urls', 'domains', 'ipAddresses', 'emailAddresses', 'phoneNumbers', 'fileHashes', 'other'];
    const values = [];
    buckets.forEach((key) => {
      (ioc[key] || []).forEach((item) => {
        const value = typeof item === 'string' ? item : (item?.value || '');
        if (value) values.push(value);
      });
    });
    return values;
  }

  function determineAlertDisposition(soc, userReport) {
    const inc = soc?.incident || {};
    const score = Number(inc.riskScore ?? userReport?.score ?? 0);
    const severity = String(inc.severity || '').toLowerCase();
    const classification = String(inc.classification || '').toLowerCase();
    const status = String(inc.status || '').toLowerCase();
    const iocCount = collectIocValues(soc?.indicatorsOfCompromise || {}).length;
    const confidence = Number(inc.confidence ?? userReport?.confidence ?? 0);

    const benignHints = /benign|false.?positive|informational|noise|whitelist|expected/.test(
      `${classification} ${status} ${inc.executiveSummary || ''} ${inc.title || ''}`
    );
    const maliciousHints = /phish|fraud|malware|credential|bec|spear|smish|vish|compromise|exploit/.test(
      `${classification} ${inc.title || ''} ${inc.attackVector || ''}`
    );

    let disposition = 'True Positive';
    let reason = '';

    if (
      benignHints
      || severity === 'informational'
      || (severity === 'low' && score < 35 && iocCount === 0)
      || (score <= 30 && !maliciousHints)
    ) {
      disposition = 'False Positive';
      reason = `AI assessed this alert as False Positive based on severity ${inc.severity || 'Unknown'}, risk score ${score}/100`
        + (iocCount ? `, and ${iocCount} weak/low-priority indicators.` : ', with no strong malicious indicators.')
        + (confidence ? ` Confidence ${confidence}%.` : '');
    } else {
      disposition = 'True Positive';
      reason = `AI assessed this alert as True Positive based on severity ${inc.severity || 'Unknown'}, risk score ${score}/100`
        + (classification ? `, classification ${inc.classification}` : '')
        + (iocCount ? `, and ${iocCount} observable indicator(s).` : '.')
        + (confidence ? ` Confidence ${confidence}%.` : '');
    }

    return { disposition, reason, score, severity: inc.severity || 'Unknown' };
  }

  function renderCaseNotesDisposition(dispositionInfo) {
    if (!socCaseNotesDisposition || !socDispositionValue || !socDispositionReason) return;
    const isTp = dispositionInfo.disposition === 'True Positive';
    socDispositionValue.textContent = dispositionInfo.disposition;
    socDispositionValue.classList.toggle('soc-disposition-value--tp', isTp);
    socDispositionValue.classList.toggle('soc-disposition-value--fp', !isTp);
    socDispositionReason.textContent = dispositionInfo.reason;
    socCaseNotesDisposition.hidden = false;
  }

  function buildCaseNotesSections(soc, userReport, dispositionInfo) {
    const inc = soc?.incident || {};
    const playbook = soc?.containmentPlaybook || {};
    const ioc = soc?.indicatorsOfCompromise || {};
    const timeline = Array.isArray(inc.timeline) ? inc.timeline : [];
    const score = dispositionInfo?.score ?? inc.riskScore ?? userReport?.score ?? '?';
    const severity = englishOnlyText(inc.severity, 'Unknown');
    const classification = englishOnlyText(inc.classification, lastContentType || 'Unclassified');
    const disposition = dispositionInfo?.disposition || 'True Positive';

    const timeLines = timeline.length
      ? timeline.map((t) => {
        const phase = englishOnlyText(t.phase, 'Activity');
        const stamp = englishOnlyText(t.timestamp, 'N/A');
        const desc = englishOnlyText(t.description, 'No description provided');
        return `${phase}: ${stamp} ? ${desc}`;
      })
      : [
        `Detected: ${soc?.generatedAt ? formatSocDateTime(new Date(soc.generatedAt)) : formatSocDateTime()}`,
        `Attack vector: ${englishOnlyText(inc.attackVector, 'Unknown')}`,
      ];

    const affected = formatCaseNoteLines(
      englishOnlyList(
        inc.affectedAssets,
        [classification, lastContentType || 'Endpoint / messaging channel']
      )
    );

    const classificationReason = formatCaseNoteLines(
      englishOnlyList(
        [
          dispositionInfo?.reason || '',
          englishOnlyText(inc.executiveSummary),
          englishOnlyText(inc.impactAssessment) ? `Impact: ${englishOnlyText(inc.impactAssessment)}` : '',
          englishOnlyText(inc.attackVector) ? `Vector: ${englishOnlyText(inc.attackVector)}` : '',
        ].filter(Boolean),
        [
          `AI disposition: ${disposition}.`,
          `Alert classified as ${classification} with risk score ${score}/100 and severity ${severity}.`,
        ]
      )
    );

    const escalateReason = formatCaseNoteLines(
      englishOnlyList(
        playbook.escalationCriteria,
        disposition === 'False Positive'
          ? [
            'No escalation required unless new corroborating evidence appears',
            'Close as False Positive after analyst validation and document rationale',
          ]
          : [
            `Severity ${severity} with risk score ${score}/100`,
            playbook.priority
              ? `Playbook priority ${englishOnlyText(playbook.priority, 'P2')}`
              : 'Potential customer financial loss / credential harvest / endpoint compromise',
          ]
      )
    );

    const remediationSource = [
      ...(playbook.immediateActions || []),
      ...(playbook.shortTermActions || []),
    ].map((step) => englishOnlyText(step.action || step));

    const remediation = formatCaseNoteLines(
      englishOnlyList(
        remediationSource,
        disposition === 'False Positive'
          ? [
            'Tune detection rule / suppress known-benign pattern if validated',
            'Document FP rationale in the ticket and close the alert',
            'Monitor for recurrence with updated context',
          ]
          : [
            'Block malicious indicators at email gateway / proxy / EDR',
            'Contain affected host or mailbox and reset credentials if needed',
            'Notify impacted user and monitor for related alerts',
          ]
      )
    );

    const indicatorsRaw = collectIocValues(ioc).map((value) => englishOnlyText(value)).filter(Boolean);
    const indicators = formatCaseNoteLines(
      indicatorsRaw.length
        ? indicatorsRaw
        : [
          englishOnlyText(inc.attackVector, 'Review original evidence for URLs, senders, hosts, and process artifacts'),
        ]
    );

    return {
      'Time of activity:': timeLines,
      'List of Affected Entities:': affected,
      'Reason for Classification:': classificationReason,
      'Reason for Escalating the Alert:': escalateReason,
      'Recommended Remediation Actions:': remediation,
      'List of Attack Indicators:': indicators,
    };
  }

  function buildCaseNotesHtml(sections) {
    return CASE_NOTE_SECTIONS.map((label) => {
      const lines = sections[label] || ['?'];
      const body = lines.length === 1
        ? `<p>${escapeHtml(lines[0])}</p>`
        : `<ul>${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>`;
      return `<strong class="soc-case-label">${escapeHtml(label)}</strong>${body}`;
    }).join('');
  }

  function setCaseNotesStatus(mode) {
    caseNotesMode = mode;
    if (!socCaseNotesStatus) return;
    socCaseNotesStatus.classList.remove('soc-case-notes__status--editing', 'soc-case-notes__status--accepted');
    if (mode === 'editing') {
      socCaseNotesStatus.textContent = 'Editing';
      socCaseNotesStatus.classList.add('soc-case-notes__status--editing');
    } else if (mode === 'accepted') {
      socCaseNotesStatus.textContent = 'Accepted';
      socCaseNotesStatus.classList.add('soc-case-notes__status--accepted');
    } else {
      socCaseNotesStatus.textContent = 'AI Draft';
    }
  }

  function populateCaseNotesFromSoc(soc, userReport) {
    if (!socCaseNotesEl || !socCaseNotesEditor) return;

    const dispositionInfo = determineAlertDisposition(soc, userReport || lastUserReport);
    renderCaseNotesDisposition(dispositionInfo);

    const sections = buildCaseNotesSections(soc, userReport || lastUserReport, dispositionInfo);
    const html = buildCaseNotesHtml(sections);
    socCaseNotesEditor.innerHTML = html;
    socCaseNotesEditor.contentEditable = 'false';
    if (socCaseNotesToolbar) socCaseNotesToolbar.hidden = true;
    if (btnCaseNotesEdit) btnCaseNotesEdit.textContent = 'Edit';
    caseNotesAcceptedHtml = '';
    setCaseNotesStatus('draft');

    if (lastSocReport) {
      lastSocReport = {
        ...lastSocReport,
        aiDisposition: dispositionInfo.disposition,
        aiDispositionReason: dispositionInfo.reason,
      };
    }

    socCaseNotesEl.hidden = false;
  }

  function toggleCaseNotesEdit() {
    if (!socCaseNotesEditor || !socCaseNotesEl || socCaseNotesEl.hidden) return;

    if (caseNotesMode === 'editing') {
      socCaseNotesEditor.contentEditable = 'false';
      if (socCaseNotesToolbar) socCaseNotesToolbar.hidden = true;
      if (btnCaseNotesEdit) btnCaseNotesEdit.textContent = 'Edit';
      setCaseNotesStatus(caseNotesAcceptedHtml && socCaseNotesEditor.innerHTML === caseNotesAcceptedHtml ? 'accepted' : 'draft');
      showToast('Editing stopped');
      return;
    }

    socCaseNotesEditor.contentEditable = 'true';
    if (socCaseNotesToolbar) socCaseNotesToolbar.hidden = false;
    if (btnCaseNotesEdit) btnCaseNotesEdit.textContent = 'Done';
    setCaseNotesStatus('editing');
    socCaseNotesEditor.focus();
  }

  function acceptCaseNotes() {
    if (!socCaseNotesEditor || !socCaseNotesEl || socCaseNotesEl.hidden) return;

    socCaseNotesEditor.contentEditable = 'false';
    if (socCaseNotesToolbar) socCaseNotesToolbar.hidden = true;
    if (btnCaseNotesEdit) btnCaseNotesEdit.textContent = 'Edit';
    caseNotesAcceptedHtml = socCaseNotesEditor.innerHTML;
    setCaseNotesStatus('accepted');

    if (lastSocReport) {
      lastSocReport = {
        ...lastSocReport,
        analystCaseNotesHtml: caseNotesAcceptedHtml,
        analystCaseNotesAcceptedAt: new Date().toISOString(),
      };
    }

    showToast('Analyst case notes accepted');
  }

  function resetReportSubmitButton() {
    if (!btnReportBank) return;
    btnReportBank.classList.remove('btn--decision-loading', 'btn--decision-pop', 'btn--decision-approved');
    btnReportBank.textContent = 'Submit Fraud Report';
    btnReportBank.disabled = false;
    btnReportBank.setAttribute('aria-pressed', 'false');
  }

  function applyReportSubmitSuccess() {
    if (!btnReportBank) return;
    btnReportBank.classList.remove('btn--decision-loading', 'btn--decision-pop');
    btnReportBank.classList.add('btn--decision-approved');
    btnReportBank.textContent = 'Submitted ✓';
    btnReportBank.disabled = true;
    btnReportBank.setAttribute('aria-pressed', 'true');
  }

  async function reportToBank() {
    if (!lastUserReport) {
      showToast('Run an analysis first');
      return;
    }

    const score = Number(lastUserReport.score) || 0;
    if (score < 31) {
      showToast('Only suspicious or high-risk results can be submitted');
      return;
    }

    if (btnReportBank) {
      btnReportBank.classList.add('btn--decision-loading', 'btn--decision-pop');
      btnReportBank.textContent = 'Submitting…';
      btnReportBank.disabled = true;
    }

    try {
      const response = await fetch(getApiUrl('/api/cases'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: lastEvidenceText,
          contentType: lastContentType,
          screenshotDataUrl: lastScreenshotDataUrl,
          fraudProbability: score,
          aiExplanation: lastUserReport.shortExplanation,
          reasoning: lastUserReport.reasoning || [],
          fraudCategory: lastUserReport.threatType || 'general',
          threatType: lastUserReport.threatType || 'general',
        }),
      });

      const result = await response.json();
      if (!response.ok || !result.success) {
        throw new Error(result.error || 'Failed to submit fraud report');
      }

      applyReportSubmitSuccess();
      if (reportBankHint) reportBankHint.hidden = false;
      showToast(`Fraud report submitted — ${result.case.id}`);
      if (activeMode === 'fraud') renderFraudOpsDashboard();
    } catch (err) {
      console.error(err);
      resetReportSubmitButton();
      showToast(err.message || 'Could not submit fraud report');
    } finally {
      btnReportBank?.classList.remove('btn--decision-pop');
    }
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
          <span class="soc-report-time">${escapeHtml(soc.generatedAt ? formatSocDateTime(new Date(soc.generatedAt)) : formatSocDateTime())}</span>
        </div>
        <h3 class="soc-header__title">${escapeHtml(inc.title || 'Security Incident Report')}</h3>
        <div class="soc-header__badges">
          <span class="soc-sev soc-sev--${sevClass} soc-sev--lg">${escapeHtml(inc.severity || 'Unknown')}</span>
          <span class="soc-badge soc-badge--status">${escapeHtml(inc.status || 'Open')}</span>
          <span class="soc-badge">${escapeHtml(inc.classification || 'Unclassified')}</span>
          <span class="soc-badge soc-badge--priority">${escapeHtml(playbook.priority || 'P2')}</span>
        </div>
      </header>

      ${(inc.executiveSummary || inc.summary)
        ? `<p class="soc-summary">${escapeHtml(inc.executiveSummary || inc.summary)}</p>`
        : ''}

      <div class="soc-metrics">
        <div class="soc-metric"><span>Risk Score</span><strong>${escapeHtml(String(inc.riskScore ?? '?'))}/100</strong></div>
        <div class="soc-metric"><span>Confidence</span><strong>${escapeHtml(String(inc.confidence ?? '?'))}%</strong></div>
        <div class="soc-metric"><span>Attack Vector</span><strong>${escapeHtml(inc.attackVector || '?')}</strong></div>
        <div class="soc-metric"><span>Kill Chain</span><strong>${escapeHtml(mitre.killChainPhase || '?')}</strong></div>
      </div>

      <div class="soc-section">
        <h4 class="soc-section__title">Impact Assessment</h4>
        <p class="soc-text">${escapeHtml(inc.impactAssessment || '?')}</p>
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

      ${soc.source === 'local' ? '<p class="soc-fallback-note">? Local fallback report ? configure OpenAI for full enterprise SOC output.</p>' : ''}
    `;

    populateCaseNotesFromSoc(soc, lastUserReport);
    updateResultsVisibility();
  }

  function finalizeAnalysis(text, contentType, report) {
    lastUserReport = report;
    lastEvidenceText = text;
    lastContentType = contentType;
    lastAnalysisContext = buildChatContext(text, report);
    renderResults(report);
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
    document.getElementById('results-status-desc').textContent = shortExplanation;

    const tierKey = scoreTierKey(score);
    if (recommendContext) recommendContext.textContent = RECOMMEND_CONTEXT[tierKey];

    const recSummary = score <= 30 ? 'لا يلزم إجراء فوري' : score <= 60 ? 'توخَّ الحذر وتحقق' : 'إجراءات عاجلة مطلوبة';
    document.getElementById('stat-rec-text').textContent = recSummary;
    if (statRecContext) statRecContext.textContent = STAT_REC_CONTEXT[tierKey];

    const indicatorCount = reasoning.length;
    const warnSummary = getWarnSummary(indicatorCount);
    document.getElementById('stat-warn-text').textContent = `${indicatorCount} — ${warnSummary}`;
    if (statWarnContext) statWarnContext.textContent = getWarnContext(indicatorCount);

    document.getElementById('recommend-summary').textContent = shortExplanation;
    document.getElementById('recommend-checklist').innerHTML = actionChecklist
      .map((a) => `<li>${escapeHtml(a)}</li>`).join('');

    if (btnReportBank) {
      const suspicious = (Number(score) || 0) >= 31;
      resetReportSubmitButton();
      btnReportBank.hidden = activeMode !== 'user' || !suspicious;
    }
    if (reportBankHint) reportBankHint.hidden = true;

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
      : '<li>لا تُرصد مؤشرات خطر واضحة</li>';

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
        'تحقق من الرقم الرسمي للبنك',
        'لا ترسل OTP لأي جهة تطلبه عبر SMS',
        'اتصل بالبنك من التطبيق الرسمي',
      ];
      if (bankAdvice) {
        tips.unshift(bankAdvice);
      }
      tipsList.innerHTML = tips.slice(0, 5).map((t) => `<li><span>•</span>${escapeHtml(t)}</li>`).join('');
    } else {
      title.textContent = 'إرشادات أمنية';
      tipsList.innerHTML = `
        <li><span>•</span>لا تشارك بياناتك البنكية عبر الرسائل</li>
        <li><span>•</span>تحقق من الرقم الرسمي للبنك</li>
        <li><span>•</span>لا ترسل OTP لأي جهة تطلبه عبر SMS</li>
        <li><span>•</span>اتصل بالبنك من التطبيق الرسمي</li>`;
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
    appendChatMessage('bot', 'مرحباً! أنا ByteShield AI. اسألني عن نتيجة التحليل أو اطلب نصائح: كيف أتحقق من رسالة مشبوهة أو ماذا أفعل إذا ضغطت على رابط؟');
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
    if (e.key !== 'Escape') return;
    if (navDrawerBackdrop && !navDrawerBackdrop.hidden) {
      closeNavDrawer();
      return;
    }
    if (!modalBackdrop.hidden) {
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
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
  }



  // -----------------------------------------------------------------------
  // Fraud Operations — server-backed case portal
  // -----------------------------------------------------------------------

  function scoreLevelClass(score) {
    const n = Number(score) || 0;
    if (n >= 80) return 'high';
    if (n >= 50) return 'medium';
    return 'low';
  }

  function statusBadgeClass(status) {
    if (status === 'Pending Review') return 'pending';
    if (status === 'Under Review') return 'open';
    if (status === 'Closed') return 'closed';
    return 'open';
  }

  function sourceIcon(contentType) {
    const t = (contentType || '').toLowerCase();
    if (t.includes('url') || t.includes('link')) return '🌐';
    if (t.includes('email') || t.includes('mail')) return '✉️';
    if (t.includes('sms') || t.includes('whatsapp')) return '💬';
    if (t.includes('file') || t.includes('image') || t.includes('pdf')) return '📎';
    return '💬';
  }

  function setTextAll(selector, text) {
    document.querySelectorAll(selector).forEach((el) => {
      el.textContent = text;
    });
  }

  function switchFraudView(view) {
    const allowed = ['dashboard', 'queue', 'campaigns', 'all'];
    const target = allowed.includes(view) ? view : 'dashboard';
    fraudView = target;
    if (fraudViewDashboard) fraudViewDashboard.hidden = target !== 'dashboard';
    if (fraudViewQueue) fraudViewQueue.hidden = target !== 'queue';
    if (fraudViewCampaigns) fraudViewCampaigns.hidden = target !== 'campaigns';
    if (fraudViewAll) fraudViewAll.hidden = target !== 'all';
  }

  function setActiveFraudNav(navKey) {
    document.querySelectorAll('.fraud-nav-item[data-fraud-nav]').forEach((b) => {
      const nav = b.dataset.fraudNav;
      let active = false;
      if (navKey === 'dashboard') active = nav === 'dashboard';
      else if (navKey === 'campaigns') active = nav === 'campaigns';
      else if (navKey === 'all') active = nav === 'all';
      else if (navKey === 'queue') active = nav === 'queue' && !b.dataset.fraudFilterNav;
      else if (navKey === 'review') active = b.dataset.fraudFilterNav === 'Under Review';
      else if (navKey === 'pending') active = b.dataset.fraudFilterNav === 'Pending Review';
      else active = nav === 'queue' && !b.dataset.fraudFilterNav;
      b.classList.toggle('fraud-nav-item--active', active);
    });
  }

  function openFraudDrawer() {
    if (fraudCaseDetail) fraudCaseDetail.hidden = false;
    if (fraudDrawerBackdrop) fraudDrawerBackdrop.hidden = false;
  }

  function closeFraudDrawer() {
    if (fraudCaseDetail) fraudCaseDetail.hidden = true;
    if (fraudDrawerBackdrop) fraudDrawerBackdrop.hidden = true;
    if (fraudDetailEmpty) fraudDetailEmpty.hidden = false;
    if (fraudDetailBody) fraudDetailBody.hidden = true;
    selectedFraudCaseId = null;
    selectedFraudCase = null;
  }

  function scrollFraudSection(nav) {
    if (nav === 'dashboard') {
      switchFraudView('dashboard');
      setActiveFraudNav('dashboard');
      return;
    }
    if (nav === 'campaigns') {
      switchFraudView('campaigns');
      setActiveFraudNav('campaigns');
      renderCampaignsPage();
      return;
    }
    if (nav === 'all') {
      switchFraudView('all');
      setActiveFraudNav('all');
      renderAllCasesPage();
      return;
    }
    switchFraudView('queue');
    if (nav === 'analytics' || nav === 'actions') setActiveFraudNav('queue');
    else setActiveFraudNav('queue');
  }

  function getVisibleFraudCases() {
    let list = fraudCasesCache.slice();
    if (fraudQuickFilter === 'high') {
      list = list.filter((c) => Number(c.fraudProbability) >= 80);
    }
    return list;
  }

  function caseSubtitle(c) {
    const preview = (c.preview || '').toString().trim();
    if (preview) return preview.slice(0, 48);
    const urls = c.urls || [];
    if (urls[0]) return String(urls[0]).slice(0, 48);
    return (c.fraudCategory || 'Customer report').replace(/_/g, ' ');
  }

  function applyFraudKpis(stats, cases) {
    const pending = stats.pending || 0;
    const review = stats.underReview || 0;
    const closedToday = stats.closedToday != null
      ? stats.closedToday
      : (cases || []).filter((c) => c.status === 'Closed').length;
    const highRisk = stats.highRisk != null
      ? stats.highRisk
      : (cases || []).filter((c) => Number(c.fraudProbability) >= 70).length;
    const total = stats.total || 0;
    const closed = stats.closed || 0;
    const aiPct = total > 0 ? Math.min(96, Math.round(55 + (closed / Math.max(total, 1)) * 40)) : 0;

    if (fraudKpiTotal) fraudKpiTotal.textContent = String(total);
    setTextAll('.fraud-kpi-pending-val', String(pending));
    setTextAll('.fraud-kpi-review-val', String(review));
    setTextAll('.fraud-kpi-closed-val', String(closedToday));
    setTextAll('.fraud-kpi-high-val', String(highRisk));
    setTextAll('.fraud-kpi-ai-val', total ? `${aiPct}%` : '—');

    const pendingDelta = pending ? `${pending} awaiting triage` : 'Queue clear';
    const reviewDelta = review ? `${review} in progress` : 'No change';
    const closedDelta = closedToday ? `↑ ${closedToday} today` : 'No closures today';
    const highDelta = highRisk ? `↑ ${highRisk} high risk` : 'No high risk';
    const aiDelta = total ? 'avg. time saved' : 'Awaiting cases';

    setTextAll('.fraud-kpi-pending-delta', pendingDelta);
    setTextAll('.fraud-kpi-review-delta', reviewDelta);
    setTextAll('.fraud-kpi-closed-delta', closedDelta);
    setTextAll('.fraud-kpi-high-delta', highDelta);
    setTextAll('.fraud-kpi-ai-delta', aiDelta);

    if (fraudKpiPendingDelta) fraudKpiPendingDelta.textContent = pendingDelta;
    if (fraudKpiReviewDelta) fraudKpiReviewDelta.textContent = reviewDelta;
    if (fraudKpiClosedDelta) fraudKpiClosedDelta.textContent = closedDelta;
    if (fraudKpiHighDelta) fraudKpiHighDelta.textContent = highDelta;
    if (fraudKpiAiDelta) fraudKpiAiDelta.textContent = aiDelta;

    if (fraudQueueCount) fraudQueueCount.textContent = String((cases || []).length);
    if (fraudQueuePageBadge) fraudQueuePageBadge.textContent = String((cases || []).length);
    if (fraudAlertBadge) fraudAlertBadge.textContent = String(Math.min(99, highRisk || pending));
  }

  function renderRiskCharts(cases) {
    const list = cases || [];
    let high = 0;
    let medium = 0;
    let low = 0;
    const threatCounts = {};

    list.forEach((c) => {
      const level = scoreLevelClass(c.fraudProbability);
      if (level === 'high') high += 1;
      else if (level === 'medium') medium += 1;
      else low += 1;
      const key = (c.fraudCategory || 'general').replace(/_/g, ' ');
      threatCounts[key] = (threatCounts[key] || 0) + 1;
    });

    const total = list.length || 0;
    const highPct = total ? Math.round((high / total) * 100) : 0;
    const mediumPct = total ? Math.round((medium / total) * 100) : 0;
    const lowPct = total ? Math.max(0, 100 - highPct - mediumPct) : 100;

    if (fraudRiskDonut) {
      fraudRiskDonut.style.setProperty('--high', String(highPct));
      fraudRiskDonut.style.setProperty('--medium', String(mediumPct));
      fraudRiskDonut.style.setProperty('--low', String(lowPct));
    }
    if (fraudDonutTotal) fraudDonutTotal.textContent = String(total);
    if (fraudRiskHighPct) fraudRiskHighPct.textContent = `${highPct}%`;
    if (fraudRiskMediumPct) fraudRiskMediumPct.textContent = `${mediumPct}%`;
    if (fraudRiskLowPct) fraudRiskLowPct.textContent = `${lowPct}%`;

    if (fraudThreatBars) {
      const entries = Object.entries(threatCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
      if (!entries.length) {
        fraudThreatBars.innerHTML = '<li class="fraud-bars__empty">No threat data yet.</li>';
      } else {
        const max = Math.max(...entries.map(([, n]) => n), 1);
        fraudThreatBars.innerHTML = entries.map(([label, count]) => {
          const width = Math.round((count / max) * 100);
          return `<li class="fraud-bar">
            <span>${escapeHtml(label)}</span>
            <div class="fraud-bar__track"><div class="fraud-bar__fill" style="width:${width}%"></div></div>
            <span class="fraud-bar__count">${count}</span>
          </li>`;
        }).join('');
      }
    }
  }

  function renderFraudAlerts(cases, campaigns) {
    if (!fraudAlertsList) return;
    const alerts = [];
    (cases || [])
      .filter((c) => Number(c.fraudProbability) >= 61)
      .slice(0, 4)
      .forEach((c) => {
        alerts.push({
          title: c.preview || c.id,
          time: c.submittedAt
            ? new Date(c.submittedAt).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' })
            : '',
          sev: scoreLevelClass(c.fraudProbability),
        });
      });
    (campaigns || []).slice(0, 2).forEach((c) => {
      alerts.push({
        title: `Campaign: ${c.title || c.id}`,
        time: `${c.reportCount || 0} reports`,
        sev: (c.reportCount || 0) >= 5 ? 'high' : 'medium',
      });
    });

    if (!alerts.length) {
      fraudAlertsList.innerHTML = '<li class="fraud-alerts__empty">No alerts yet.</li>';
    } else {
      fraudAlertsList.innerHTML = alerts.slice(0, 5).map((a) => `
        <li class="fraud-alert">
          <div>
            <strong>${escapeHtml((a.title || '').toString().slice(0, 64))}</strong>
            <span>${escapeHtml(a.time)}</span>
          </div>
          <span class="fraud-alert__sev fraud-alert__sev--${a.sev}">${a.sev}</span>
        </li>`).join('');
    }

    if (fraudAiInsights) {
      const high = (cases || []).filter((c) => Number(c.fraudProbability) >= 70).length;
      const camp = (campaigns || []).length;
      if (!cases?.length) {
        fraudAiInsights.textContent = 'AI will surface patterns once cases are reported.';
      } else {
        fraudAiInsights.textContent = `AI detected ${high} high-risk case${high === 1 ? '' : 's'} and ${camp} active campaign${camp === 1 ? '' : 's'}. Prioritize pending reviews with overlapping IOCs.`;
      }
    }
  }

  async function renderFraudOpsDashboard() {
    try {
      const params = new URLSearchParams();
      if (fraudFilter && fraudFilter !== 'all') params.set('status', fraudFilter);
      if (fraudCategory && fraudCategory !== 'all') params.set('category', fraudCategory);
      if (fraudSearchQuery) params.set('q', fraudSearchQuery);

      const [casesRes, campaignsRes] = await Promise.all([
        fetch(getApiUrl(`/api/cases?${params.toString()}`)),
        fetch(getApiUrl('/api/campaigns')),
      ]);

      const casesJson = await casesRes.json();
      const campaignsJson = await campaignsRes.json();

      if (!casesRes.ok || !casesJson.success) {
        throw new Error(casesJson.error || 'Failed to load cases');
      }

      fraudCasesCache = casesJson.cases || [];
      fraudCampaignsCache = campaignsJson.success ? (campaignsJson.campaigns || []) : [];
      const stats = casesJson.stats || {};

      applyFraudKpis(stats, fraudCasesCache);
      renderFraudCaseTable();
      renderFraudCampaigns(fraudCampaignsCache);
      renderRiskCharts(fraudCasesCache);
      renderFraudAlerts(fraudCasesCache, fraudCampaignsCache);
      if (fraudView === 'campaigns') renderCampaignsPage();
      if (fraudView === 'all') {
        allCasesCache = fraudCasesCache.slice();
        renderAllCasesPage();
      }
    } catch (err) {
      console.error(err);
      if (fraudCaseList) {
        fraudCaseList.innerHTML = `<tr class="fraud-queue__empty-row"><td colspan="7">Could not load cases. ${escapeHtml(err.message)}</td></tr>`;
      }
    }
  }

  function renderFraudCampaigns(campaigns) {
    if (!fraudCampaignsList) return;
    const active = (campaigns || []).filter((c) => (c.reportCount || 0) >= 1);
    if (!active.length) {
      fraudCampaignsList.innerHTML = '<li class="fraud-campaigns__empty">No active campaigns yet.</li>';
      return;
    }
    fraudCampaignsList.innerHTML = active.slice(0, 8).map((c) => {
      const risk = c.riskLevel || ((c.reportCount || 0) >= 5 ? 'high' : (c.reportCount || 0) >= 2 ? 'medium' : 'low');
      return `
      <li class="fraud-campaign">
        <div class="fraud-campaign__top">
          <span class="fraud-campaign__icon" aria-hidden="true">⚠</span>
          <span class="fraud-campaign__risk fraud-campaign__risk--${risk}">${risk}</span>
        </div>
        <strong>${escapeHtml(c.title || 'Campaign')}</strong>
        <div class="fraud-campaign__meta">
          <span>${c.reportCount || 0} report${(c.reportCount || 0) === 1 ? '' : 's'}</span>
          <span>+${Math.min(c.reportsThisWeek || c.reportCount || 0, 15)} today</span>
        </div>
      </li>`;
    }).join('');
  }

  function getSortedCampaigns() {
    let list = (fraudCampaignsCache || []).slice();
    if (campaignSearchQuery) {
      const q = campaignSearchQuery.toLowerCase();
      list = list.filter((c) =>
        [c.title, c.primaryUrl, c.fraudCategory, c.id]
          .join(' ')
          .toLowerCase()
          .includes(q),
      );
    }
    if (campaignSort === 'reports') {
      list.sort((a, b) => (b.reportCount || 0) - (a.reportCount || 0));
    } else if (campaignSort === 'risk') {
      list.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
    } else {
      list.sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));
    }
    return list;
  }

  function applyCampaignKpis(campaigns) {
    const list = campaigns || [];
    const active = list.length;
    const reports = list.reduce((sum, c) => sum + (c.reportCount || 0), 0);
    const high = list.filter((c) => (c.riskLevel || scoreLevelClass(c.riskScore)) === 'high').length;
    const resolved = list.filter((c) => String(c.status).toLowerCase() === 'resolved' || String(c.status).toLowerCase() === 'closed').length;
    const avg = active ? (reports / active).toFixed(1) : '0';

    if (campKpiActive) campKpiActive.textContent = String(active);
    if (campKpiReports) campKpiReports.textContent = String(reports);
    if (campKpiHigh) campKpiHigh.textContent = String(high);
    if (campKpiResolved) campKpiResolved.textContent = String(resolved);
    if (campKpiAvg) campKpiAvg.textContent = String(avg);
    if (campKpiActiveDelta) campKpiActiveDelta.textContent = active ? `↑ ${active} active` : 'No campaigns';
    if (campKpiReportsDelta) campKpiReportsDelta.textContent = reports ? `↑ ${reports} total reports` : '—';
    if (campKpiHighDelta) campKpiHighDelta.textContent = high ? `↑ ${high} high risk` : 'No high risk';
    if (campKpiResolvedDelta) campKpiResolvedDelta.textContent = resolved ? `↑ ${resolved} resolved` : 'None this week';
    if (campKpiAvgDelta) campKpiAvgDelta.textContent = active ? 'avg reports / campaign' : 'No change';
    if (fraudCampaignsPageBadge) fraudCampaignsPageBadge.textContent = String(active);
  }

  function renderCampaignsPage() {
    applyCampaignKpis(fraudCampaignsCache);
    const list = getSortedCampaigns();
    if (!fraudCampaignPageList) return;

    if (!list.length) {
      fraudCampaignPageList.innerHTML = '<li class="fraud-camp-list__empty">No active campaigns yet.</li>';
      if (fraudCampaignPager) fraudCampaignPager.textContent = 'Showing 0 campaigns';
      if (fraudCampaignDetailEmpty) fraudCampaignDetailEmpty.hidden = false;
      if (fraudCampaignDetailBody) fraudCampaignDetailBody.hidden = true;
      return;
    }

    if (!selectedCampaignId || !list.some((c) => c.id === selectedCampaignId)) {
      selectedCampaignId = list[0].id;
    }

    fraudCampaignPageList.innerHTML = list.map((c) => {
      const risk = c.riskLevel || scoreLevelClass(c.riskScore);
      const url = c.primaryUrl || (c.fraudCategory || 'general').replace(/_/g, ' ');
      return `
        <li>
          <button type="button" class="fraud-camp-card${c.id === selectedCampaignId ? ' fraud-camp-card--active' : ''}" data-campaign-id="${escapeHtml(c.id)}">
            <span class="fraud-camp-card__icon" aria-hidden="true">${c.primaryUrl ? '🌐' : '💬'}</span>
            <div class="fraud-camp-card__body">
              <strong>${escapeHtml(c.title || 'Campaign')}</strong>
              <span dir="ltr">${escapeHtml(url)}</span>
            </div>
            <div class="fraud-camp-card__meta">
              <span class="fraud-campaign__risk fraud-campaign__risk--${risk}">${risk}</span>
              <em>${c.reportCount || 0} reports</em>
            </div>
          </button>
        </li>`;
    }).join('');

    if (fraudCampaignPager) {
      const n = list.length;
      fraudCampaignPager.textContent = `Showing 1 to ${n} of ${n} campaign${n === 1 ? '' : 's'}`;
    }

    fraudCampaignPageList.querySelectorAll('.fraud-camp-card').forEach((btn) => {
      btn.addEventListener('click', () => selectCampaign(btn.dataset.campaignId));
    });

    selectCampaign(selectedCampaignId);
  }

  function formatCampDate(iso) {
    if (!iso) return '\u2014';
    return new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium' }).format(new Date(iso));
  }

  function selectCampaign(id) {
    selectedCampaignId = id;
    const campaign = (fraudCampaignsCache || []).find((c) => c.id === id);
    if (!campaign) return;

    fraudCampaignPageList?.querySelectorAll('.fraud-camp-card').forEach((el) => {
      el.classList.toggle('fraud-camp-card--active', el.dataset.campaignId === id);
    });

    if (fraudCampaignDetailEmpty) fraudCampaignDetailEmpty.hidden = true;
    if (fraudCampaignDetailBody) fraudCampaignDetailBody.hidden = false;

    const risk = campaign.riskLevel || scoreLevelClass(campaign.riskScore);
    if (fraudCampDetailTitle) fraudCampDetailTitle.textContent = campaign.title || 'Campaign';
    if (fraudCampDetailRisk) {
      fraudCampDetailRisk.textContent = `${risk} risk`;
      fraudCampDetailRisk.className = `fraud-campaign__risk fraud-campaign__risk--${risk}`;
    }
    if (fraudCampDetailUrl) fraudCampDetailUrl.textContent = campaign.primaryUrl || 'No primary URL';
    if (fraudCampDetailIcon) fraudCampDetailIcon.textContent = campaign.primaryUrl ? '🌐' : '💬';
    if (fraudCampStatReports) fraudCampStatReports.textContent = String(campaign.reportCount || 0);
    if (fraudCampStatToday) {
      const week = campaign.reportsThisWeek || 0;
      fraudCampStatToday.textContent = week ? `+${week} this week` : '—';
    }
    if (fraudCampStatSenders) fraudCampStatSenders.textContent = String(campaign.uniqueSenders || 0);
    if (fraudCampStatFirst) fraudCampStatFirst.textContent = formatCampDate(campaign.firstSeenAt);
    if (fraudCampStatLast) fraudCampStatLast.textContent = formatCampDate(campaign.lastSeenAt);
    if (fraudCampStatCategory) {
      fraudCampStatCategory.textContent = (campaign.fraudCategory || 'general').replace(/_/g, ' ');
    }
    if (fraudCampDetailDesc) fraudCampDetailDesc.textContent = campaign.description || '—';

    if (fraudCampDetailIocs) {
      const iocs = campaign.iocs || {};
      const items = [];
      (iocs.domains || []).slice(0, 2).forEach((v) => items.push({ type: 'Domain', value: v }));
      (iocs.urls || []).slice(0, 2).forEach((v) => items.push({ type: 'URL', value: v }));
      (iocs.phones || []).slice(0, 2).forEach((v) => items.push({ type: 'Phone', value: v }));
      (iocs.emails || []).slice(0, 2).forEach((v) => items.push({ type: 'Email', value: v }));
      fraudCampDetailIocs.innerHTML = items.length
        ? items.map((i) => `<li><strong>${i.type}</strong>${escapeHtml(i.value)}</li>`).join('')
        : '<li>No IOCs extracted yet.</li>';
    }

    if (fraudCampTrend) {
      const trend = campaign.trend || [0, 0, 0, 0, 0, 0, 0];
      const max = Math.max(...trend, 1);
      fraudCampTrend.innerHTML = trend.map((n) => {
        const h = Math.max(8, Math.round((n / max) * 100));
        return `<div class="fraud-trend__bar" style="height:${h}%" title="${n} reports"></div>`;
      }).join('');
    }

    if (fraudCampRegions) {
      const regions = campaign.regions || [];
      if (!regions.length) {
        fraudCampRegions.innerHTML = '<li class="fraud-bars__empty">No region data.</li>';
      } else {
        const max = Math.max(...regions.map((r) => r.count || 0), 1);
        fraudCampRegions.innerHTML = regions.map((r) => {
          const width = Math.round(((r.count || 0) / max) * 100);
          return `<li class="fraud-bar">
            <span>${escapeHtml(r.name)}</span>
            <div class="fraud-bar__track"><div class="fraud-bar__fill" style="width:${width}%"></div></div>
            <span class="fraud-bar__count">${r.count || 0}</span>
          </li>`;
        }).join('');
      }
    }
  }

  function renderFraudCaseTable() {
    if (!fraudCaseList) return;
    const visible = getVisibleFraudCases();

    if (!visible.length) {
      fraudCaseList.innerHTML = `<tr class="fraud-queue__empty-row" id="fraud-list-empty"><td colspan="9">No reported cases yet. Customer fraud reports appear here.</td></tr>`;
      if (fraudQueuePager) fraudQueuePager.textContent = 'Showing 0 cases';
      if (fraudQueuePages) fraudQueuePages.hidden = true;
      return;
    }

    fraudCaseList.innerHTML = visible.map((c) => {
      const levelClass = scoreLevelClass(c.fraudProbability);
      const date = c.submittedAt
        ? new Date(c.submittedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
        : '\u2014';
      const category = (c.fraudCategory || 'general').replace(/_/g, ' ');
      const source = c.contentType || 'Message';
      const statusClass = statusBadgeClass(c.status);
      const icon = sourceIcon(source);
      const sub = caseSubtitle(c);
      return `
        <tr data-case-id="${escapeHtml(c.id)}" class="${c.id === selectedFraudCaseId ? 'fraud-queue__row--active' : ''}">
          <td><input type="checkbox" class="fraud-row-check" aria-label="Select ${escapeHtml(c.id)}" /></td>
          <td><span class="fraud-queue__type-icon" aria-hidden="true">${icon}</span></td>
          <td>
            <div class="fraud-queue__case-cell">
              <span class="fraud-queue__id">${escapeHtml(c.id)}</span>
              <span class="fraud-queue__case-sub" title="${escapeHtml(sub)}">${escapeHtml(sub)}</span>
            </div>
          </td>
          <td>${escapeHtml(date)}</td>
          <td>${escapeHtml(category)}</td>
          <td><span class="fraud-score-pill fraud-score-pill--${levelClass}">${c.fraudProbability || 0}</span></td>
          <td><span class="fraud-source">${icon} ${escapeHtml(source)}</span></td>
          <td><span class="fraud-status-pill fraud-status-pill--${statusClass}">${escapeHtml(c.status)}</span></td>
          <td><button type="button" class="fraud-open-link" data-case-id="${escapeHtml(c.id)}">View →</button></td>
        </tr>`;
    }).join('');

    const n = visible.length;
    if (fraudQueuePager) {
      fraudQueuePager.textContent = `Showing 1 to ${n} of ${n} case${n === 1 ? '' : 's'}`;
    }
    if (fraudQueuePages) {
      fraudQueuePages.hidden = false;
      fraudQueuePages.innerHTML = `<button type="button" class="fraud-page-btn fraud-page-btn--active">1</button>`;
    }
    if (fraudQueuePageBadge) fraudQueuePageBadge.textContent = String(n);
    if (fraudQueueCount) fraudQueueCount.textContent = String(n);

    fraudCaseList.querySelectorAll('.fraud-open-link').forEach((el) => {
      el.addEventListener('click', () => selectFraudCase(el.dataset.caseId));
    });
  }

  function renderFraudCaseList() {
    renderFraudCaseTable();
  }

  function pct(part, total) {
    if (!total) return 0;
    return Math.round((part / total) * 100);
  }

  function getFilteredAllCases() {
    let list = (allCasesCache.length ? allCasesCache : fraudCasesCache).slice();
    if (allStatus && allStatus !== 'all') {
      list = list.filter((c) => c.status === allStatus);
    }
    if (allCategory && allCategory !== 'all') {
      list = list.filter((c) => (c.fraudCategory || '').toLowerCase() === allCategory.toLowerCase());
    }
    if (allRisk && allRisk !== 'all') {
      list = list.filter((c) => scoreLevelClass(c.fraudProbability) === allRisk);
    }
    if (allSource && allSource !== 'all') {
      list = list.filter((c) => String(c.contentType || '').toLowerCase().includes(allSource.toLowerCase()));
    }
    if (allSearchQuery) {
      const q = allSearchQuery.toLowerCase();
      list = list.filter((c) => {
        const hay = [
          c.id,
          c.preview,
          c.fraudCategory,
          c.contentType,
          c.status,
          ...(c.urls || []),
          ...(c.emails || []),
        ].join(' ').toLowerCase();
        return hay.includes(q);
      });
    }
    return list;
  }

  function applyAllCasesKpis(cases) {
    const list = cases || [];
    const total = list.length;
    const pending = list.filter((c) => c.status === 'Pending Review').length;
    const review = list.filter((c) => c.status === 'Under Review').length;
    const closed = list.filter((c) => c.status === 'Closed').length;
    const hasDecisions = list.some((c) => c.decision);
    const resolvedCount = hasDecisions
      ? list.filter((c) => c.status === 'Closed' && c.decision?.outcome === 'approve').length
      : closed;
    const closedCount = hasDecisions
      ? list.filter((c) => c.status === 'Closed' && c.decision?.outcome !== 'approve').length
      : 0;

    if (allKpiTotal) allKpiTotal.textContent = String(total);
    if (allKpiPending) allKpiPending.textContent = String(pending);
    if (allKpiReview) allKpiReview.textContent = String(review);
    if (allKpiResolved) allKpiResolved.textContent = String(resolvedCount);
    if (allKpiClosed) allKpiClosed.textContent = String(closedCount);
    if (allKpiTotalPct) allKpiTotalPct.textContent = total ? '100%' : '0%';
    if (allKpiPendingPct) allKpiPendingPct.textContent = `${pct(pending, total)}%`;
    if (allKpiReviewPct) allKpiReviewPct.textContent = `${pct(review, total)}%`;
    if (allKpiResolvedPct) allKpiResolvedPct.textContent = `${pct(resolvedCount, total)}%`;
    if (allKpiClosedPct) allKpiClosedPct.textContent = `${pct(closedCount, total)}%`;

    const pendingPct = pct(pending, total);
    const reviewPct = pct(review, total);
    const closedPct = Math.max(0, 100 - pendingPct - reviewPct);
    if (allStatusDonut) {
      allStatusDonut.style.setProperty('--pending', String(pendingPct));
      allStatusDonut.style.setProperty('--review', String(reviewPct));
      allStatusDonut.style.setProperty('--closed', String(total ? closedPct : 100));
    }
    if (allDonutTotal) allDonutTotal.textContent = String(total);
    if (allStatusPendingPct) allStatusPendingPct.textContent = `${pendingPct}%`;
    if (allStatusReviewPct) allStatusReviewPct.textContent = `${reviewPct}%`;
    if (allStatusClosedPct) allStatusClosedPct.textContent = `${closedPct}%`;

    if (allRiskBars) {
      let high = 0;
      let medium = 0;
      let low = 0;
      list.forEach((c) => {
        const level = scoreLevelClass(c.fraudProbability);
        if (level === 'high') high += 1;
        else if (level === 'medium') medium += 1;
        else low += 1;
      });
      const max = Math.max(high, medium, low, 1);
      allRiskBars.innerHTML = [
        { label: 'High (80–100)', count: high },
        { label: 'Medium (50–79)', count: medium },
        { label: 'Low (0–49)', count: low },
      ].map((r) => {
        const width = Math.round((r.count / max) * 100);
        return `<li class="fraud-bar">
          <span>${r.label}</span>
          <div class="fraud-bar__track"><div class="fraud-bar__fill" style="width:${width}%"></div></div>
          <span class="fraud-bar__count">${r.count}</span>
        </li>`;
      }).join('');
    }
  }

  async function renderAllCasesPage() {
    try {
      // Always load unfiltered set for All Cases
      const res = await fetch(getApiUrl('/api/cases'));
      const json = await res.json();
      if (!res.ok || !json.success) throw new Error(json.error || 'Failed to load cases');
      allCasesCache = json.cases || [];
      applyAllCasesKpis(allCasesCache);
      renderAllCasesTable();
    } catch (err) {
      console.error(err);
      if (allCasesList) {
        allCasesList.innerHTML = `<tr class="fraud-queue__empty-row"><td colspan="10">Could not load cases. ${escapeHtml(err.message)}</td></tr>`;
      }
    }
  }

  function renderAllCasesTable() {
    if (!allCasesList) return;
    const visible = getFilteredAllCases();

    if (!visible.length) {
      allCasesList.innerHTML = `<tr class="fraud-queue__empty-row"><td colspan="10">No cases match the current filters.</td></tr>`;
      if (allCasesPager) allCasesPager.textContent = 'Showing 0 cases';
      if (allCasesPages) allCasesPages.hidden = true;
      return;
    }

    allCasesList.innerHTML = visible.map((c) => {
      const levelClass = scoreLevelClass(c.fraudProbability);
      const date = c.submittedAt
        ? new Date(c.submittedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
        : '\u2014';
      const category = (c.fraudCategory || 'general').replace(/_/g, ' ');
      const source = c.contentType || 'Message';
      const statusClass = statusBadgeClass(c.status);
      const icon = sourceIcon(source);
      const sub = caseSubtitle(c);
      const assignee = c.status === 'Under Review' || c.status === 'Closed' ? 'Analyst' : 'Unassigned';
      const initial = assignee === 'Unassigned' ? '?' : 'A';
      return `
        <tr data-case-id="${escapeHtml(c.id)}">
          <td><input type="checkbox" class="all-row-check" aria-label="Select ${escapeHtml(c.id)}" /></td>
          <td><span class="fraud-queue__type-icon" aria-hidden="true">${icon}</span></td>
          <td>
            <div class="fraud-queue__case-cell">
              <span class="fraud-queue__id">${escapeHtml(c.id)}</span>
              <span class="fraud-queue__case-sub" title="${escapeHtml(sub)}">${escapeHtml(sub)}</span>
            </div>
          </td>
          <td>${escapeHtml(date)}</td>
          <td><span class="fraud-category-pill">${escapeHtml(category)}</span></td>
          <td><span class="fraud-score-pill fraud-score-pill--${levelClass}">${c.fraudProbability || 0}</span></td>
          <td><span class="fraud-source">${icon} ${escapeHtml(source)}</span></td>
          <td><span class="fraud-status-pill fraud-status-pill--${statusClass}">${escapeHtml(c.status)}</span></td>
          <td>
            <span class="fraud-assignee">
              <span class="fraud-assignee__avatar">${initial}</span>
              ${escapeHtml(assignee)}
            </span>
          </td>
          <td>
            <button type="button" class="fraud-open-link all-case-open" data-case-id="${escapeHtml(c.id)}">View</button>
            <button type="button" class="fraud-row-menu" data-case-id="${escapeHtml(c.id)}" aria-label="More actions">⋯</button>
          </td>
        </tr>`;
    }).join('');

    const n = visible.length;
    if (allCasesPager) allCasesPager.textContent = `Showing 1 to ${n} of ${n} case${n === 1 ? '' : 's'}`;
    if (allCasesPages) {
      allCasesPages.hidden = false;
      allCasesPages.innerHTML = `<button type="button" class="fraud-page-btn fraud-page-btn--active">1</button>`;
    }

    allCasesList.querySelectorAll('.all-case-open, .fraud-row-menu').forEach((el) => {
      el.addEventListener('click', () => selectFraudCase(el.dataset.caseId));
    });
  }

  function renderIocCards(iocs) {
    if (!fraudDetailIocs) return;
    const groups = [
      { key: 'domains', label: 'Domain' },
      { key: 'urls', label: 'URL' },
      { key: 'emails', label: 'Email' },
      { key: 'phones', label: 'Phone' },
      { key: 'ips', label: 'IP' },
      { key: 'hashes', label: 'Hash' },
    ];

    const cards = [];
    for (const g of groups) {
      for (const value of (iocs?.[g.key] || [])) {
        cards.push(`
          <div class="fraud-ioc">
            <span class="fraud-ioc__type">${g.label}</span>
            <code class="fraud-ioc__value" dir="ltr">${escapeHtml(value)}</code>
            <button type="button" class="fraud-ioc__copy" data-copy="${escapeHtml(value)}">Copy</button>
          </div>`);
      }
    }

    fraudDetailIocs.innerHTML = cards.length
      ? cards.join('')
      : '<p class="fraud-ops__empty">No IOCs extracted.</p>';

    fraudDetailIocs.querySelectorAll('.fraud-ioc__copy').forEach((btn) => {
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.copy || '');
          showToast('Copied');
        } catch {
          showToast('Copy failed');
        }
      });
    });
  }

  async function selectFraudCase(id) {
    selectedFraudCaseId = id;
    fraudCopilotHistory = [];
    if (fraudCopilotMessages) fraudCopilotMessages.innerHTML = '';
    if (fraudModifyPanel) fraudModifyPanel.hidden = true;
    openFraudDrawer();

    try {
      const response = await fetch(getApiUrl(`/api/cases/${encodeURIComponent(id)}`));
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.error || 'Case not found');

      const c = result.case;
      selectedFraudCase = c;
      const inv = c.investigation || {};

      if (fraudDetailEmpty) fraudDetailEmpty.hidden = true;
      if (fraudDetailBody) fraudDetailBody.hidden = false;

      if (fraudDetailId) fraudDetailId.textContent = c.id;
      if (fraudDetailTitle) {
        fraudDetailTitle.textContent = (inv.aiInvestigationSummary || c.aiExplanation || c.fraudCategory || c.id)
          .toString()
          .slice(0, 120);
      }
      if (fraudDetailTime) {
        fraudDetailTime.textContent = c.submittedAt
          ? new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(c.submittedAt))
          : '\u2014';
      }
      if (fraudDetailStatus) {
        fraudDetailStatus.textContent = c.status;
        fraudDetailStatus.className = `fraud-badge fraud-badge--${statusBadgeClass(c.status)}`;
      }
      if (fraudDetailType) fraudDetailType.textContent = (c.fraudCategory || '\u2014').replace(/_/g, ' ');
      if (fraudDetailScore) fraudDetailScore.textContent = `${c.fraudProbability || 0}/100`;
      if (fraudDetailRisk) fraudDetailRisk.textContent = `${c.fraudProbability || 0}%`;
      if (fraudDetailThreat) fraudDetailThreat.textContent = c.contentType || '\u2014';
      if (fraudDetailSummary) fraudDetailSummary.textContent = inv.aiInvestigationSummary || c.aiExplanation || '\u2014';
      if (fraudDetailEvidence) fraudDetailEvidence.textContent = c.content || '\u2014';

      if (fraudDetailScreenshotWrap && fraudDetailScreenshot) {
        if (c.screenshotDataUrl) {
          fraudDetailScreenshot.src = c.screenshotDataUrl;
          fraudDetailScreenshotWrap.hidden = false;
        } else {
          fraudDetailScreenshot.removeAttribute('src');
          fraudDetailScreenshotWrap.hidden = true;
        }
      }

      renderIocCards(c.iocs || {});

      if (fraudRecAction) fraudRecAction.textContent = inv.recommendation?.action || '\u2014';
      if (fraudRecRationale) fraudRecRationale.textContent = inv.recommendation?.rationale || '\u2014';
      if (fraudRecConfidence) {
        fraudRecConfidence.textContent = inv.recommendation?.confidence != null
          ? `Confidence ${inv.recommendation.confidence}%`
          : '';
      }

      if (fraudDocExecutive) fraudDocExecutive.textContent = inv.executiveInvestigationSummary || '\u2014';
      if (fraudDocTechnical) fraudDocTechnical.textContent = inv.technicalInvestigationSummary || '\u2014';
      if (fraudDocCustomer) fraudDocCustomer.textContent = inv.customerNotificationDraft || '\u2014';
      if (fraudDocManagement) fraudDocManagement.textContent = inv.managementSummary || '\u2014';
      if (fraudDocNotes) {
        const notes = inv.investigationNotes || [];
        fraudDocNotes.innerHTML = notes.length
          ? notes.map((n) => `<li>${escapeHtml(n)}</li>`).join('')
          : '<li>\u2014</li>';
      }

      const closed = c.status === 'Closed';
      applyFraudDecisionButtons(c.decision, closed);

      try {
        const statsRes = await fetch(getApiUrl('/api/cases'));
        const statsJson = await statsRes.json();
        if (statsJson.success && statsJson.stats) {
          applyFraudKpis(statsJson.stats, fraudCasesCache);
        }
        const cached = fraudCasesCache.find((x) => x.id === id);
        if (cached) cached.status = c.status;
        renderFraudCaseTable();
      } catch {
        /* ignore */
      }
    } catch (err) {
      console.error(err);
      showToast(err.message || 'Failed to open case');
    }
  }

  async function submitFraudDecision(outcome, action, analystNote) {
    if (!selectedFraudCaseId) return;

    const triggerBtn = outcome === 'approve'
      ? btnFraudApprove
      : outcome === 'reject'
        ? btnFraudReject
        : btnFraudModifySave;
    const loadingLabels = {
      approve: 'Approving…',
      reject: 'Rejecting…',
      modify: 'Saving…',
    };

    if (triggerBtn) {
      triggerBtn.classList.add('btn--decision-loading', 'btn--decision-pop');
      triggerBtn.textContent = loadingLabels[outcome] || 'Saving…';
      triggerBtn.disabled = true;
    }
    [btnFraudApprove, btnFraudModify, btnFraudReject].forEach((btn) => {
      if (btn && btn !== triggerBtn) btn.disabled = true;
    });

    try {
      const response = await fetch(getApiUrl(`/api/cases/${encodeURIComponent(selectedFraudCaseId)}/decision`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ outcome, action, analystNote }),
      });
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.error || 'Decision failed');
      showToast(`Decision saved: ${outcome}`);
      if (fraudModifyPanel) fraudModifyPanel.hidden = true;
      await selectFraudCase(selectedFraudCaseId);
    } catch (err) {
      console.error(err);
      showToast(err.message || 'Could not save decision');
      applyFraudDecisionButtons(selectedFraudCase?.decision, selectedFraudCase?.status === 'Closed');
    } finally {
      triggerBtn?.classList.remove('btn--decision-loading', 'btn--decision-pop');
    }
  }

  function applyFraudDecisionButtons(decision, closed) {
    const config = [
      {
        el: btnFraudApprove,
        outcome: 'approve',
        defaultLabel: 'Approve',
        chosenLabel: 'Approved ✓',
        chosenClass: 'btn--decision-approved',
      },
      {
        el: btnFraudModify,
        outcome: 'modify',
        defaultLabel: 'Modify',
        chosenLabel: 'Modified ✓',
        chosenClass: 'btn--decision-modified',
      },
      {
        el: btnFraudReject,
        outcome: 'reject',
        defaultLabel: 'Reject',
        chosenLabel: 'Rejected ✓',
        chosenClass: 'btn--decision-rejected',
      },
    ];

    config.forEach(({ el, outcome, defaultLabel, chosenLabel, chosenClass }) => {
      if (!el) return;
      el.classList.remove(
        'btn--decision-approved',
        'btn--decision-modified',
        'btn--decision-rejected',
        'btn--decision-loading',
        'btn--decision-muted',
        'btn--decision-pop',
      );
      const chosen = decision?.outcome === outcome;
      el.textContent = chosen ? chosenLabel : defaultLabel;
      el.disabled = closed;
      el.setAttribute('aria-pressed', chosen ? 'true' : 'false');
      if (chosen) {
        el.classList.add(chosenClass);
      } else if (decision && closed) {
        el.classList.add('btn--decision-muted');
      }
    });
  }

  function appendCopilotMessage(role, text) {
    if (!fraudCopilotMessages) return;
    const div = document.createElement('div');
    div.className = `fraud-copilot__msg fraud-copilot__msg--${role}`;
    div.textContent = text;
    fraudCopilotMessages.appendChild(div);
    fraudCopilotMessages.scrollTop = fraudCopilotMessages.scrollHeight;
  }

  async function askFraudCopilot(question) {
    if (!selectedFraudCaseId || !question) return;
    appendCopilotMessage('user', question);
    fraudCopilotHistory.push({ role: 'user', content: question });
    appendCopilotMessage('assistant', 'Thinking\u2026');

    try {
      const response = await fetch(getApiUrl(`/api/cases/${encodeURIComponent(selectedFraudCaseId)}/copilot`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: fraudCopilotHistory }),
      });
      const result = await response.json();
      if (!response.ok || !result.success) throw new Error(result.error || 'Copilot failed');

      fraudCopilotHistory.push({ role: 'assistant', content: result.reply });
      if (fraudCopilotMessages?.lastChild) {
        fraudCopilotMessages.lastChild.textContent = result.reply;
      }
    } catch (err) {
      console.error(err);
      if (fraudCopilotMessages?.lastChild) {
        fraudCopilotMessages.lastChild.textContent = err.message || 'Copilot unavailable';
      }
    }
  }

  // Wire fraud ops events
  function completeFraudLogin(remember) {
    setFraudAuth(true, remember);
    if (fraudLoginError) fraudLoginError.hidden = true;
    enterFraudOpsDashboard();
    showToast('Signed in to Fraud Ops');
  }

  if (fraudLoginForm) {
    fraudLoginForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const user = fraudLoginUser?.value?.trim() || '';
      const pass = fraudLoginPass?.value || '';
      if (!user || !pass) {
        if (fraudLoginError) {
          fraudLoginError.textContent = 'Please enter your username and password.';
          fraudLoginError.hidden = false;
        }
        return;
      }
      completeFraudLogin(!!fraudLoginRemember?.checked);
    });
  }

  if (fraudLoginSso) {
    fraudLoginSso.addEventListener('click', () => {
      completeFraudLogin(!!fraudLoginRemember?.checked);
    });
  }

  if (fraudLoginTogglePass && fraudLoginPass) {
    fraudLoginTogglePass.addEventListener('click', () => {
      const show = fraudLoginPass.type === 'password';
      fraudLoginPass.type = show ? 'text' : 'password';
      fraudLoginTogglePass.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  }

  if (fraudLoginForgot) {
    fraudLoginForgot.addEventListener('click', () => {
      showToast('Contact your bank admin to reset Fraud Ops access');
    });
  }

  if (btnFraudLogout) {
    btnFraudLogout.addEventListener('click', () => {
      setFraudAuth(false, false);
      if (fraudLoginUser) fraudLoginUser.value = '';
      if (fraudLoginPass) fraudLoginPass.value = '';
      showFraudLogin();
      showToast('Signed out');
    });
  }

  if (btnFraudRefresh) {
    btnFraudRefresh.addEventListener('click', () => {
      renderFraudOpsDashboard();
      showToast('Fraud queue refreshed');
    });
  }

  if (btnFraudCloseDrawer) {
    btnFraudCloseDrawer.addEventListener('click', () => closeFraudDrawer());
  }
  if (fraudDrawerBackdrop) {
    fraudDrawerBackdrop.addEventListener('click', () => closeFraudDrawer());
  }

  if (btnFraudOpenCopilot) {
    btnFraudOpenCopilot.addEventListener('click', () => {
      if (selectedFraudCaseId) {
        openFraudDrawer();
        document.getElementById('fraud-copilot-section')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        fraudCopilotInput?.focus();
      } else if (fraudCasesCache.length) {
        selectFraudCase(fraudCasesCache[0].id).then(() => {
          document.getElementById('fraud-copilot-section')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
          fraudCopilotInput?.focus();
        });
      } else {
        showToast('Open a case first to use Copilot');
        scrollFraudSection('queue');
      }
    });
  }

  if (btnFraudExport) {
    btnFraudExport.addEventListener('click', () => {
      const rows = [
        ['Case ID', 'Status', 'Category', 'Risk', 'Submitted', 'Source'],
        ...fraudCasesCache.map((c) => [
          c.id,
          c.status,
          c.fraudCategory || '',
          String(c.fraudProbability || 0),
          c.submittedAt || '',
          c.contentType || '',
        ]),
      ];
      const csv = rows.map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `byteshield-fraud-cases-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Case report exported');
    });
  }

  document.querySelectorAll('[data-fraud-nav]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const nav = btn.dataset.fraudNav;
      const filterNav = btn.dataset.fraudFilterNav;

      // All Cases page (must run before filterNav handling)
      if (nav === 'all') {
        allStatus = 'all';
        allCategory = 'all';
        allRisk = 'all';
        allSource = 'all';
        allSearchQuery = '';
        if (allStatusFilter) allStatusFilter.value = 'all';
        if (allCategoryFilter) allCategoryFilter.value = 'all';
        if (allRiskFilter) allRiskFilter.value = 'all';
        if (allSourceFilter) allSourceFilter.value = 'all';
        if (allCasesSearch) allCasesSearch.value = '';
        scrollFraudSection('all');
        return;
      }

      if (filterNav) {
        fraudFilter = filterNav;
        fraudQuickFilter = null;
        if (fraudStatusFilter) fraudStatusFilter.value = filterNav;
        document.querySelectorAll('.fraud-filter').forEach((b) => {
          b.classList.toggle('fraud-filter--active', b.dataset.fraudFilter === fraudFilter);
        });
        switchFraudView('queue');
        if (filterNav === 'Under Review') setActiveFraudNav('review');
        else if (filterNav === 'Pending Review') setActiveFraudNav('pending');
        else setActiveFraudNav('queue');
        renderFraudOpsDashboard();
        return;
      }
      scrollFraudSection(nav);
    });
  });

  document.querySelectorAll('[data-fraud-quick]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const q = btn.dataset.fraudQuick;
      document.querySelectorAll('[data-fraud-quick]').forEach((b) => {
        b.classList.toggle('fraud-quick-filter--active', b === btn);
      });
      if (q === 'high') {
        fraudQuickFilter = 'high';
        fraudFilter = 'all';
        if (fraudStatusFilter) fraudStatusFilter.value = 'all';
      } else if (q === 'review') {
        fraudQuickFilter = null;
        fraudFilter = 'Under Review';
        if (fraudStatusFilter) fraudStatusFilter.value = 'Under Review';
      } else if (q === 'pending') {
        fraudQuickFilter = null;
        fraudFilter = 'Pending Review';
        if (fraudStatusFilter) fraudStatusFilter.value = 'Pending Review';
      } else {
        fraudQuickFilter = null;
        fraudFilter = 'all';
        if (fraudStatusFilter) fraudStatusFilter.value = 'all';
      }
      document.querySelectorAll('.fraud-filter').forEach((b) => {
        b.classList.toggle('fraud-filter--active', b.dataset.fraudFilter === fraudFilter);
      });
      switchFraudView('queue');
      setActiveFraudNav('queue');
      renderFraudOpsDashboard();
    });
  });

  if (fraudStatusFilter) {
    fraudStatusFilter.addEventListener('change', () => {
      fraudFilter = fraudStatusFilter.value || 'all';
      fraudQuickFilter = null;
      document.querySelectorAll('.fraud-filter').forEach((b) => {
        b.classList.toggle('fraud-filter--active', b.dataset.fraudFilter === fraudFilter);
      });
      document.querySelectorAll('[data-fraud-quick]').forEach((b) => b.classList.remove('fraud-quick-filter--active'));
      renderFraudOpsDashboard();
    });
  }

  if (btnFraudBackServices) {
    btnFraudBackServices.addEventListener('click', () => {
      document.getElementById('close-byteshield')?.click();
    });
  }

  if (btnFraudCampaignsRefresh) {
    btnFraudCampaignsRefresh.addEventListener('click', async () => {
      await renderFraudOpsDashboard();
      renderCampaignsPage();
      showToast('Campaigns refreshed');
    });
  }

  if (fraudCampaignSearch) {
    let campSearchTimer = null;
    fraudCampaignSearch.addEventListener('input', () => {
      clearTimeout(campSearchTimer);
      campSearchTimer = setTimeout(() => {
        campaignSearchQuery = fraudCampaignSearch.value.trim();
        renderCampaignsPage();
      }, 200);
    });
  }

  if (fraudCampaignSort) {
    fraudCampaignSort.addEventListener('change', () => {
      campaignSort = fraudCampaignSort.value || 'newest';
      renderCampaignsPage();
    });
  }

  if (btnFraudCampViewCases) {
    btnFraudCampViewCases.addEventListener('click', () => {
      switchFraudView('queue');
      setActiveFraudNav('queue');
      showToast('Showing case queue — filter by campaign cases as needed');
    });
  }

  if (btnFraudAllRefresh) {
    btnFraudAllRefresh.addEventListener('click', async () => {
      await renderAllCasesPage();
      showToast('All cases refreshed');
    });
  }

  if (allCasesSearch) {
    let allSearchTimer = null;
    allCasesSearch.addEventListener('input', () => {
      clearTimeout(allSearchTimer);
      allSearchTimer = setTimeout(() => {
        allSearchQuery = allCasesSearch.value.trim();
        renderAllCasesTable();
      }, 200);
    });
  }

  function refreshAllFiltersFromControls() {
    allStatus = allStatusFilter?.value || 'all';
    allCategory = allCategoryFilter?.value || 'all';
    allRisk = allRiskFilter?.value || 'all';
    allSource = allSourceFilter?.value || 'all';
    renderAllCasesTable();
  }

  [allStatusFilter, allCategoryFilter, allRiskFilter, allSourceFilter].forEach((el) => {
    el?.addEventListener('change', refreshAllFiltersFromControls);
  });

  if (allSelectAll) {
    allSelectAll.addEventListener('change', () => {
      allCasesList?.querySelectorAll('.all-row-check').forEach((cb) => {
        cb.checked = allSelectAll.checked;
      });
    });
  }

  if (btnAllAdvancedSearch) {
    btnAllAdvancedSearch.addEventListener('click', () => {
      allCasesSearch?.focus();
      showToast('Use the search and filters above');
    });
  }

  if (btnAllExport) {
    btnAllExport.addEventListener('click', () => {
      const rows = [
        ['Case ID', 'Status', 'Category', 'Risk', 'Submitted', 'Source'],
        ...getFilteredAllCases().map((c) => [
          c.id,
          c.status,
          c.fraudCategory || '',
          String(c.fraudProbability || 0),
          c.submittedAt || '',
          c.contentType || '',
        ]),
      ];
      const csv = rows.map((r) => r.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `byteshield-all-cases-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Cases exported');
    });
  }

  if (btnAllBulk) {
    btnAllBulk.addEventListener('click', () => showToast('Select cases with checkboxes, then use View to update'));
  }
  if (btnAllPlaybook) {
    btnAllPlaybook.addEventListener('click', () => showToast('Playbook builder coming soon'));
  }

  if (fraudSelectAll) {
    fraudSelectAll.addEventListener('change', () => {
      fraudCaseList?.querySelectorAll('.fraud-row-check').forEach((cb) => {
        cb.checked = fraudSelectAll.checked;
      });
    });
  }

  if (btnFraudApprove) {
    btnFraudApprove.addEventListener('click', () => {
      btnFraudApprove.classList.add('btn--decision-pop');
      window.setTimeout(() => btnFraudApprove.classList.remove('btn--decision-pop'), 350);
      const action = selectedFraudCase?.investigation?.recommendation?.action || 'Continue Monitoring';
      submitFraudDecision('approve', action, '');
    });
  }

  if (btnFraudReject) {
    btnFraudReject.addEventListener('click', () => {
      submitFraudDecision('reject', 'False Positive', 'Analyst rejected AI recommendation');
    });
  }

  if (btnFraudModify) {
    btnFraudModify.addEventListener('click', () => {
      if (fraudModifyPanel) fraudModifyPanel.hidden = !fraudModifyPanel.hidden;
      if (fraudModifyAction && selectedFraudCase?.investigation?.recommendation?.action) {
        fraudModifyAction.value = selectedFraudCase.investigation.recommendation.action;
      }
    });
  }

  if (btnFraudModifySave) {
    btnFraudModifySave.addEventListener('click', () => {
      submitFraudDecision(
        'modify',
        fraudModifyAction?.value || 'Continue Monitoring',
        fraudModifyNote?.value || '',
      );
    });
  }

  if (fraudCopilotForm) {
    fraudCopilotForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const q = fraudCopilotInput?.value?.trim();
      if (!q) return;
      fraudCopilotInput.value = '';
      askFraudCopilot(q);
    });
  }

  document.querySelectorAll('.fraud-filter').forEach((btn) => {
    btn.addEventListener('click', () => {
      fraudFilter = btn.dataset.fraudFilter;
      document.querySelectorAll('.fraud-filter').forEach((b) => {
        b.classList.toggle('fraud-filter--active', b.dataset.fraudFilter === fraudFilter);
      });
      renderFraudOpsDashboard();
    });
  });

  if (fraudSearch) {
    let searchTimer = null;
    fraudSearch.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => {
        fraudSearchQuery = fraudSearch.value.trim();
        renderFraudOpsDashboard();
      }, 250);
    });
  }

  if (fraudCategoryFilter) {
    fraudCategoryFilter.addEventListener('change', () => {
      fraudCategory = fraudCategoryFilter.value;
      renderFraudOpsDashboard();
    });
  }

  renderFraudOpsDashboard();
  updateScanInputForMode(activeMode);
})();
