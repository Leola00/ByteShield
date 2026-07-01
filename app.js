(function () {
  'use strict';

  const SAMPLE_SCAM = `URGENT: Your bank account has been suspended due to suspicious activity. Verify your identity immediately or your funds will be frozen within 24 hours.

Click here to confirm: http://secure-bank-verify.xyz/login

Reply with your OTP code if you received one. Do NOT call the bank — this is faster.`;

  const RING_CIRCUMFERENCE = 327;

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

  openByteshield.addEventListener('click', () => {
    alinmaPage.hidden = true;
    byteshieldPanel.hidden = false;
    document.body.style.overflow = 'hidden';
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
    if (!file.type.startsWith('image/')) {
      showToast('يرجى رفع ملف صورة');
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
    if (score < 35) return { level: 'منخفض', class: 'low', verdict: 'يبدو آمناً نسبياً — تحقق دائماً بشكل مستقل' };
    if (score < 65) return { level: 'متوسط', class: 'medium', verdict: 'مشبوه — توخَّ الحذر قبل أي إجراء' };
    return { level: 'مرتفع', class: 'high', verdict: 'احتيال أو تصيد محتمل — لا تتفاعل' };
  }

  function getRecommendations(score, type) {
    const recs = [];
    if (score >= 65) {
      recs.push('لا تنقر على أي روابط ولا ترد على الرسالة');
      recs.push('لا تشارك كلمات المرور أو رموز OTP أو بيانات الدفع');
      recs.push('تواصل مع الجهة مباشرة عبر موقعها أو تطبيق الإنماء الرسمي');
      recs.push('أبلغ البنك أو الجهات المختصة بالجرائم الإلكترونية');
    } else if (score >= 35) {
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
    if (score >= 65) {
      parts.push('عدة مؤشرات تطابق حملات احتيال مالي وتصيد معروفة. الجمع بين الاستعجال وطلب البيانات والروابط المشبوهة إشارة قوية على احتيال.');
    } else if (score >= 35) {
      parts.push('بعض الأنماط تشبه الهندسة الاجتماعية. الجهات الموثوقة نادراً ما تضغط عليك للتصرف فوراً عبر رسائل غير مطلوبة.');
    } else {
      parts.push('لم تُرصد أنماط تصيد رئيسية، لكن الهندسة الاجتماعية قد تكون خفية. ثق بحدسك إذا شعرت بأي شيء غريب.');
    }
    return parts.join(' ');
  }

  async function runAnalysis() {
    const input = getInputContent();

    if (activeTab === 'screenshot') {
      if (!input.hasImage) {
        showToast('يرجى رفع لقطة شاشة أولاً');
        return;
      }
    } else if (!input.text) {
      showToast('يرجى إدخال محتوى للتحليل');
      return;
    }

    btnScan.classList.add('scanning');
    btnScan.textContent = 'جاري التحليل…';

    try {
      if (activeTab === 'screenshot') {
        const analysis = analyzeScreenshot();
        const { level, class: levelClass, verdict } = scoreToLevel(analysis.score);
        const recommendations = getRecommendations(analysis.score, input.type);
        const explanation = analysis.explanation || buildExplanation(input.text, analysis.flags, analysis.score, input.type);
        renderResults(analysis.score, level, levelClass, verdict, analysis.flags, recommendations, explanation);
        return;
      }

      const response = await fetch('http://localhost:3000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: input.text }),
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        const message = result.error || 'فشل التحليل — تأكد من تشغيل الخادم';
        if (message.includes('429') || message.toLowerCase().includes('quota')) {
          showToast('تم تجاوز حد Gemini المجاني — انتظر دقيقة وحاول مجدداً');
        } else {
          showToast(message);
        }
        return;
      }

      const ai = result.data;
      const score = Number(ai.riskScore) || 0;
      const flags = Array.isArray(ai.reasons) ? ai.reasons : [];
      const classification = String(ai.classification || '').toLowerCase();

      let level;
      let levelClass;
      let verdict;

      if (classification.includes('high') || score >= 65) {
        level = 'مرتفع';
        levelClass = 'high';
        verdict = 'احتيال أو تصيد محتمل — لا تتفاعل';
      } else if (classification.includes('medium') || score >= 35) {
        level = 'متوسط';
        levelClass = 'medium';
        verdict = 'مشبوه — توخَّ الحذر قبل أي إجراء';
      } else {
        level = 'منخفض';
        levelClass = 'low';
        verdict = 'يبدو آمناً نسبياً — تحقق دائماً بشكل مستقل';
      }

      const recommendations = ai.recommendation
        ? [ai.recommendation, ...getRecommendations(score, input.type)]
        : getRecommendations(score, input.type);

      const explanation = buildExplanation(input.text, flags, score, input.type);

      renderResults(score, level, levelClass, verdict, flags, recommendations, explanation);
    } catch (error) {
      console.error(error);
      showToast('تعذر الاتصال بالخادم — شغّل الباكند أولاً (node server.js)');
    } finally {
      btnScan.classList.remove('scanning');
      btnScan.textContent = 'تشغيل التحليل الأمني';
    }
  }

  function renderResults(score, level, levelClass, verdict, flags, recommendations, explanation) {
    resultsPlaceholder.hidden = true;
    results.hidden = false;

    document.getElementById('results-time').textContent = new Date().toLocaleString('ar-SA');
    document.getElementById('risk-score').textContent = score;

    const ring = document.getElementById('risk-ring');
    ring.className = 'risk-gauge__fill risk-gauge__fill--' + levelClass;
    ring.style.strokeDashoffset = RING_CIRCUMFERENCE - (score / 100) * RING_CIRCUMFERENCE;

    const badge = document.getElementById('risk-level');
    badge.textContent = 'خطر ' + level;
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
