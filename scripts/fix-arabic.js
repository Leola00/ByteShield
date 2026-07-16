const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const old = execSync('git show 354c89e:app.js', { encoding: 'utf8', cwd: root });
let cur = fs.readFileSync(path.join(root, 'app.js'), 'utf8');

function extract(src, name) {
  const i = src.indexOf(name);
  if (i < 0) return null;
  let depth = 0;
  let started = false;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') {
      depth += 1;
      started = true;
    } else if (src[j] === '}') {
      depth -= 1;
      if (started && depth === 0) return src.slice(i, j + 1);
    }
  }
  return null;
}

const replacements = [
  ['function analyzeText', 'function analyzeUrl'],
  ['function analyzeUrl', 'function analyzeScreenshot'],
  ['function analyzeScreenshot', 'function scoreToLevel'],
  ['function scoreToLevel', 'function getRecommendations'],
  ['function getRecommendations', 'function buildExplanation'],
  ['function buildExplanation', 'function buildLocalReport'],
  ['function buildLocalReport', 'function isOpenAiKeyError'],
];

for (const [start, end] of replacements) {
  const block = extract(old, start);
  if (!block) {
    console.warn('Missing block:', start);
    continue;
  }
  const startIdx = cur.indexOf(start);
  const endIdx = cur.indexOf(end);
  if (startIdx < 0 || endIdx < 0) {
    console.warn('Anchor not found:', start, end);
    continue;
  }
  cur = cur.slice(0, startIdx) + block + '\n\n  ' + cur.slice(endIdx);
}

const fixes = [
  ["showToast('???? ??????? ? ByteShield ???? ????? ??????');", "showToast('هذه الخدمة في ByteShield — افتح بطاقة فحص الاحتيال');"],
  ["text: screenshotFile ? `[???: ${screenshotFile.name}]` : ''", "text: screenshotFile ? `[ملف: ${screenshotFile.name}]` : ''"],
  ["if (levelEl) levelEl.textContent = `????? ??????: ${forecast.forecastLevel || '?'}`;", "if (levelEl) levelEl.textContent = `مستوى التوقع: ${forecast.forecastLevel || '—'}`;"],
  ["'?? ???? ????? ????'", "'لا يلزم إجراء فوري'"],
  ["'????? ????? ?????'", "'توخَّ الحذر وتحقق'"],
  ["'??????? ????? ??????'", "'إجراءات عاجلة مطلوبة'"],
  ["'?? ????? ?????? ?????'", "'لم تُرصد مؤشرات واضحة'"],
  ["'?????? ??????'", "'مؤشرات منخفضة'"],
  ["'?????? ??????'", "'مؤشرات متوسطة'"],
  ["'?????? ??????'", "'مؤشرات مرتفعة'"],
  ["`${indicatorCount} ? ${warnText}`", "`${indicatorCount} — ${warnText}`"],
  [": '<li>?? ????? ?????? ???? ?????</li>'", ": '<li>لا تُرصد مؤشرات خطر واضحة</li>'"],
  ["appendChatMessage('bot', '??????! ??? ByteShield AI.", "appendChatMessage('bot', 'مرحباً! أنا ByteShield AI."],
  ["const typing = appendChatMessage('bot', '???? ????????');", "const typing = appendChatMessage('bot', 'جاري الكتابة…');"],
  ["showToast('???? ??????? ????????');", "showToast('تعذر الاتصال بالمساعد');"],
  ["showToast(result.error || '??? ???????');", "showToast(result.error || 'فشل الإرسال');"],
  ["`???????: ${text}`", "`الرسالة: ${text}`"],
  ["`???? ?????: ${report.score}/100`", "`درجة الخطر: ${report.score}/100`"],
  ["`??????: ${report.tier.statusAr}`", "`الحالة: ${report.tier.statusAr}`"],
  ["`?????: ${report.shortExplanation}`", "`الشرح: ${report.shortExplanation}`"],
  ["`???????: ${report.reasoning.join('? ')}`", "`الأسباب: ${report.reasoning.join('؛ ')}`"],
  ["`????????: ${report.actionChecklist.join('? ')}`", "`التوصيات: ${report.actionChecklist.join('؛ ')}`"],
  ["title.textContent = `??????? ${detectedBanks[0]}`;", "title.textContent = `إرشادات ${detectedBanks[0]}`;"],
  ["title.textContent = '??????? ??????';", "title.textContent = 'إرشادات أمنية';"],
  ["tipsList.innerHTML = tips.slice(0, 5).map((t) => `<li><span>???</span>${escapeHtml(t)}</li>`).join('');", "tipsList.innerHTML = tips.slice(0, 5).map((t) => `<li><span>•</span>${escapeHtml(t)}</li>`).join('');"],
  ["<li><span>???</span>", "<li><span>•</span>"],
  ["btnScan.textContent = '\\u0628\\u062f\\u0621 \\u0627\\u0644\\u062a\\u062d\\u0644\\u064a\\u0644 \\u0627\\u0644\\u0623\\u0645\\u0646\\u064a';", "btnScan.textContent = '🛡️ بدء التحليل الأمني';"],
];

for (const [from, to] of fixes) {
  if (cur.includes(from)) cur = cur.split(from).join(to);
}

fs.writeFileSync(path.join(root, 'app.js'), cur, 'utf8');
console.log('Arabic strings restored');
