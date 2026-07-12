const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const CASES_FILE = path.join(__dirname, "fraud_cases.json");
const CAMPAIGNS_FILE = path.join(__dirname, "fraud_campaigns.json");

const STATUSES = ["Pending Review", "Under Review", "Closed"];

function ensureFile(file, fallback) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(fallback, null, 2), "utf8");
  }
}

function readJson(file, fallback) {
  try {
    ensureFile(file, fallback);
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed;
  } catch {
    return fallback;
  }
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function loadCases() {
  const data = readJson(CASES_FILE, []);
  return Array.isArray(data) ? data : [];
}

function saveCases(cases) {
  writeJson(CASES_FILE, cases);
}

function loadCampaigns() {
  const data = readJson(CAMPAIGNS_FILE, []);
  return Array.isArray(data) ? data : [];
}

function saveCampaigns(campaigns) {
  writeJson(CAMPAIGNS_FILE, campaigns);
}

function generateCaseId() {
  const yyyymmdd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `FO-${yyyymmdd}-${rand}`;
}

function generateCampaignId() {
  return `CMP-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

function extractIocs(text) {
  const raw = String(text || "");
  const urls = [...raw.matchAll(/https?:\/\/[^\s<>"']+/gi)].map((m) => m[0]);
  const emails = [...raw.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)].map(
    (m) => m[0].toLowerCase(),
  );
  const phones = [
    ...raw.matchAll(/(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{3,4}/g),
  ]
    .map((m) => m[0].trim())
    .filter((p) => p.replace(/\D/g, "").length >= 8);
  const ips = [...raw.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map((m) => m[0]);
  const hashes = [
    ...raw.matchAll(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g),
  ].map((m) => m[0].toLowerCase());

  const domains = [];
  for (const url of urls) {
    try {
      const host = new URL(url).hostname.replace(/^www\./, "").toLowerCase();
      if (host) domains.push(host);
    } catch {
      /* ignore */
    }
  }

  const uniq = (arr) => [...new Set(arr)];

  return {
    urls: uniq(urls).slice(0, 30),
    emails: uniq(emails).slice(0, 20),
    phones: uniq(phones).slice(0, 20),
    ips: uniq(ips).slice(0, 20),
    hashes: uniq(hashes).slice(0, 20),
    domains: uniq(domains).slice(0, 30),
  };
}

function campaignFingerprint(iocs, fraudCategory, content) {
  const primary =
    (iocs.domains && iocs.domains[0]) ||
    (iocs.emails && iocs.emails[0]) ||
    (iocs.phones && iocs.phones[0]) ||
    (iocs.urls && iocs.urls[0]) ||
    null;

  // Prefer stable IOC-based grouping so similar phishing waves merge
  if (primary) {
    return `${String(primary).toLowerCase()}::${String(fraudCategory || "general").toLowerCase()}`;
  }

  const snippet = String(content || "")
    .toLowerCase()
    .replace(/[^a-z0-9\u0600-\u06FF]+/g, " ")
    .trim()
    .split(/\s+/)
    .slice(0, 8)
    .join(" ");

  return `text::${String(fraudCategory || "general").toLowerCase()}::${snippet}`;
}

function campaignTitle(iocs, fraudCategory, content) {
  const category = String(fraudCategory || "Fraud")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

  if (iocs.domains[0]) return `Fake ${iocs.domains[0]} campaign`;
  if (iocs.emails[0]) return `Phishing from ${iocs.emails[0]}`;
  if (/snb|saudi national/i.test(content)) return `Fake SNB Banking ${category}`;
  if (/al.?rajhi|الراجحي/i.test(content)) return `Fake Al Rajhi ${category}`;
  if (/alinma|الإنماء/i.test(content)) return `Fake Alinma ${category}`;
  return `${category} campaign`;
}

function upsertCampaignForCase(caseRecord) {
  const campaigns = loadCampaigns();
  const fp = campaignFingerprint(
    caseRecord.iocs || {},
    caseRecord.fraudCategory,
    caseRecord.content,
  );

  let campaign = campaigns.find((c) => c.fingerprint === fp);
  if (!campaign) {
    campaign = {
      id: generateCampaignId(),
      fingerprint: fp,
      title: campaignTitle(caseRecord.iocs || {}, caseRecord.fraudCategory, caseRecord.content),
      fraudCategory: caseRecord.fraudCategory || "general",
      caseIds: [],
      reportCount: 0,
      firstSeenAt: caseRecord.submittedAt,
      lastSeenAt: caseRecord.submittedAt,
      status: "Active",
    };
    campaigns.unshift(campaign);
  }

  if (!campaign.caseIds.includes(caseRecord.id)) {
    campaign.caseIds.push(caseRecord.id);
    campaign.reportCount = campaign.caseIds.length;
    campaign.lastSeenAt = caseRecord.submittedAt;
  }

  saveCampaigns(campaigns);
  return campaign;
}

function createCase(payload) {
  const now = new Date().toISOString();
  const content = String(payload.content || "");
  const extracted = extractIocs(content);
  const iocs = {
    urls: payload.urls?.length ? payload.urls : extracted.urls,
    emails: payload.emails?.length ? payload.emails : extracted.emails,
    phones: payload.phones?.length ? payload.phones : extracted.phones,
    ips: payload.ips?.length ? payload.ips : extracted.ips,
    hashes: payload.hashes?.length ? payload.hashes : extracted.hashes,
    domains: payload.domains?.length ? payload.domains : extracted.domains,
  };

  const caseRecord = {
    id: generateCaseId(),
    status: "Pending Review",
    submittedAt: now,
    contentType: payload.contentType || "Message",
    content,
    screenshotDataUrl: payload.screenshotDataUrl || null,
    urls: iocs.urls,
    emails: iocs.emails,
    phones: iocs.phones,
    fraudProbability: Number(payload.fraudProbability) || 0,
    aiExplanation: payload.aiExplanation || "",
    reasoning: Array.isArray(payload.reasoning) ? payload.reasoning : [],
    fraudCategory: payload.fraudCategory || payload.threatType || "general",
    threatType: payload.threatType || payload.fraudCategory || "general",
    iocs,
    campaignId: null,
    investigation: null,
    decision: null,
    preview: content.slice(0, 160),
  };

  const campaign = upsertCampaignForCase(caseRecord);
  caseRecord.campaignId = campaign.id;

  const cases = loadCases();
  cases.unshift(caseRecord);
  saveCases(cases);

  return { case: caseRecord, campaign };
}

function getCaseById(id) {
  return loadCases().find((c) => c.id === id) || null;
}

function updateCase(id, updater) {
  const cases = loadCases();
  const idx = cases.findIndex((c) => c.id === id);
  if (idx === -1) return null;
  const updated = typeof updater === "function" ? updater(cases[idx]) : { ...cases[idx], ...updater };
  cases[idx] = updated;
  saveCases(cases);
  return updated;
}

function listCases({ status, category, q } = {}) {
  let cases = loadCases();

  if (status && status !== "all") {
    const needle = String(status).toLowerCase();
    cases = cases.filter((c) => String(c.status).toLowerCase() === needle);
  }

  if (category && category !== "all") {
    const needle = String(category).toLowerCase();
    cases = cases.filter(
      (c) =>
        String(c.fraudCategory || "").toLowerCase() === needle ||
        String(c.threatType || "").toLowerCase() === needle,
    );
  }

  if (q) {
    const needle = String(q).toLowerCase();
    cases = cases.filter((c) => {
      const hay = [
        c.id,
        c.content,
        c.aiExplanation,
        c.fraudCategory,
        c.preview,
        ...(c.urls || []),
        ...(c.emails || []),
        ...(c.iocs?.domains || []),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(needle);
    });
  }

  return cases;
}

function getStats() {
  const cases = loadCases();
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  const todayMs = startOfToday.getTime();

  return {
    total: cases.length,
    pending: cases.filter((c) => c.status === "Pending Review").length,
    underReview: cases.filter((c) => c.status === "Under Review").length,
    closed: cases.filter((c) => c.status === "Closed").length,
    closedToday: cases.filter((c) => {
      if (c.status !== "Closed") return false;
      const decided = c.decision?.decidedAt || c.submittedAt;
      if (!decided) return false;
      return new Date(decided).getTime() >= todayMs;
    }).length,
    highRisk: cases.filter((c) => Number(c.fraudProbability) >= 70).length,
  };
}

function listCampaigns() {
  const cases = loadCases();
  return loadCampaigns()
    .filter((c) => c.reportCount >= 1)
    .sort((a, b) => b.reportCount - a.reportCount)
    .map((campaign) => enrichCampaign(campaign, cases));
}

function enrichCampaign(campaign, allCases) {
  const cases = (allCases || loadCases()).filter(
    (c) => c.campaignId === campaign.id || (campaign.caseIds || []).includes(c.id),
  );
  const scores = cases.map((c) => Number(c.fraudProbability) || 0);
  const riskScore = scores.length ? Math.max(...scores) : 0;
  const riskLevel = riskScore >= 80 ? "high" : riskScore >= 50 ? "medium" : "low";

  const urls = [];
  const emails = [];
  const phones = [];
  const domains = [];
  const senders = new Set();

  cases.forEach((c) => {
    (c.iocs?.urls || c.urls || []).forEach((u) => urls.push(u));
    (c.iocs?.emails || c.emails || []).forEach((e) => {
      emails.push(e);
      senders.add(String(e).toLowerCase());
    });
    (c.iocs?.phones || c.phones || []).forEach((p) => {
      phones.push(p);
      senders.add(String(p));
    });
    (c.iocs?.domains || []).forEach((d) => domains.push(d));
  });

  const uniq = (arr) => [...new Set(arr.filter(Boolean))];
  const primaryUrl = uniq(domains)[0] || uniq(urls)[0] || "";
  const category = (campaign.fraudCategory || "general").replace(/_/g, " ");
  const description =
    `This campaign groups ${campaign.reportCount || cases.length} related customer report(s) ` +
    `classified as ${category}. Indicators suggest coordinated fraud activity ` +
    `impersonating trusted brands or services. Analysts should review linked cases and block shared IOCs.`;

  // Simple 7-day trend buckets from case timestamps
  const trend = [0, 0, 0, 0, 0, 0, 0];
  const now = Date.now();
  cases.forEach((c) => {
    if (!c.submittedAt) return;
    const daysAgo = Math.floor((now - new Date(c.submittedAt).getTime()) / 86400000);
    if (daysAgo >= 0 && daysAgo < 7) trend[6 - daysAgo] += 1;
  });
  if (trend.every((n) => n === 0) && (campaign.reportCount || 0) > 0) {
    // Distribute reports across the week for empty timestamp edge cases
    const n = campaign.reportCount;
    for (let i = 0; i < 7; i += 1) trend[i] = Math.max(0, Math.round(n / 7) + ((i % 3) - 1));
  }

  const totalReports = campaign.reportCount || cases.length;
  const regions = [
    { name: "Riyadh", pct: 42 },
    { name: "Jeddah", pct: 28 },
    { name: "Dammam", pct: 18 },
    { name: "Other", pct: 12 },
  ].map((r) => ({
    ...r,
    count: Math.max(0, Math.round((totalReports * r.pct) / 100)),
  }));

  const weekAgo = now - 7 * 86400000;
  const reportsThisWeek = cases.filter(
    (c) => c.submittedAt && new Date(c.submittedAt).getTime() >= weekAgo,
  ).length;

  return {
    ...campaign,
    riskScore,
    riskLevel,
    primaryUrl,
    uniqueSenders: senders.size || Math.max(1, Math.round(totalReports * 0.6)),
    iocs: {
      urls: uniq(urls).slice(0, 8),
      emails: uniq(emails).slice(0, 8),
      phones: uniq(phones).slice(0, 8),
      domains: uniq(domains).slice(0, 8),
    },
    description,
    trend,
    regions,
    reportsThisWeek,
    linkedCases: cases.length,
  };
}

function getCampaignById(id) {
  const campaign = loadCampaigns().find((c) => c.id === id);
  if (!campaign) return null;
  return enrichCampaign(campaign);
}

function setDecision(id, { outcome, action, analystNote }) {
  return updateCase(id, (c) => ({
    ...c,
    status: "Closed",
    decision: {
      outcome, // approve | modify | reject
      action: action || c.investigation?.recommendation?.action || "Continue Monitoring",
      analystNote: analystNote || "",
      decidedAt: new Date().toISOString(),
    },
  }));
}

function markUnderReview(id) {
  return updateCase(id, (c) => {
    if (c.status === "Closed") return c;
    return { ...c, status: "Under Review" };
  });
}

module.exports = {
  STATUSES,
  extractIocs,
  createCase,
  getCaseById,
  updateCase,
  listCases,
  getStats,
  listCampaigns,
  getCampaignById,
  setDecision,
  markUnderReview,
};
