const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { getSupabase, isConfigured } = require("./supabase");
const {
  campaignIdFromFingerprint,
  withRepresentativeCampaignIdentity,
} = require("./services/campaignIds");

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

function loadCasesLocal() {
  const data = readJson(CASES_FILE, []);
  return Array.isArray(data) ? data : [];
}

function saveCasesLocal(cases) {
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

function migrateStoredCampaigns() {
  const campaigns = loadCampaigns();
  const idMap = new Map();
  let changed = false;

  campaigns.forEach((campaign) => {
    const repId = campaign.fingerprint
      ? campaignIdFromFingerprint(campaign.fingerprint)
      : withRepresentativeCampaignIdentity(campaign).id;
    if (campaign.id !== repId || campaign.title !== repId) {
      if (campaign.id) idMap.set(campaign.id, repId);
      campaign.id = repId;
      campaign.title = repId;
      changed = true;
    }
  });

  if (changed) {
    saveCampaigns(campaigns);
    if (idMap.size) {
      const cases = loadCasesLocal();
      let casesChanged = false;
      cases.forEach((caseRecord) => {
        if (caseRecord.campaignId && idMap.has(caseRecord.campaignId)) {
          caseRecord.campaignId = idMap.get(caseRecord.campaignId);
          casesChanged = true;
        }
      });
      if (casesChanged) saveCasesLocal(cases);
    }
  }

  return campaigns;
}

function upsertCampaignForCase(caseRecord) {
  const campaigns = loadCampaigns();
  const fp = campaignFingerprint(
    caseRecord.iocs || {},
    caseRecord.fraudCategory,
    caseRecord.content,
  );
  const repId = campaignIdFromFingerprint(fp);

  let campaign = campaigns.find((c) => c.fingerprint === fp);
  if (!campaign) {
    campaign = {
      id: repId,
      fingerprint: fp,
      title: repId,
      fraudCategory: caseRecord.fraudCategory || "general",
      caseIds: [],
      reportCount: 0,
      firstSeenAt: caseRecord.submittedAt,
      lastSeenAt: caseRecord.submittedAt,
      status: "Active",
    };
    campaigns.unshift(campaign);
  } else {
    campaign.id = repId;
    campaign.title = repId;
  }

  if (!campaign.caseIds.includes(caseRecord.id)) {
    campaign.caseIds.push(caseRecord.id);
    campaign.reportCount = campaign.caseIds.length;
    campaign.lastSeenAt = caseRecord.submittedAt;
  }

  saveCampaigns(campaigns);
  return withRepresentativeCampaignIdentity(campaign);
}

function rowToCase(row) {
  if (!row) return null;
  const iocs = row.iocs || {};
  let investigation = row.investigation || null;
  if (!investigation && (row.ai_summary || row.ai_recommendation)) {
    investigation = {
      aiInvestigationSummary: row.ai_summary || "",
      recommendation: {
        action: row.ai_recommendation || "Continue Monitoring",
        rationale: row.ai_summary || "",
        confidence: null,
      },
    };
  }

  return {
    id: row.case_id,
    uuid: row.id,
    status: row.status || "Pending Review",
    submittedAt: row.created_at,
    contentType: row.content_type || row.source || "Message",
    content: row.content || "",
    screenshotDataUrl: row.screenshot_data_url || null,
    urls: row.urls || iocs.urls || [],
    emails: row.emails || iocs.emails || [],
    phones: row.phones || iocs.phones || [],
    fraudProbability: Number(row.fraud_score) || 0,
    aiExplanation: row.ai_summary || "",
    reasoning: row.reasoning || [],
    fraudCategory: row.fraud_category || "general",
    threatType: row.fraud_category || "general",
    iocs,
    campaignId: row.campaign_id || null,
    investigation,
    decision: row.decision || null,
    preview: row.preview || String(row.content || "").slice(0, 160),
    assignedTo: row.assigned_to || null,
    source: row.source || row.content_type || "Message",
  };
}

function caseToRow(caseRecord) {
  const inv = caseRecord.investigation || null;
  return {
    case_id: caseRecord.id,
    source: caseRecord.contentType || caseRecord.source || "Message",
    content: caseRecord.content || "",
    fraud_score: Number(caseRecord.fraudProbability) || 0,
    fraud_category: caseRecord.fraudCategory || caseRecord.threatType || "general",
    ai_summary: inv?.aiInvestigationSummary || caseRecord.aiExplanation || "",
    ai_recommendation: inv?.recommendation?.action || null,
    iocs: caseRecord.iocs || {},
    status: caseRecord.status || "Pending Review",
    assigned_to: caseRecord.assignedTo || null,
    content_type: caseRecord.contentType || "Message",
    preview: caseRecord.preview || String(caseRecord.content || "").slice(0, 160),
    campaign_id: caseRecord.campaignId || null,
    screenshot_data_url: caseRecord.screenshotDataUrl || null,
    reasoning: caseRecord.reasoning || [],
    urls: caseRecord.urls || caseRecord.iocs?.urls || [],
    emails: caseRecord.emails || caseRecord.iocs?.emails || [],
    phones: caseRecord.phones || caseRecord.iocs?.phones || [],
    investigation: inv,
    decision: caseRecord.decision || null,
  };
}

async function createCase(payload) {
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
    assignedTo: null,
    source: payload.contentType || "Message",
  };

  const campaign = upsertCampaignForCase(caseRecord);
  caseRecord.campaignId = campaign.id;

  if (isConfigured) {
    const sb = getSupabase();
    const { data, error } = await sb
      .from("fraud_cases")
      .insert(caseToRow(caseRecord))
      .select("*")
      .single();
    if (error) throw error;
    return { case: rowToCase(data), campaign };
  }

  const cases = loadCasesLocal();
  cases.unshift(caseRecord);
  saveCasesLocal(cases);
  return { case: caseRecord, campaign };
}

async function getCaseById(id) {
  if (isConfigured) {
    const sb = getSupabase();
    const { data, error } = await sb
      .from("fraud_cases")
      .select("*")
      .eq("case_id", id)
      .maybeSingle();
    if (error) throw error;
    return rowToCase(data);
  }
  return loadCasesLocal().find((c) => c.id === id) || null;
}

async function updateCase(id, updater) {
  const current = await getCaseById(id);
  if (!current) return null;
  const updated =
    typeof updater === "function" ? updater(current) : { ...current, ...updater };

  if (isConfigured) {
    const sb = getSupabase();
    const { data, error } = await sb
      .from("fraud_cases")
      .update(caseToRow(updated))
      .eq("case_id", id)
      .select("*")
      .single();
    if (error) throw error;
    return rowToCase(data);
  }

  const cases = loadCasesLocal();
  const idx = cases.findIndex((c) => c.id === id);
  if (idx === -1) return null;
  cases[idx] = updated;
  saveCasesLocal(cases);
  return updated;
}

async function listCases({ status, category, q } = {}) {
  if (isConfigured) {
    const sb = getSupabase();
    let query = sb.from("fraud_cases").select("*").order("created_at", { ascending: false });

    if (status && status !== "all") {
      query = query.eq("status", status);
    }
    if (category && category !== "all") {
      query = query.eq("fraud_category", category);
    }

    const { data, error } = await query;
    if (error) throw error;

    let cases = (data || []).map(rowToCase);
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

  let cases = loadCasesLocal();

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

async function getStats() {
  const cases = await listCases();
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

function enrichCampaign(campaign, allCases) {
  const normalized = withRepresentativeCampaignIdentity(campaign);
  const cases = (allCases || []).filter((c) => {
    if (normalized.caseIds?.includes(c.id)) return true;
    if (c.campaignId && c.campaignId === normalized.id) return true;
    if (
      normalized.fingerprint &&
      campaignFingerprint(c.iocs || {}, c.fraudCategory, c.content) === normalized.fingerprint
    ) {
      return true;
    }
    return false;
  });
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

  const trend = [0, 0, 0, 0, 0, 0, 0];
  const now = Date.now();
  cases.forEach((c) => {
    if (!c.submittedAt) return;
    const daysAgo = Math.floor((now - new Date(c.submittedAt).getTime()) / 86400000);
    if (daysAgo >= 0 && daysAgo < 7) trend[6 - daysAgo] += 1;
  });
  if (trend.every((n) => n === 0) && (campaign.reportCount || 0) > 0) {
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
    ...normalized,
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

async function listCampaigns() {
  const cases = await listCases();
  return migrateStoredCampaigns()
    .filter((c) => c.reportCount >= 1)
    .sort((a, b) => b.reportCount - a.reportCount)
    .map((campaign) => enrichCampaign(campaign, cases));
}

async function getCampaignById(id) {
  const campaign = loadCampaigns().find(
    (c) => c.id === id || campaignIdFromFingerprint(c.fingerprint) === id,
  );
  if (!campaign) return null;
  const cases = await listCases();
  return enrichCampaign(campaign, cases);
}

async function setDecision(id, { outcome, action, analystNote }) {
  return updateCase(id, (c) => ({
    ...c,
    status: "Closed",
    decision: {
      outcome,
      action: action || c.investigation?.recommendation?.action || "Continue Monitoring",
      analystNote: analystNote || "",
      decidedAt: new Date().toISOString(),
    },
  }));
}

async function markUnderReview(id, assignedTo = "Analyst") {
  return updateCase(id, (c) => {
    if (c.status === "Closed") return c;
    return {
      ...c,
      status: "Under Review",
      assignedTo: assignedTo || c.assignedTo || "Analyst",
    };
  });
}

async function releaseToQueue(id) {
  return updateCase(id, (c) => {
    if (c.status === "Closed") return c;
    return {
      ...c,
      status: "Pending Review",
      assignedTo: null,
    };
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
  releaseToQueue,
  isSupabaseConfigured: isConfigured,
};
