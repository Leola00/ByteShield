/**
 * Fraud cases data access — Supabase `fraud_cases` table.
 * Uses only core columns that exist in the live table:
 * id, case_id, source, content, fraud_score, fraud_category,
 * ai_summary, ai_recommendation, iocs, status, assigned_to,
 * internal_notes, created_at
 *
 * Extra UI fields (investigation, decision, etc.) are stored in iocs._meta
 *
 * If Supabase UPDATE fails (e.g. missing updated_at trigger column),
 * decision/status patches are kept in a local override file so Approve/Reject still work.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { getSupabase, isConfigured } = require("../supabase");

const OVERRIDES_PATH = path.join(__dirname, "..", "data", "case-overrides.json");

function generateCaseId() {
  const yyyymmdd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `FO-${yyyymmdd}-${rand}`;
}

function readOverrides() {
  try {
    if (!fs.existsSync(OVERRIDES_PATH)) return {};
    return JSON.parse(fs.readFileSync(OVERRIDES_PATH, "utf8") || "{}");
  } catch {
    return {};
  }
}

function writeOverride(caseId, patch) {
  const all = readOverrides();
  all[caseId] = {
    ...(all[caseId] || {}),
    ...patch,
    updatedAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(OVERRIDES_PATH), { recursive: true });
  fs.writeFileSync(OVERRIDES_PATH, JSON.stringify(all, null, 2), "utf8");
  return all[caseId];
}

function applyOverrideToCase(mapped) {
  if (!mapped?.id) return mapped;
  const ov = readOverrides()[mapped.id];
  if (!ov) return mapped;

  const dbStatus = mapped.status || "Pending Review";
  const hasExplicitAssignment =
    ov.explicitTake === true || ov.decision || ov.reviewedAt || ov.reviewedBy;
  const next = { ...mapped };

  if (ov.investigation) next.investigation = ov.investigation;
  if (ov.decision && typeof ov.decision === "object") {
    next.decision = ov.decision;
    next.decisionLabel = ov.decision.outcome || ov.decisionLabel;
  }
  if (ov.screenshotDataUrl) next.screenshotDataUrl = ov.screenshotDataUrl;
  if (ov.aiSummary) {
    next.aiSummary = ov.aiSummary;
    next.aiExplanation = ov.aiSummary;
  }
  if (ov.aiRecommendation) next.aiRecommendation = ov.aiRecommendation;

  // Stale local overrides from old auto-assign-on-view must not pull cases into My Reviews.
  if (dbStatus === "Pending Review" && !hasExplicitAssignment) {
    next.status = dbStatus;
    next.assignedTo = mapped.assignedTo ?? null;
    next.reviewedBy = mapped.reviewedBy ?? null;
    next.reviewedAt = mapped.reviewedAt ?? null;
    return next;
  }

  if (ov.status) next.status = ov.status;
  if (ov.assignedTo !== undefined) next.assignedTo = ov.assignedTo;
  if (ov.reviewedBy !== undefined) next.reviewedBy = ov.reviewedBy;
  if (ov.reviewedAt !== undefined) next.reviewedAt = ov.reviewedAt;
  return next;
}

function parseIocs(value) {
  if (!value) return { _meta: {} };
  if (typeof value === "object") {
    return { ...value, _meta: value._meta && typeof value._meta === "object" ? value._meta : {} };
  }
  try {
    const parsed = JSON.parse(value);
    return {
      ...parsed,
      _meta: parsed._meta && typeof parsed._meta === "object" ? parsed._meta : {},
    };
  } catch {
    return { _meta: {} };
  }
}

function publicIocs(iocs) {
  const copy = { ...(iocs || {}) };
  delete copy._meta;
  return copy;
}

/** Supabase row → API / UI case object */
function mapRow(row) {
  if (!row) return null;
  const packed = parseIocs(row.iocs);
  const meta = packed._meta || {};
  const iocs = publicIocs(packed);

  let investigation = meta.investigation || null;
  if (!investigation && (row.ai_summary || row.ai_recommendation)) {
    investigation = {
      aiInvestigationSummary: row.ai_summary || "",
      recommendation: {
        action: row.ai_recommendation || "Continue Monitoring",
        rationale: row.ai_summary || "",
        confidence: null,
      },
      investigationNotes: row.internal_notes ? [String(row.internal_notes)] : [],
    };
  }

  return applyOverrideToCase({
    id: row.case_id,
    uuid: row.id,
    caseId: row.case_id,
    status: row.status || "Pending Review",
    submittedAt: row.created_at,
    createdAt: row.created_at,
    contentType: row.source || meta.contentType || "Message",
    source: row.source || meta.contentType || "Message",
    content: row.content || "",
    screenshotDataUrl: meta.screenshotDataUrl || null,
    urls: meta.urls || iocs.urls || [],
    emails: meta.emails || iocs.emails || [],
    phones: meta.phones || iocs.phones || [],
    fraudProbability: Number(row.fraud_score) || 0,
    fraudScore: Number(row.fraud_score) || 0,
    aiExplanation: row.ai_summary || "",
    aiSummary: row.ai_summary || "",
    aiRecommendation: row.ai_recommendation || null,
    reasoning: meta.reasoning || [],
    fraudCategory: row.fraud_category || "general",
    threatType: row.fraud_category || "general",
    iocs,
    campaignId: meta.campaignId || null,
    investigation,
    decision: row.decision_payload || meta.decision || (row.decision ? { outcome: row.decision } : null),
    decisionLabel: row.decision || meta.decision?.outcome || null,
    preview: meta.preview || String(row.content || "").slice(0, 160),
    assignedTo: row.assigned_to || null,
    internalNotes: row.internal_notes || null,
    reviewedBy: row.reviewed_by || null,
    reviewedAt: row.reviewed_at || null,
  });
}

function buildInsertPayload(input = {}) {
  const content = String(input.content || "").trim();
  const caseId = input.case_id || input.caseId || generateCaseId();
  const source = input.source || input.contentType || "Message";
  const score = Number(input.fraud_score ?? input.fraudScore ?? input.fraudProbability ?? 0) || 0;
  const category = input.fraud_category || input.fraudCategory || input.threatType || "general";
  const baseIocs = input.iocs && typeof input.iocs === "object" ? { ...input.iocs } : {};
  delete baseIocs._meta;

  const meta = {
    contentType: source,
    preview: content.slice(0, 160),
    campaignId: input.campaign_id || input.campaignId || null,
    screenshotDataUrl: input.screenshot_data_url || input.screenshotDataUrl || null,
    reasoning: Array.isArray(input.reasoning) ? input.reasoning : [],
    urls: input.urls || baseIocs.urls || [],
    emails: input.emails || baseIocs.emails || [],
    phones: input.phones || baseIocs.phones || [],
    investigation: input.investigation || null,
    decision: input.decision || null,
  };

  return {
    case_id: caseId,
    source,
    content,
    fraud_score: score,
    fraud_category: category,
    ai_summary: input.ai_summary || input.aiSummary || input.aiExplanation || "",
    ai_recommendation:
      input.ai_recommendation ||
      input.aiRecommendation ||
      input.recommendation ||
      null,
    iocs: { ...baseIocs, _meta: meta },
    status: input.status || "Pending Review",
    assigned_to: input.assigned_to || input.assignedTo || null,
    internal_notes: input.internal_notes || input.internalNotes || null,
  };
}

async function assertSupabase() {
  if (!isConfigured) {
    throw new Error(
      "Supabase is not configured. Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to backend/.env",
    );
  }
  return getSupabase();
}

async function createReport(input) {
  const sb = await assertSupabase();
  const payload = buildInsertPayload(input);
  if (!payload.content) {
    const err = new Error("content is required");
    err.status = 400;
    throw err;
  }

  const { data, error } = await sb.from("fraud_cases").insert(payload).select("*").single();
  if (error) throw error;
  return mapRow(data);
}

async function listAllCases({ status, category, q } = {}) {
  const sb = await assertSupabase();
  let query = sb.from("fraud_cases").select("*").order("created_at", { ascending: false });

  if (status && status !== "all") query = query.eq("status", status);
  if (category && category !== "all") query = query.eq("fraud_category", category);

  const { data, error } = await query;
  if (error) throw error;

  let cases = (data || []).map(mapRow);
  if (q) {
    const needle = String(q).toLowerCase();
    cases = cases.filter((c) =>
      [c.id, c.content, c.aiSummary, c.fraudCategory, c.preview, c.assignedTo]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }
  return cases;
}

async function getCaseByIdOrCaseId(id) {
  const sb = await assertSupabase();
  const isUuid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      String(id),
    );

  let query = sb.from("fraud_cases").select("*");
  query = isUuid ? query.eq("id", id) : query.eq("case_id", id);

  const { data, error } = await query.maybeSingle();
  if (error) throw error;
  return mapRow(data);
}

async function patchCase(id, updates = {}) {
  const sb = await assertSupabase();
  const current = await getCaseByIdOrCaseId(id);
  if (!current) {
    const err = new Error("Case not found");
    err.status = 404;
    throw err;
  }

  // Only touch columns that exist on the live fraud_cases table.
  // Decision / review / investigation live in iocs._meta (and local overrides as backup).
  const patch = {};
  if (updates.status !== undefined) patch.status = updates.status;
  if (updates.assigned_to !== undefined) patch.assigned_to = updates.assigned_to;
  if (updates.assignedTo !== undefined) patch.assigned_to = updates.assignedTo;
  if (updates.internal_notes !== undefined) patch.internal_notes = updates.internal_notes;
  if (updates.internalNotes !== undefined) patch.internal_notes = updates.internalNotes;
  if (updates.ai_summary !== undefined) patch.ai_summary = updates.ai_summary;
  if (updates.ai_recommendation !== undefined) {
    patch.ai_recommendation = updates.ai_recommendation;
  }

  const decisionMeta =
    typeof updates.decision === "string"
      ? updates.decisionPayload || updates.decision_payload || { outcome: updates.decision }
      : updates.decision;

  const needsMeta =
    updates.investigation !== undefined ||
    decisionMeta !== undefined ||
    updates.screenshotDataUrl !== undefined ||
    updates.reviewedBy !== undefined ||
    updates.reviewed_by !== undefined ||
    updates.reviewedAt !== undefined ||
    updates.reviewed_at !== undefined;

  if (needsMeta) {
    const existing = await sb
      .from("fraud_cases")
      .select("iocs")
      .eq("case_id", current.id)
      .maybeSingle();
    const packed = parseIocs(existing.data?.iocs);
    const meta = { ...(packed._meta || {}) };
    if (updates.investigation !== undefined) meta.investigation = updates.investigation;
    if (decisionMeta !== undefined) meta.decision = decisionMeta;
    if (updates.screenshotDataUrl !== undefined) {
      meta.screenshotDataUrl = updates.screenshotDataUrl;
    }
    if (updates.reviewedBy !== undefined || updates.reviewed_by !== undefined) {
      meta.reviewedBy = updates.reviewedBy || updates.reviewed_by;
    }
    if (updates.reviewedAt !== undefined || updates.reviewed_at !== undefined) {
      meta.reviewedAt = updates.reviewedAt || updates.reviewed_at;
    }
    packed._meta = meta;
    patch.iocs = packed;
  }

  if (!Object.keys(patch).length) {
    const err = new Error("No valid fields to update");
    err.status = 400;
    throw err;
  }

  const isUuid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      String(id),
    );

  let query = sb.from("fraud_cases").update(patch).select("*");
  query = isUuid ? query.eq("id", id) : query.eq("case_id", id);

  const { data, error } = await query.maybeSingle();
  if (!error && data) return mapRow(data);

  // Live DB often has a trigger on updated_at without the column — any UPDATE fails.
  // Fall back to local overrides so Approve / Modify / Reject still work.
  const msg = error?.message || "Update failed";
  console.warn("Supabase patch failed, using local override:", msg);

  const overridePatch = {
    status: patch.status !== undefined ? patch.status : current.status,
    assignedTo:
      patch.assigned_to !== undefined ? patch.assigned_to : current.assignedTo,
    reviewedBy:
      updates.reviewedBy || updates.reviewed_by || current.reviewedBy || null,
    reviewedAt:
      updates.reviewedAt || updates.reviewed_at || current.reviewedAt || null,
  };
  if (updates.investigation !== undefined) {
    overridePatch.investigation = updates.investigation;
  }
  if (patch.status === "Under Review") {
    overridePatch.explicitTake = true;
  }
  if (patch.status === "Pending Review") {
    overridePatch.explicitTake = false;
    overridePatch.assignedTo = null;
  }
  if (decisionMeta !== undefined) {
    overridePatch.decision = decisionMeta;
    overridePatch.decisionLabel = decisionMeta.outcome || null;
  }
  if (updates.ai_summary !== undefined) overridePatch.aiSummary = updates.ai_summary;
  if (updates.ai_recommendation !== undefined) {
    overridePatch.aiRecommendation = updates.ai_recommendation;
  }
  if (patch.iocs) {
    const meta = parseIocs(patch.iocs)._meta || {};
    if (meta.investigation) overridePatch.investigation = meta.investigation;
    if (meta.decision) {
      overridePatch.decision = meta.decision;
      overridePatch.decisionLabel = meta.decision.outcome || null;
    }
    if (meta.screenshotDataUrl) {
      overridePatch.screenshotDataUrl = meta.screenshotDataUrl;
    }
  }

  writeOverride(current.id, overridePatch);
  return applyOverrideToCase({ ...current, ...overridePatch });
}

function computeStats(cases) {
  const list = cases || [];
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  const todayMs = startOfToday.getTime();

  return {
    total: list.length,
    pending: list.filter((c) => c.status === "Pending Review").length,
    underReview: list.filter((c) => c.status === "Under Review").length,
    closed: list.filter((c) => c.status === "Closed").length,
    closedToday: list.filter((c) => {
      if (c.status !== "Closed") return false;
      const decided = c.reviewedAt || c.decision?.decidedAt || c.submittedAt;
      return decided && new Date(decided).getTime() >= todayMs;
    }).length,
    highRisk: list.filter((c) => Number(c.fraudProbability) >= 70).length,
    falsePositives: list.filter(
      (c) => c.status === "Closed" && (c.decision?.outcome === "reject" || c.decisionLabel === "reject"),
    ).length,
    approved: list.filter(
      (c) => c.status === "Closed" && (c.decision?.outcome === "approve" || c.decisionLabel === "approve"),
    ).length,
  };
}

/**
 * Apply operator action: approve | reject | escalate | close | modify
 */
async function applyCaseAction(id, { outcome, action, analystNote, reviewedBy, assignedTo } = {}) {
  const normalized = String(outcome || "").toLowerCase();
  const now = new Date().toISOString();
  const decisionPayload = {
    outcome: normalized,
    action: action || "",
    analystNote: analystNote || "",
    decidedAt: now,
    reviewedBy: reviewedBy || assignedTo || "Analyst",
  };

  let status = "Closed";
  if (normalized === "escalate") {
    status = "Under Review";
  } else if (normalized === "close") {
    status = "Closed";
  } else if (["approve", "reject", "modify"].includes(normalized)) {
    status = "Closed";
  }

  return patchCase(id, {
    status,
    assigned_to: assignedTo || reviewedBy || undefined,
    reviewed_by: reviewedBy || assignedTo || null,
    reviewed_at: now,
    decision: decisionPayload,
  });
}

module.exports = {
  isConfigured,
  generateCaseId,
  mapRow,
  buildInsertPayload,
  createReport,
  listAllCases,
  getCaseByIdOrCaseId,
  patchCase,
  computeStats,
  applyCaseAction,
};
