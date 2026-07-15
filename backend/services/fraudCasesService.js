/**
 * Fraud cases data access — Supabase `fraud_cases` table.
 * Uses only core columns that exist in the live table:
 * id, case_id, source, content, fraud_score, fraud_category,
 * ai_summary, ai_recommendation, iocs, status, assigned_to,
 * internal_notes, created_at
 *
 * Extra UI fields (investigation, decision, etc.) are stored in iocs._meta
 */
const crypto = require("crypto");
const { getSupabase, isConfigured } = require("../supabase");

function generateCaseId() {
  const yyyymmdd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `FO-${yyyymmdd}-${rand}`;
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

  return {
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
  };
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
  if (updates.reviewed_by !== undefined) patch.reviewed_by = updates.reviewed_by;
  if (updates.reviewedBy !== undefined) patch.reviewed_by = updates.reviewedBy;
  if (updates.reviewed_at !== undefined) patch.reviewed_at = updates.reviewed_at;
  if (updates.reviewedAt !== undefined) patch.reviewed_at = updates.reviewedAt;
  if (updates.decision !== undefined && typeof updates.decision === "string") {
    patch.decision = updates.decision;
  }
  if (updates.decision_payload !== undefined) patch.decision_payload = updates.decision_payload;
  if (updates.decisionPayload !== undefined) patch.decision_payload = updates.decisionPayload;

  const needsMeta =
    updates.investigation !== undefined ||
    updates.decision !== undefined ||
    updates.screenshotDataUrl !== undefined;

  if (needsMeta) {
    const existing = await sb
      .from("fraud_cases")
      .select("iocs")
      .eq("case_id", current.id)
      .maybeSingle();
    const packed = parseIocs(existing.data?.iocs);
    const meta = { ...(packed._meta || {}) };
    if (updates.investigation !== undefined) meta.investigation = updates.investigation;
    if (updates.decision !== undefined) meta.decision = updates.decision;
    if (updates.screenshotDataUrl !== undefined) {
      meta.screenshotDataUrl = updates.screenshotDataUrl;
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
  if (error) throw error;
  if (!data) {
    const err = new Error("Case not found");
    err.status = 404;
    throw err;
  }
  return mapRow(data);
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
    decision: normalized,
    decision_payload: decisionPayload,
    decisionPayload,
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
