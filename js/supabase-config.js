/**
 * Frontend Supabase configuration for ByteShield.
 * Expects window.__BYTESHIELD_SUPABASE__ from /js/supabase-env.js
 * (injected by the Express server from backend/.env).
 */
(function (global) {
  "use strict";

  var cfg = global.__BYTESHIELD_SUPABASE__ || {};
  var url = cfg.url || "";
  var anonKey = cfg.anonKey || "";
  var client = null;

  function isConfigured() {
    return Boolean(url && anonKey && global.supabase && typeof global.supabase.createClient === "function");
  }

  function getClient() {
    if (!isConfigured()) return null;
    if (!client) {
      client = global.supabase.createClient(url, anonKey, {
        auth: { persistSession: false, autoRefreshToken: false },
      });
    }
    return client;
  }

  /**
   * Map a fraud_cases row to the shape the existing Fraud Ops UI expects.
   */
  function mapCaseRow(row) {
    if (!row) return null;
    var iocs = row.iocs || {};
    var investigation = row.investigation || null;
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
      iocs: iocs,
      campaignId: row.campaign_id || null,
      investigation: investigation,
      decision: row.decision || null,
      preview: row.preview || String(row.content || "").slice(0, 160),
      assignedTo: row.assigned_to || null,
      aiRecommendation: row.ai_recommendation || null,
      source: row.source || row.content_type || "Message",
    };
  }

  async function listCases(filters) {
    var sb = getClient();
    if (!sb) throw new Error("Supabase is not configured");

    filters = filters || {};
    var query = sb.from("fraud_cases").select("*").order("created_at", { ascending: false });

    if (filters.status && filters.status !== "all") {
      query = query.eq("status", filters.status);
    }
    if (filters.category && filters.category !== "all") {
      query = query.eq("fraud_category", filters.category);
    }
    if (filters.q) {
      var q = String(filters.q);
      query = query.or(
        "case_id.ilike.%" + q + "%,content.ilike.%" + q + "%,ai_summary.ilike.%" + q + "%,fraud_category.ilike.%" + q + "%"
      );
    }

    var result = await query;
    if (result.error) throw result.error;
    return (result.data || []).map(mapCaseRow);
  }

  async function getCaseByCaseId(caseId) {
    var sb = getClient();
    if (!sb) throw new Error("Supabase is not configured");
    var result = await sb.from("fraud_cases").select("*").eq("case_id", caseId).maybeSingle();
    if (result.error) throw result.error;
    return mapCaseRow(result.data);
  }

  async function assignCase(caseId, assignedTo) {
    var sb = getClient();
    if (!sb) throw new Error("Supabase is not configured");
    var result = await sb
      .from("fraud_cases")
      .update({
        status: "Under Review",
        assigned_to: assignedTo || "Analyst",
      })
      .eq("case_id", caseId)
      .neq("status", "Closed")
      .select("*")
      .maybeSingle();
    if (result.error) throw result.error;
    return mapCaseRow(result.data);
  }

  async function closeCase(caseId, decision) {
    var sb = getClient();
    if (!sb) throw new Error("Supabase is not configured");
    var result = await sb
      .from("fraud_cases")
      .update({
        status: "Closed",
        decision: decision || null,
      })
      .eq("case_id", caseId)
      .select("*")
      .maybeSingle();
    if (result.error) throw result.error;
    return mapCaseRow(result.data);
  }

  function computeStats(cases) {
    var list = cases || [];
    var startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);
    var todayMs = startOfToday.getTime();

    return {
      total: list.length,
      pending: list.filter(function (c) { return c.status === "Pending Review"; }).length,
      underReview: list.filter(function (c) { return c.status === "Under Review"; }).length,
      closed: list.filter(function (c) { return c.status === "Closed"; }).length,
      closedToday: list.filter(function (c) {
        if (c.status !== "Closed") return false;
        var decided = (c.decision && c.decision.decidedAt) || c.submittedAt;
        if (!decided) return false;
        return new Date(decided).getTime() >= todayMs;
      }).length,
      highRisk: list.filter(function (c) { return Number(c.fraudProbability) >= 70; }).length,
    };
  }

  global.ByteShieldSupabase = {
    isConfigured: isConfigured,
    getClient: getClient,
    mapCaseRow: mapCaseRow,
    listCases: listCases,
    getCaseByCaseId: getCaseByCaseId,
    assignCase: assignCase,
    closeCase: closeCase,
    computeStats: computeStats,
  };
})(window);
