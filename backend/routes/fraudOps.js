/**
 * Fraud Ops HTTP routes backed by Supabase.
 * POST   /api/report
 * GET    /api/cases
 * PATCH  /api/cases/:id
 * GET    /api/cases/:id   (open / assign)
 */
const express = require("express");
const fraudCases = require("../services/fraudCasesService");
const {
  isSupabaseNetworkError,
  logSupabaseFallbackOnce,
} = require("../services/supabaseResilience");

function analystsMatch(assignee, analyst) {
  const a = String(assignee || "").trim().toLowerCase();
  const b = String(analyst || "").trim().toLowerCase();
  if (!a || !b) return true;
  return a === b || a.includes(b) || b.includes(a);
}

// Fraud Ops investigation content must be presented in English. Detect Arabic
// script so we can regenerate an English package when a stored stub is Arabic.
function containsArabic(value) {
  return /[\u0600-\u06FF]/.test(String(value || ""));
}

function createFraudOpsRouter({ casesStore, investigation, openai, callOpenAiJson } = {}) {
  const router = express.Router();

  /** POST /api/report — save a fraud report into fraud_cases */
  router.post("/report", async (req, res) => {
    try {
      if (!fraudCases.isConfigured) {
        return res.status(503).json({
          success: false,
          error: "Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in backend/.env",
        });
      }

      const body = req.body || {};
      const content = String(body.content || "").trim();
      if (!content) {
        return res.status(400).json({ success: false, error: "content is required" });
      }

      const created = await fraudCases.createReport({
        case_id: body.case_id || body.caseId,
        source: body.source || body.contentType || "Message",
        content,
        fraud_score: body.fraud_score ?? body.fraudScore ?? body.fraudProbability,
        fraud_category: body.fraud_category || body.fraudCategory || body.threatType,
        ai_summary: body.ai_summary || body.aiSummary || body.aiExplanation || body.shortExplanation,
        ai_recommendation: body.ai_recommendation || body.aiRecommendation || body.recommendation,
        iocs: body.iocs || {},
        status: body.status || "Pending Review",
        assigned_to: body.assigned_to || body.assignedTo || null,
        internal_notes: body.internal_notes || body.internalNotes || null,
        screenshotDataUrl: body.screenshotDataUrl,
        reasoning: body.reasoning,
        urls: body.urls,
        emails: body.emails,
        phones: body.phones,
      });

      res.status(201).json({ success: true, case: created });
    } catch (error) {
      console.error("POST /api/report Error:", error);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  async function respondLocalCases(req, res) {
    if (!casesStore) {
      return res.status(503).json({
        success: false,
        error: "Supabase is not configured and local case store is unavailable",
      });
    }
    const { status, category, q } = req.query;
    const list = await casesStore.listCases({ status, category, q });
    return res.json({
      success: true,
      source: "local",
      stats: await casesStore.getStats(),
      cases: list.map(toListItem),
    });
  }

  /** GET /api/cases — every fraud case, newest first */
  router.get("/cases", async (req, res) => {
    try {
      if (!fraudCases.isConfigured) {
        return respondLocalCases(req, res);
      }

      const { status, category, q } = req.query;
      const all = await fraudCases.listAllCases();
      let list = all;
      if (status && status !== "all") {
        list = list.filter((c) => c.status === status);
      }
      if (category && category !== "all") {
        list = list.filter((c) => c.fraudCategory === category);
      }
      if (q) {
        const needle = String(q).toLowerCase();
        list = list.filter((c) =>
          [c.id, c.content, c.aiSummary, c.fraudCategory, c.preview, c.assignedTo]
            .join(" ")
            .toLowerCase()
            .includes(needle),
        );
      }
      res.json({
        success: true,
        source: "supabase",
        stats: fraudCases.computeStats(all),
        cases: list.map(toListItem),
      });
    } catch (error) {
      if (isSupabaseNetworkError(error) && casesStore) {
        logSupabaseFallbackOnce("GET /api/cases", error);
        return respondLocalCases(req, res);
      }
      console.error("GET /api/cases Error:", error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  /** PATCH /api/cases/:id — update status, assigned_to, internal_notes */
  router.patch("/cases/:id", async (req, res) => {
    try {
      if (!fraudCases.isConfigured) {
        return res.status(503).json({
          success: false,
          error: "Supabase is not configured",
        });
      }

      const body = req.body || {};
      const updated = await fraudCases.patchCase(req.params.id, {
        status: body.status,
        assigned_to: body.assigned_to ?? body.assignedTo,
        internal_notes: body.internal_notes ?? body.internalNotes,
        investigation: body.investigation,
        decision: body.decision,
        ai_summary: body.ai_summary,
        ai_recommendation: body.ai_recommendation,
      });

      res.json({ success: true, case: updated });
    } catch (error) {
      console.error("PATCH /api/cases/:id Error:", error);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  /** POST /api/cases/:id/take — assign pending case to analyst (explicit take only) */
  router.post("/cases/:id/take", async (req, res) => {
    try {
      const assignedTo = String(
        req.body?.assigned_to || req.body?.assignedTo || req.query.assigned_to || "Analyst",
      );

      if (fraudCases.isConfigured) {
        let found = await fraudCases.getCaseByIdOrCaseId(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
        }
        if (found.status === "Closed") {
          return res.status(400).json({ success: false, error: "Case is closed" });
        }
        if (found.status === "Pending Review") {
          found = await fraudCases.patchCase(found.id, {
            status: "Under Review",
            assigned_to: assignedTo,
          });
        }
        return res.json({ success: true, case: found });
      }

      if (!casesStore) {
        return res.status(503).json({ success: false, error: "Case store unavailable" });
      }

      let found = await casesStore.getCaseById(req.params.id);
      if (!found) {
        return res.status(404).json({ success: false, error: "Case not found" });
      }
      if (found.status === "Pending Review") {
        found = await casesStore.markUnderReview(found.id, assignedTo);
      }
      return res.json({ success: true, case: found });
    } catch (error) {
      if (isSupabaseNetworkError(error) && casesStore) {
        logSupabaseFallbackOnce("POST /api/cases/:id/take", error);
        const assignedTo = String(
          req.body?.assigned_to || req.body?.assignedTo || req.query.assigned_to || "Analyst",
        );
        let found = await casesStore.getCaseById(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
        }
        if (found.status === "Pending Review") {
          found = await casesStore.markUnderReview(found.id, assignedTo);
        }
        return res.json({ success: true, case: found, source: "local" });
      }
      console.error("POST /api/cases/:id/take Error:", error);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  /** POST /api/cases/:id/release — return under-review case to pending queue */
  router.post("/cases/:id/release", async (req, res) => {
    try {
      const analyst = String(
        req.body?.assigned_to || req.body?.assignedTo || req.body?.analyst || "",
      ).trim();

      if (fraudCases.isConfigured) {
        let found = await fraudCases.getCaseByIdOrCaseId(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
        }
        if (found.status === "Closed") {
          return res.status(400).json({ success: false, error: "Case is closed" });
        }
        if (found.status !== "Under Review") {
          return res.json({ success: true, case: found });
        }
        if (analyst && found.assignedTo && !analystsMatch(found.assignedTo, analyst)) {
          return res.status(403).json({
            success: false,
            error: "Only the assigned analyst can return this case to the queue",
          });
        }
        found = await fraudCases.patchCase(found.id, {
          status: "Pending Review",
          assigned_to: null,
        });
        return res.json({ success: true, case: found });
      }

      if (!casesStore) {
        return res.status(503).json({ success: false, error: "Case store unavailable" });
      }

      let found = await casesStore.getCaseById(req.params.id);
      if (!found) {
        return res.status(404).json({ success: false, error: "Case not found" });
      }
      if (found.status === "Under Review") {
        found = await casesStore.releaseToQueue(found.id);
      }
      return res.json({ success: true, case: found });
    } catch (error) {
      if (isSupabaseNetworkError(error) && casesStore) {
        logSupabaseFallbackOnce("POST /api/cases/:id/release", error);
        let found = await casesStore.getCaseById(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
        }
        if (found.status === "Under Review") {
          found = await casesStore.releaseToQueue(found.id);
        }
        return res.json({ success: true, case: found, source: "local" });
      }
      console.error("POST /api/cases/:id/release Error:", error);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  /** GET /api/cases/:id — read case (never auto-assign; use POST /take) */
  router.get("/cases/:id", async (req, res) => {
    try {
      const previewOnly =
        req.query.preview === "true" || req.query.preview === "1";

      if (fraudCases.isConfigured) {
        let found = await fraudCases.getCaseByIdOrCaseId(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
        }

        // Ensure a full, English investigation package always shows in the drawer —
        // even in preview ("Work on this case?") mode before the case is assigned.
        const hasInvestigation =
          investigation &&
          typeof investigation.generateInvestigation === "function";
        const needsFill =
          hasInvestigation &&
          (!investigation.isInvestigationComplete(found.investigation) ||
            containsArabic(found.investigation?.aiInvestigationSummary) ||
            containsArabic(found.investigation?.recommendation?.rationale) ||
            containsArabic(found.investigation?.executiveInvestigationSummary));

        if (needsFill && previewOnly) {
          // Fast, in-memory English package for the read-only preview (no persist).
          const package_ = investigation.buildLocalInvestigation(found);
          found = {
            ...found,
            investigation: package_,
            aiExplanation:
              package_?.aiInvestigationSummary || found.aiExplanation,
            aiSummary: package_?.aiInvestigationSummary || found.aiSummary,
            aiRecommendation:
              package_?.recommendation?.action || found.aiRecommendation,
          };
        } else if (needsFill) {
          try {
            const package_ = await investigation.generateInvestigation(
              openai,
              callOpenAiJson,
              found,
            );
            try {
              found = await fraudCases.patchCase(found.id, {
                investigation: package_,
                ai_summary: package_?.aiInvestigationSummary || found.aiSummary,
                ai_recommendation:
                  package_?.recommendation?.action || found.aiRecommendation,
              });
            } catch (saveErr) {
              console.warn("Could not persist investigation:", saveErr.message);
              found = {
                ...found,
                investigation: package_,
                aiExplanation: package_?.aiInvestigationSummary || found.aiExplanation,
                aiSummary: package_?.aiInvestigationSummary || found.aiSummary,
                aiRecommendation:
                  package_?.recommendation?.action || found.aiRecommendation,
              };
            }
          } catch (invErr) {
            console.warn("On-open investigation failed:", invErr.message);
          }
        }

        return res.json({ success: true, case: found });
      }

      if (!casesStore) {
        return res.status(503).json({ success: false, error: "Case store unavailable" });
      }

      let found = await casesStore.getCaseById(req.params.id);
      if (!found) {
        return res.status(404).json({ success: false, error: "Case not found" });
      }
      res.json({ success: true, case: found });
    } catch (error) {
      if (isSupabaseNetworkError(error) && casesStore) {
        logSupabaseFallbackOnce("GET /api/cases/:id", error);
        let found = await casesStore.getCaseById(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
        }
        return res.json({ success: true, case: found, source: "local" });
      }
      console.error("GET /api/cases/:id Error:", error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  /** Legacy submit used by the UI "Submit Fraud Report" button */
  router.post("/cases", async (req, res) => {
    try {
      const body = req.body || {};
      const content = String(body.content || "").trim();
      if (!content) {
        return res.status(400).json({ success: false, error: "content is required" });
      }

      const score = Number(body.fraudProbability ?? body.fraud_score ?? body.score) || 0;
      if (score < 31) {
        return res.status(400).json({
          success: false,
          error: "Only suspicious or high-risk analyses can be submitted as fraud reports",
        });
      }

      let saved;

      if (fraudCases.isConfigured) {
        saved = await fraudCases.createReport({
          source: body.contentType || body.source || "Message",
          content,
          fraud_score: score,
          fraud_category: body.fraudCategory || body.threatType || "general",
          ai_summary: body.aiExplanation || body.shortExplanation || "",
          ai_recommendation: body.recommendation || null,
          iocs: body.iocs || {},
          status: "Pending Review",
          screenshotDataUrl: body.screenshotDataUrl || null,
          reasoning: body.reasoning || [],
          urls: body.urls,
          emails: body.emails,
          phones: body.phones,
        });

        if (investigation && typeof investigation.generateInvestigation === "function") {
          try {
            const package_ = await investigation.generateInvestigation(
              openai,
              callOpenAiJson,
              saved,
            );
            try {
              saved = await fraudCases.patchCase(saved.id, {
                investigation: package_,
                ai_summary: package_?.aiInvestigationSummary || saved.aiSummary,
                ai_recommendation:
                  package_?.recommendation?.action || saved.aiRecommendation,
              });
            } catch (saveErr) {
              console.warn("Investigation save failed:", saveErr.message);
              saved = {
                ...saved,
                investigation: package_,
                aiExplanation: package_?.aiInvestigationSummary || saved.aiExplanation,
                aiSummary: package_?.aiInvestigationSummary || saved.aiSummary,
                aiRecommendation:
                  package_?.recommendation?.action || saved.aiRecommendation,
              };
            }
          } catch (invErr) {
            console.warn("Investigation enrich failed:", invErr.message);
          }
        }
      } else if (casesStore) {
        const { case: created } = await casesStore.createCase({
          content,
          contentType: body.contentType || "Message",
          screenshotDataUrl: body.screenshotDataUrl || null,
          urls: body.urls,
          emails: body.emails,
          phones: body.phones,
          domains: body.domains,
          ips: body.ips,
          hashes: body.hashes,
          fraudProbability: score,
          aiExplanation: body.aiExplanation || body.shortExplanation || "",
          reasoning: body.reasoning || [],
          fraudCategory: body.fraudCategory || body.threatType || "general",
          threatType: body.threatType || body.fraudCategory || "general",
        });

        const package_ = await investigation.generateInvestigation(
          openai,
          callOpenAiJson,
          created,
        );
        saved = await casesStore.updateCase(created.id, (c) => ({
          ...c,
          investigation: package_,
          aiExplanation: package_?.aiInvestigationSummary || c.aiExplanation,
        }));
      } else {
        return res.status(503).json({ success: false, error: "No case store available" });
      }

      res.status(201).json({ success: true, case: saved });
    } catch (error) {
      console.error("POST /api/cases Error:", error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  /** Decision (approve / modify / reject / escalate / close) */
  router.post("/cases/:id/decision", async (req, res) => {
    try {
      const { outcome, action, analystNote, reviewedBy, assignedTo } = req.body || {};
      const normalized = String(outcome || "").toLowerCase();
      if (!["approve", "modify", "reject", "escalate", "close"].includes(normalized)) {
        return res.status(400).json({
          success: false,
          error: "outcome must be approve, modify, reject, escalate, or close",
        });
      }

      if (fraudCases.isConfigured) {
        const saved = await fraudCases.applyCaseAction(req.params.id, {
          outcome: normalized,
          action,
          analystNote,
          reviewedBy,
          assignedTo,
        });
        return res.json({ success: true, case: saved });
      }

      if (!casesStore) {
        return res.status(503).json({ success: false, error: "Case store unavailable" });
      }

      const saved = await casesStore.setDecision(req.params.id, {
        outcome: normalized === "close" ? "approve" : normalized,
        action: action || "",
        analystNote: analystNote || "",
      });
      if (!saved) {
        return res.status(404).json({ success: false, error: "Case not found" });
      }
      res.json({ success: true, case: saved });
    } catch (error) {
      console.error("Decision Error:", error);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  return router;
}

function toListItem(c) {
  return {
    id: c.id,
    status: c.status,
    submittedAt: c.submittedAt,
    fraudProbability: c.fraudProbability,
    fraudCategory: c.fraudCategory,
    contentType: c.contentType || c.source,
    source: c.source || c.contentType,
    preview: c.preview,
    campaignId: c.campaignId,
    assignedTo: c.assignedTo || null,
    reviewedBy: c.reviewedBy || null,
    recommendation: c.investigation?.recommendation?.action || c.aiRecommendation || null,
  };
}

module.exports = { createFraudOpsRouter };
