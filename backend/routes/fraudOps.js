/**
 * Fraud Ops HTTP routes backed by Supabase.
 * POST   /api/report
 * GET    /api/cases
 * PATCH  /api/cases/:id
 * GET    /api/cases/:id   (open / assign)
 */
const express = require("express");
const fraudCases = require("../services/fraudCasesService");

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

  /** GET /api/cases — every fraud case, newest first */
  router.get("/cases", async (req, res) => {
    try {
      if (!fraudCases.isConfigured) {
        // Fall back to legacy JSON store so the UI still works offline
        if (casesStore) {
          const { status, category, q } = req.query;
          const list = await casesStore.listCases({ status, category, q });
          return res.json({
            success: true,
            source: "local",
            stats: await casesStore.getStats(),
            cases: list.map(toListItem),
          });
        }
        return res.status(503).json({
          success: false,
          error: "Supabase is not configured",
        });
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

  /** GET /api/cases/:id — open case; auto-assign when pending */
  router.get("/cases/:id", async (req, res) => {
    try {
      const assignedTo = String(req.query.assigned_to || req.query.analyst || "Analyst");

      if (fraudCases.isConfigured) {
        let found = await fraudCases.getCaseByIdOrCaseId(req.params.id);
        if (!found) {
          return res.status(404).json({ success: false, error: "Case not found" });
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
      res.json({ success: true, case: found });
    } catch (error) {
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
            saved = await fraudCases.patchCase(saved.id, {
              investigation: package_,
              ai_summary: package_?.aiInvestigationSummary || saved.aiSummary,
              ai_recommendation:
                package_?.recommendation?.action || saved.aiRecommendation,
            });
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
