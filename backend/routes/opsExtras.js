/**
 * Auth + analysts + internal notes HTTP routes
 */
const express = require("express");
const authService = require("../services/authService");
const analysts = require("../services/analystsService");
const notes = require("../services/notesService");
const fraudCases = require("../services/fraudCasesService");
const { isConfigured } = require("../supabase");
const {
  isSupabaseNetworkError,
  logSupabaseFallbackOnce,
} = require("../services/supabaseResilience");

function createOpsExtrasRouter() {
  const router = express.Router();

  router.post("/auth/login", async (req, res) => {
    try {
      const { email, password, username } = req.body || {};
      const result = await authService.login(email || username, password);
      res.json({ success: true, ...result });
    } catch (error) {
      console.error("Login Error:", error.message);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  router.get("/analysts/me", async (req, res) => {
    try {
      const id = req.query.id || req.headers["x-analyst-id"];
      const email = req.query.email;
      let analyst = null;
      if (id) analyst = await analysts.getById(id);
      else if (email) analyst = await analysts.getByEmail(email);
      if (!analyst) return res.status(404).json({ success: false, error: "Analyst not found" });
      res.json({ success: true, analyst });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  router.get("/analysts", async (_req, res) => {
    try {
      res.json({ success: true, analysts: await analysts.listAnalysts() });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  /** Add employee → row in public.analysts (email + password) */
  router.post("/analysts", async (req, res) => {
    try {
      const body = req.body || {};
      const analyst = await authService.createEmployee({
        email: body.email,
        password: body.password,
        fullName: body.fullName || body.full_name,
        role: body.role,
        team: body.team,
        phone: body.phone,
        phoneCode: body.phoneCode || body.phone_code,
      });
      res.status(201).json({ success: true, analyst });
    } catch (error) {
      console.error("Create employee error:", error.message);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  router.patch("/analysts/:id", async (req, res) => {
    try {
      const updated = await analysts.updateProfile(req.params.id, req.body || {});
      res.json({ success: true, analyst: updated });
    } catch (error) {
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  router.post("/auth/password", async (req, res) => {
    try {
      const body = req.body || {};
      await authService.changePassword({
        analyst_id: body.analyst_id || body.analystId,
        access_token: body.access_token || body.accessToken,
        currentPassword: body.currentPassword || body.current_password,
        newPassword: body.newPassword || body.new_password,
      });
      res.json({ success: true });
    } catch (error) {
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  /** Internal notes — all / by case */
  router.get("/notes", async (req, res) => {
    try {
      if (!isConfigured) return res.json({ success: true, notes: [] });
      const list = await notes.listAll({
        analystId: req.query.analyst_id,
        q: req.query.q,
      });
      res.json({ success: true, notes: list });
    } catch (error) {
      if (isSupabaseNetworkError(error)) {
        logSupabaseFallbackOnce("GET /api/notes", error);
        return res.json({ success: true, notes: [], source: "local" });
      }
      res.status(500).json({ success: false, error: error.message });
    }
  });

  router.get("/cases/:id/notes", async (req, res) => {
    try {
      const c = await fraudCases.getCaseByIdOrCaseId(req.params.id);
      if (!c) return res.status(404).json({ success: false, error: "Case not found" });
      const list = await notes.listByCaseUuid(c.uuid);
      res.json({ success: true, notes: list });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  router.post("/cases/:id/notes", async (req, res) => {
    try {
      const c = await fraudCases.getCaseByIdOrCaseId(req.params.id);
      if (!c) return res.status(404).json({ success: false, error: "Case not found" });
      const created = await notes.createNote({
        caseUuid: c.uuid,
        analystId: req.body?.analyst_id || req.body?.analystId,
        note: req.body?.note,
        parentNoteId: req.body?.parent_note_id || req.body?.parentNoteId || null,
      });
      res.status(201).json({ success: true, note: created });
    } catch (error) {
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  router.get("/notes/:noteId/comments", async (req, res) => {
    try {
      if (!isConfigured) return res.json({ success: true, comments: [] });
      const parent = await notes.getById(req.params.noteId);
      if (!parent) return res.status(404).json({ success: false, error: "Note not found" });
      const comments = await notes.listCommentsByParentId(req.params.noteId);
      res.json({ success: true, comments });
    } catch (error) {
      if (isSupabaseNetworkError(error)) {
        logSupabaseFallbackOnce("GET /api/notes/:noteId/comments", error);
        return res.json({ success: true, comments: [], source: "local" });
      }
      res.status(500).json({ success: false, error: error.message });
    }
  });

  router.post("/notes/:noteId/comments", async (req, res) => {
    try {
      if (!isConfigured) {
        return res.status(503).json({ success: false, error: "Supabase is not configured" });
      }
      const parent = await notes.getById(req.params.noteId);
      if (!parent) return res.status(404).json({ success: false, error: "Note not found" });
      const created = await notes.createNote({
        caseUuid: parent.caseUuid,
        analystId: req.body?.analyst_id || req.body?.analystId,
        note: req.body?.note || req.body?.text,
        parentNoteId: parent.id,
      });
      res.status(201).json({ success: true, comment: created });
    } catch (error) {
      console.error("POST /notes/:noteId/comments Error:", error.message);
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  router.delete("/notes/:noteId", async (req, res) => {
    try {
      await notes.deleteNote(req.params.noteId, req.query.analyst_id || req.body?.analyst_id);
      res.json({ success: true });
    } catch (error) {
      res.status(error.status || 500).json({ success: false, error: error.message });
    }
  });

  return router;
}

module.exports = { createOpsExtrasRouter };
