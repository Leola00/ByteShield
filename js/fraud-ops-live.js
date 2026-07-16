/**
 * Fraud Ops live API helpers + Supabase realtime (keeps UI unchanged).
 */
(function (global) {
  "use strict";

  function apiUrl(path) {
    if (typeof getApiUrl === "function") return getApiUrl(path);
    return path;
  }

  async function jsonFetch(path, options) {
    const res = await fetch(apiUrl(path), {
      headers: { "Content-Type": "application/json", ...(options && options.headers) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
      throw new Error(data.error || res.statusText || "Request failed");
    }
    return data;
  }

  const SESSION_KEY = "byteshield_fraud_ops_session";

  function saveSession(payload) {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(payload || {}));
    } catch {
      /* ignore */
    }
  }

  function loadSession() {
    try {
      return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
    } catch {
      return null;
    }
  }

  function clearSession() {
    try {
      sessionStorage.removeItem(SESSION_KEY);
    } catch {
      /* ignore */
    }
  }

  async function login(email, password) {
    const data = await jsonFetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    saveSession({
      analyst: data.analyst,
      session: data.session,
      at: Date.now(),
    });
    return data;
  }

  function currentAnalyst() {
    return loadSession()?.analyst || null;
  }

  async function updateAnalystProfile(id, updates) {
    const data = await jsonFetch("/api/analysts/" + encodeURIComponent(id), {
      method: "PATCH",
      body: JSON.stringify(updates),
    });
    const sess = loadSession() || {};
    sess.analyst = data.analyst;
    saveSession(sess);
    return data.analyst;
  }

  async function listNotes(params) {
    const qs = new URLSearchParams(params || {}).toString();
    const data = await jsonFetch("/api/notes" + (qs ? "?" + qs : ""));
    return data.notes || [];
  }

  async function listCaseNotes(caseId) {
    const data = await jsonFetch("/api/cases/" + encodeURIComponent(caseId) + "/notes");
    return data.notes || [];
  }

  async function addCaseNote(caseId, note, analystId) {
    const data = await jsonFetch("/api/cases/" + encodeURIComponent(caseId) + "/notes", {
      method: "POST",
      body: JSON.stringify({ note, analyst_id: analystId }),
    });
    return data.note;
  }

  async function listNoteComments(noteId) {
    const data = await jsonFetch("/api/notes/" + encodeURIComponent(noteId) + "/comments");
    return data.comments || [];
  }

  async function addNoteComment(noteId, note, analystId) {
    const data = await jsonFetch("/api/notes/" + encodeURIComponent(noteId) + "/comments", {
      method: "POST",
      body: JSON.stringify({ note, analyst_id: analystId }),
    });
    return data.comment;
  }

  async function deleteNote(noteId, analystId) {
    const qs = analystId ? "?analyst_id=" + encodeURIComponent(analystId) : "";
    await jsonFetch("/api/notes/" + encodeURIComponent(noteId) + qs, { method: "DELETE" });
  }

  let realtimeChannel = null;

  function startRealtime(onChange) {
    stopRealtime();
    const client =
      typeof ByteShieldSupabase !== "undefined" && ByteShieldSupabase.getClient
        ? ByteShieldSupabase.getClient()
        : null;
    if (!client || typeof client.channel !== "function") return false;

    realtimeChannel = client
      .channel("fraud-ops-live")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "fraud_cases" },
        function (payload) {
          if (typeof onChange === "function") onChange("fraud_cases", payload);
        },
      )
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "internal_notes" },
        function (payload) {
          if (typeof onChange === "function") onChange("internal_notes", payload);
        },
      )
      .subscribe();
    return true;
  }

  function stopRealtime() {
    try {
      const client =
        typeof ByteShieldSupabase !== "undefined" && ByteShieldSupabase.getClient
          ? ByteShieldSupabase.getClient()
          : null;
      if (client && realtimeChannel) client.removeChannel(realtimeChannel);
    } catch {
      /* ignore */
    }
    realtimeChannel = null;
  }

  global.FraudOpsLive = {
    login,
    loadSession,
    saveSession,
    clearSession,
    currentAnalyst,
    updateAnalystProfile,
    listNotes,
    listCaseNotes,
    addCaseNote,
    listNoteComments,
    addNoteComment,
    deleteNote,
    startRealtime,
    stopRealtime,
    jsonFetch,
  };
})(window);
