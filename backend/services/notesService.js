/**
 * Internal notes — Supabase `internal_notes` table
 */
const { getSupabase, isConfigured } = require("../supabase");

const REPLY_PREFIX_RE = /^\[RE:([0-9a-f-]{36})\]\s/i;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function normalizeAnalystId(analystId) {
  const id = String(analystId || "").trim();
  return UUID_RE.test(id) ? id : null;
}

function isReplyNoteText(noteText) {
  return REPLY_PREFIX_RE.test(String(noteText || ""));
}

function replyPrefix(parentNoteId) {
  return `[RE:${parentNoteId}] `;
}

function stripReplyPrefix(noteText, parentNoteId) {
  const prefix = replyPrefix(parentNoteId);
  const raw = String(noteText || "");
  return raw.startsWith(prefix) ? raw.slice(prefix.length) : raw;
}

function mapNote(row, { stripReplyForParentId } = {}) {
  if (!row) return null;
  const analyst = row.analysts || null;
  let noteText = row.note;
  if (stripReplyForParentId) {
    noteText = stripReplyPrefix(noteText, stripReplyForParentId);
  }
  return {
    id: row.id,
    caseUuid: row.case_id,
    parentNoteId: row.parent_note_id || null,
    analystId: row.analyst_id,
    note: noteText,
    createdAt: row.created_at,
    analystName: analyst?.full_name || "Analyst",
    analystEmail: analyst?.email || null,
    analystAvatar: analyst?.avatar || null,
  };
}

async function getById(noteId) {
  if (!isConfigured) return null;
  const sb = getSupabase();
  const { data, error } = await sb
    .from("internal_notes")
    .select("*")
    .eq("id", noteId)
    .maybeSingle();
  if (error) throw error;
  if (!data) return null;
  return mapNote(data);
}

async function listCommentsByParentId(parentNoteId) {
  if (!isConfigured) return [];
  const sb = getSupabase();
  const { data, error } = await sb
    .from("internal_notes")
    .select("*, analysts(full_name, email, avatar)")
    .eq("parent_note_id", parentNoteId)
    .order("created_at", { ascending: true });

  if (!error) {
    return (data || []).map((row) => mapNote(row, { stripReplyForParentId: parentNoteId }));
  }

  if (/parent_note_id/i.test(error.message || "")) {
    const prefix = replyPrefix(parentNoteId);
    const { data: rows, error: fallbackError } = await sb
      .from("internal_notes")
      .select("*, analysts(full_name, email, avatar)")
      .like("note", `${prefix}%`)
      .order("created_at", { ascending: true });
    if (fallbackError) throw fallbackError;
    return (rows || []).map((row) => mapNote(row, { stripReplyForParentId: parentNoteId }));
  }

  throw error;
}

async function listByCaseUuid(caseUuid) {
  if (!isConfigured) return [];
  const sb = getSupabase();
  const { data, error } = await sb
    .from("internal_notes")
    .select("*, analysts(full_name, email, avatar)")
    .eq("case_id", caseUuid)
    .order("created_at", { ascending: true });
  if (error) throw error;
  return (data || [])
    .filter((row) => !row.parent_note_id && !isReplyNoteText(row.note))
    .map(mapNote);
}

async function listAll({ analystId, q } = {}) {
  if (!isConfigured) return [];
  const sb = getSupabase();
  let query = sb
    .from("internal_notes")
    .select("*, analysts(full_name, email, avatar), fraud_cases(case_id, status)")
    .is("parent_note_id", null)
    .order("created_at", { ascending: false });

  if (analystId) query = query.eq("analyst_id", analystId);

  let { data, error } = await query;
  if (error && /parent_note_id/i.test(error.message || "")) {
    let fallback = sb
      .from("internal_notes")
      .select("*, analysts(full_name, email, avatar), fraud_cases(case_id, status)")
      .order("created_at", { ascending: false });
    if (analystId) fallback = fallback.eq("analyst_id", analystId);
    ({ data, error } = await fallback);
  }
  if (error) throw error;

  let notes = (data || [])
    .filter((row) => !row.parent_note_id && !isReplyNoteText(row.note))
    .map((row) => ({
    ...mapNote(row),
    caseId: row.fraud_cases?.case_id || null,
    caseStatus: row.fraud_cases?.status || null,
  }));

  if (q) {
    const needle = String(q).toLowerCase();
    notes = notes.filter((n) =>
      [n.note, n.analystName, n.caseId].join(" ").toLowerCase().includes(needle),
    );
  }
  return notes;
}

async function createNote({ caseUuid, analystId, note, parentNoteId }) {
  if (!isConfigured) {
    const err = new Error("Supabase is not configured");
    err.status = 503;
    throw err;
  }
  const sb = getSupabase();
  const text = String(note || "").trim();
  if (!text) {
    const err = new Error("note is required");
    err.status = 400;
    throw err;
  }
  const payload = {
    case_id: caseUuid,
    analyst_id: normalizeAnalystId(analystId),
    note: text,
  };

  if (parentNoteId) {
    const withParent = { ...payload, parent_note_id: parentNoteId };
    let { data, error } = await sb
      .from("internal_notes")
      .insert(withParent)
      .select("*, analysts(full_name, email, avatar)")
      .single();

    if (error && /parent_note_id/i.test(error.message || "")) {
      ({ data, error } = await sb
        .from("internal_notes")
        .insert({ ...payload, note: `${replyPrefix(parentNoteId)}${text}` })
        .select("*, analysts(full_name, email, avatar)")
        .single());
    }

    if (error) throw error;
    return mapNote(data, { stripReplyForParentId: parentNoteId });
  }

  const { data, error } = await sb
    .from("internal_notes")
    .insert(payload)
    .select("*, analysts(full_name, email, avatar)")
    .single();
  if (error) throw error;
  return mapNote(data);
}

async function deleteNote(noteId, analystId) {
  const sb = getSupabase();
  // Only delete own notes when analystId provided
  let query = sb.from("internal_notes").delete().eq("id", noteId);
  if (analystId) query = query.eq("analyst_id", analystId);
  const { data, error } = await query.select("id").maybeSingle();
  if (error) throw error;
  if (!data) {
    const err = new Error("Note not found or not owned by analyst");
    err.status = 404;
    throw err;
  }
  return true;
}

module.exports = {
  getById,
  listByCaseUuid,
  listCommentsByParentId,
  listAll,
  createNote,
  deleteNote,
};
