/**
 * Internal notes — Supabase `internal_notes` table
 */
const { getSupabase, isConfigured } = require("../supabase");

function mapNote(row) {
  if (!row) return null;
  const analyst = row.analysts || null;
  return {
    id: row.id,
    caseUuid: row.case_id,
    analystId: row.analyst_id,
    note: row.note,
    createdAt: row.created_at,
    analystName: analyst?.full_name || "Analyst",
    analystEmail: analyst?.email || null,
    analystAvatar: analyst?.avatar || null,
  };
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
  return (data || []).map(mapNote);
}

async function listAll({ analystId, q } = {}) {
  if (!isConfigured) return [];
  const sb = getSupabase();
  let query = sb
    .from("internal_notes")
    .select("*, analysts(full_name, email, avatar), fraud_cases(case_id, status)")
    .order("created_at", { ascending: false });

  if (analystId) query = query.eq("analyst_id", analystId);

  const { data, error } = await query;
  if (error) throw error;

  let notes = (data || []).map((row) => ({
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

async function createNote({ caseUuid, analystId, note }) {
  const sb = getSupabase();
  const text = String(note || "").trim();
  if (!text) {
    const err = new Error("note is required");
    err.status = 400;
    throw err;
  }
  const { data, error } = await sb
    .from("internal_notes")
    .insert({
      case_id: caseUuid,
      analyst_id: analystId || null,
      note: text,
    })
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
  listByCaseUuid,
  listAll,
  createNote,
  deleteNote,
};
