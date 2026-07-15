/**
 * Analysts — Supabase `analysts` table
 */
const { getSupabase, isConfigured } = require("../supabase");

function mapAnalyst(row) {
  if (!row) return null;
  return {
    id: row.id,
    authUserId: row.auth_user_id,
    fullName: row.full_name,
    email: row.email,
    role: row.role || "Fraud Analyst",
    team: row.team || "Fraud Team",
    avatar: row.avatar || null,
    phone: row.phone || null,
    phoneCode: row.phone_code || "+966",
    bio: row.bio || null,
    createdAt: row.created_at,
  };
}

const PUBLIC_COLUMNS =
  "id, auth_user_id, full_name, email, role, team, avatar, phone, phone_code, bio, created_at, updated_at";

async function getByEmail(email) {
  if (!isConfigured) return null;
  const sb = getSupabase();
  const { data, error } = await sb
    .from("analysts")
    .select(PUBLIC_COLUMNS)
    .eq("email", String(email || "").trim().toLowerCase())
    .maybeSingle();
  if (error) throw error;
  return mapAnalyst(data);
}

async function getByAuthUserId(authUserId) {
  if (!isConfigured) return null;
  const sb = getSupabase();
  const { data, error } = await sb
    .from("analysts")
    .select(PUBLIC_COLUMNS)
    .eq("auth_user_id", authUserId)
    .maybeSingle();
  if (error) throw error;
  return mapAnalyst(data);
}

async function getById(id) {
  if (!isConfigured) return null;
  const sb = getSupabase();
  const { data, error } = await sb.from("analysts").select(PUBLIC_COLUMNS).eq("id", id).maybeSingle();
  if (error) throw error;
  return mapAnalyst(data);
}

async function listAnalysts() {
  if (!isConfigured) return [];
  const sb = getSupabase();
  const { data, error } = await sb.from("analysts").select(PUBLIC_COLUMNS).order("full_name");
  if (error) throw error;
  return (data || []).map(mapAnalyst);
}

async function upsertFromAuth({ authUserId, email, fullName, role, team }) {
  const sb = getSupabase();
  const normalizedEmail = String(email || "").trim().toLowerCase();
  const existing = await getByEmail(normalizedEmail);
  if (existing) {
    const { data, error } = await sb
      .from("analysts")
      .update({
        auth_user_id: authUserId || existing.authUserId,
        full_name: fullName || existing.fullName,
        role: role || existing.role,
        team: team || existing.team,
        updated_at: new Date().toISOString(),
      })
      .eq("id", existing.id)
      .select(PUBLIC_COLUMNS)
      .single();
    if (error) throw error;
    return mapAnalyst(data);
  }

  const { data, error } = await sb
    .from("analysts")
    .insert({
      auth_user_id: authUserId || null,
      full_name: fullName || normalizedEmail.split("@")[0] || "Analyst",
      email: normalizedEmail,
      role: role || "Fraud Analyst",
      team: team || "Fraud Team",
    })
    .select(PUBLIC_COLUMNS)
    .single();
  if (error) throw error;
  return mapAnalyst(data);
}

async function updateProfile(id, updates = {}) {
  const sb = getSupabase();
  const patch = { updated_at: new Date().toISOString() };
  if (updates.fullName !== undefined) patch.full_name = updates.fullName;
  if (updates.full_name !== undefined) patch.full_name = updates.full_name;
  if (updates.email !== undefined) patch.email = String(updates.email).trim().toLowerCase();
  if (updates.role !== undefined) patch.role = updates.role;
  if (updates.team !== undefined) patch.team = updates.team;
  if (updates.avatar !== undefined) patch.avatar = updates.avatar;
  if (updates.phone !== undefined) patch.phone = updates.phone;
  if (updates.phoneCode !== undefined) patch.phone_code = updates.phoneCode;
  if (updates.phone_code !== undefined) patch.phone_code = updates.phone_code;
  if (updates.bio !== undefined) patch.bio = updates.bio;

  const { data, error } = await sb
    .from("analysts")
    .update(patch)
    .eq("id", id)
    .select(PUBLIC_COLUMNS)
    .single();
  if (error) throw error;
  return mapAnalyst(data);
}

/** Raw row including password — for login / password change only */
async function getAuthRowByEmail(email) {
  if (!isConfigured) return null;
  const sb = getSupabase();
  const { data, error } = await sb
    .from("analysts")
    .select("*")
    .eq("email", String(email || "").trim().toLowerCase())
    .maybeSingle();
  if (error) throw error;
  return data || null;
}

async function getAuthRowById(id) {
  if (!isConfigured) return null;
  const sb = getSupabase();
  const { data, error } = await sb.from("analysts").select("*").eq("id", id).maybeSingle();
  if (error) throw error;
  return data || null;
}

async function setPassword(id, passwordHash) {
  if (!passwordHash || !/^\$2[abxy]?\$/.test(String(passwordHash))) {
    const err = new Error("Password must be stored as a bcrypt hash");
    err.status = 400;
    throw err;
  }
  const sb = getSupabase();
  const { data, error } = await sb
    .from("analysts")
    .update({ password: passwordHash, updated_at: new Date().toISOString() })
    .eq("id", id)
    .select(PUBLIC_COLUMNS)
    .single();
  if (error) throw error;
  return mapAnalyst(data);
}

async function createEmployeeRow({
  email,
  password,
  fullName,
  role,
  team,
  phone,
  phoneCode,
}) {
  if (password && !/^\$2[abxy]?\$/.test(String(password))) {
    const err = new Error("Password must be stored as a bcrypt hash");
    err.status = 400;
    throw err;
  }
  const sb = getSupabase();
  const { data, error } = await sb
    .from("analysts")
    .insert({
      email: String(email || "").trim().toLowerCase(),
      password: password || null,
      full_name: fullName || "Analyst",
      role: role || "Fraud Analyst",
      team: team || "Fraud Team",
      phone: phone || null,
      phone_code: phoneCode || "+966",
    })
    .select(PUBLIC_COLUMNS)
    .single();
  if (error) throw error;
  return mapAnalyst(data);
}

module.exports = {
  mapAnalyst,
  getByEmail,
  getByAuthUserId,
  getById,
  listAnalysts,
  upsertFromAuth,
  updateProfile,
  getAuthRowByEmail,
  getAuthRowById,
  setPassword,
  createEmployeeRow,
};
