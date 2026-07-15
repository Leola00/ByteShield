/**
 * Fraud Ops authentication via public.analysts (email + bcrypt password hash).
 * Passwords are never stored in plain text — only bcrypt hashes ($2a$...).
 */
const bcrypt = require("bcryptjs");
const analysts = require("./analystsService");
const { isConfigured } = require("../supabase");

/** Cost factor — higher = slower to crack */
const BCRYPT_ROUNDS = 12;

function looksHashed(value) {
  return typeof value === "string" && /^\$2[abxy]?\$\d{2}\$/.test(value);
}

async function hashPassword(plain) {
  return bcrypt.hash(String(plain), BCRYPT_ROUNDS);
}

async function verifyPassword(plain, storedHash) {
  if (!storedHash) return false;
  const s = String(storedHash);
  const p = String(plain);
  if (!looksHashed(s)) {
    // Refuse plain-text storage; treat as invalid until admin resets
    return false;
  }
  return bcrypt.compare(p, s);
}

/**
 * Login against analysts.email + analysts.password (bcrypt hash)
 */
async function login(email, password) {
  if (!isConfigured) {
    const err = new Error("Supabase is not configured");
    err.status = 503;
    throw err;
  }

  const normalizedEmail = String(email || "").trim().toLowerCase();
  const pass = String(password || "");
  if (!normalizedEmail || !pass) {
    const err = new Error("Email and password are required");
    err.status = 400;
    throw err;
  }

  const row = await analysts.getAuthRowByEmail(normalizedEmail);
  if (!row) {
    const err = new Error("Invalid login credentials");
    err.status = 401;
    throw err;
  }

  if (!row.password) {
    const err = new Error(
      "No password set for this employee. Open Table Editor → analysts and set the password column.",
    );
    err.status = 401;
    throw err;
  }

  if (!looksHashed(row.password)) {
    const err = new Error(
      "Password is not hashed. Re-save the password in Table Editor (plain text once) so it auto-encrypts, or run schema-password-hash.sql.",
    );
    err.status = 401;
    throw err;
  }

  const ok = await verifyPassword(pass, row.password);
  if (!ok) {
    const err = new Error("Invalid login credentials");
    err.status = 401;
    throw err;
  }

  const analyst = analysts.mapAnalyst(row);
  return {
    analyst,
    session: {
      access_token: `table:${analyst.id}`,
      refresh_token: null,
      expires_at: null,
      kind: "table",
    },
  };
}

/**
 * Change password — stores bcrypt hash only.
 */
async function changePassword(payload = {}) {
  const newPassword = String(payload.newPassword || payload.new_password || "");
  if (!newPassword || newPassword.length < 6) {
    const err = new Error("New password must be at least 6 characters");
    err.status = 400;
    throw err;
  }

  let analystId = payload.analyst_id || payload.analystId || null;
  const token = String(payload.access_token || payload.accessToken || "");
  if (!analystId && token.startsWith("table:")) {
    analystId = token.slice("table:".length);
  }

  if (!analystId) {
    const err = new Error("analyst_id is required to change password");
    err.status = 400;
    throw err;
  }

  const row = await analysts.getAuthRowById(analystId);
  if (!row) {
    const err = new Error("Employee not found");
    err.status = 404;
    throw err;
  }

  const current = payload.currentPassword || payload.current_password;
  if (current) {
    const ok = await verifyPassword(current, row.password);
    if (!ok) {
      const err = new Error("Current password is incorrect");
      err.status = 401;
      throw err;
    }
  }

  const hashed = await hashPassword(newPassword);
  await analysts.setPassword(analystId, hashed);
  return { id: analystId };
}

/**
 * Create employee — password is bcrypt-hashed before insert.
 */
async function createEmployee({ email, password, fullName, role, team, phone, phoneCode }) {
  if (!isConfigured) {
    const err = new Error("Supabase is not configured");
    err.status = 503;
    throw err;
  }

  const normalizedEmail = String(email || "").trim().toLowerCase();
  const pass = String(password || "");
  const name = String(fullName || "").trim() || normalizedEmail.split("@")[0] || "Analyst";

  if (!normalizedEmail || !pass) {
    const err = new Error("email and password are required");
    err.status = 400;
    throw err;
  }
  if (pass.length < 6) {
    const err = new Error("Password must be at least 6 characters");
    err.status = 400;
    throw err;
  }

  const existing = await analysts.getByEmail(normalizedEmail);
  if (existing) {
    const err = new Error("An employee with this email already exists");
    err.status = 409;
    throw err;
  }

  const hashed = await hashPassword(pass);
  return analysts.createEmployeeRow({
    email: normalizedEmail,
    password: hashed,
    fullName: name,
    role: role || "Fraud Analyst",
    team: team || "Fraud Team",
    phone,
    phoneCode,
  });
}

module.exports = {
  login,
  changePassword,
  createEmployee,
  hashPassword,
  verifyPassword,
  looksHashed,
};
