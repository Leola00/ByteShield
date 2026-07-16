/**
 * Local Fraud Ops login when Supabase is not configured (dev/demo only).
 */
const LOCAL_DEV_ANALYST_ID = "local-dev-analyst";

function trimEnv(name, fallback = "") {
  return String(process.env[name] || fallback).trim();
}

function getLocalDevCredentials() {
  return {
    email: trimEnv("FRAUD_DEV_EMAIL", "analyst@alinma.com").toLowerCase(),
    password: trimEnv("FRAUD_DEV_PASSWORD", "alinma123"),
  };
}

function buildLocalDevAnalyst(overrides = {}) {
  const creds = getLocalDevCredentials();
  return {
    id: LOCAL_DEV_ANALYST_ID,
    authUserId: null,
    fullName: trimEnv("FRAUD_DEV_NAME", "Fraud Analyst"),
    email: creds.email,
    role: trimEnv("FRAUD_DEV_ROLE", "Fraud Analyst"),
    team: trimEnv("FRAUD_DEV_TEAM", "Fraud Team"),
    avatar: null,
    phone: null,
    phoneCode: "+966",
    bio: null,
    createdAt: null,
    ...overrides,
  };
}

function isLocalDevAnalystId(id) {
  return String(id || "") === LOCAL_DEV_ANALYST_ID;
}

function matchesLocalDevLogin(email, password) {
  const creds = getLocalDevCredentials();
  const normalizedEmail = String(email || "").trim().toLowerCase();
  return normalizedEmail === creds.email && String(password || "") === creds.password;
}

module.exports = {
  LOCAL_DEV_ANALYST_ID,
  getLocalDevCredentials,
  buildLocalDevAnalyst,
  isLocalDevAnalystId,
  matchesLocalDevLogin,
};
