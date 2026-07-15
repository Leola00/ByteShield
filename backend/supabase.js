/**
 * Reusable Supabase client for ByteShield backend.
 * Prefer SUPABASE_SERVICE_ROLE_KEY (server-side). Falls back to anon key.
 */
const { createClient } = require("@supabase/supabase-js");

function trimEnv(name) {
  return String(process.env[name] || "").trim().replace(/^["']|["']$/g, "");
}

function isPlaceholder(value) {
  if (!value) return true;
  const v = value.toLowerCase().trim();
  return (
    v.includes("your_project_ref") ||
    v.includes("your-project-ref") ||
    v === "https://your_project_ref.supabase.co" ||
    v.startsWith("your-supabase") ||
    v.startsWith("your_supabase") ||
    v.startsWith("your-anon") ||
    v.startsWith("your-service") ||
    v === "changeme" ||
    v.includes("xxxxx")
  );
}

const supabaseUrl = trimEnv("SUPABASE_URL");
const supabaseAnonKey = trimEnv("SUPABASE_ANON_KEY");
const supabaseServiceKey = trimEnv("SUPABASE_SERVICE_ROLE_KEY");

const hasUrl = Boolean(supabaseUrl && !isPlaceholder(supabaseUrl));
const hasServiceKey = Boolean(supabaseServiceKey && !isPlaceholder(supabaseServiceKey));
const hasAnonKey = Boolean(supabaseAnonKey && !isPlaceholder(supabaseAnonKey));

const isConfigured = hasUrl && (hasServiceKey || hasAnonKey);

/** @type {import('@supabase/supabase-js').SupabaseClient | null} */
const supabase = isConfigured
  ? createClient(supabaseUrl, hasServiceKey ? supabaseServiceKey : supabaseAnonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    })
  : null;

function getSupabase() {
  if (!supabase) {
    throw new Error(
      "Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in backend/.env",
    );
  }
  return supabase;
}

function getPublicConfig() {
  const ready = hasUrl && hasAnonKey;
  return {
    url: ready ? supabaseUrl : null,
    anonKey: ready ? supabaseAnonKey : null,
    configured: ready,
  };
}

module.exports = {
  supabase,
  getSupabase,
  getPublicConfig,
  isConfigured,
};
