/**
 * Detect transient Supabase connectivity failures (DNS, offline, timeout)
 * so read routes can fall back to local JSON storage.
 */

const loggedFallbacks = new Set();

function errorText(error) {
  if (!error) return "";
  const parts = [
    error.message,
    error.details,
    error.cause?.message,
    error.cause?.code,
    String(error),
  ];
  return parts.filter(Boolean).join("\n");
}

function isSupabaseNetworkError(error) {
  const text = errorText(error).toLowerCase();
  if (!text) return false;

  const networkSignals = [
    "fetch failed",
    "enotfound",
    "econnrefused",
    "econnreset",
    "etimedout",
    "enetunreach",
    "network error",
    "socket hang up",
    "getaddrinfo",
    "unable to connect",
  ];

  return networkSignals.some((signal) => text.includes(signal));
}

function logSupabaseFallbackOnce(route, error) {
  const key = route || "supabase";
  if (loggedFallbacks.has(key)) return;
  loggedFallbacks.add(key);
  const hint = errorText(error).split("\n")[0] || "network unreachable";
  console.warn(
    `⚠️ Supabase unreachable (${hint}) — using local JSON fallback for ${key}. Check internet/VPN or SUPABASE_URL.`,
  );
}

module.exports = {
  isSupabaseNetworkError,
  logSupabaseFallbackOnce,
};
