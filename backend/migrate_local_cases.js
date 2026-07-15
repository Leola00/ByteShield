/**
 * One-time migrate local fraud_cases.json → Supabase fraud_cases (core columns only)
 */
require("dotenv").config({ path: require("path").join(__dirname, ".env"), override: true });
const fs = require("fs");
const path = require("path");
const { getSupabase } = require("./supabase");
const service = require("./services/fraudCasesService");

(async () => {
  if (!service.isConfigured) {
    console.log("error=Supabase not configured");
    process.exit(1);
  }

  const file = path.join(__dirname, "fraud_cases.json");
  if (!fs.existsSync(file)) {
    console.log("error=No local fraud_cases.json found");
    process.exit(1);
  }

  const local = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(local) || !local.length) {
    console.log("migrated=0");
    return;
  }

  const sb = getSupabase();
  let ok = 0;
  let failed = 0;

  for (const c of local) {
    if (!c?.id) continue;
    const row = service.buildInsertPayload({
      case_id: c.id,
      source: c.contentType || "Message",
      content: c.content || "",
      fraud_score: c.fraudProbability,
      fraud_category: c.fraudCategory || c.threatType,
      ai_summary: c.investigation?.aiInvestigationSummary || c.aiExplanation || "",
      ai_recommendation: c.investigation?.recommendation?.action || null,
      iocs: c.iocs || {},
      status: c.status || "Pending Review",
      assigned_to: c.assignedTo || null,
      screenshotDataUrl: c.screenshotDataUrl || null,
      reasoning: c.reasoning || [],
      urls: c.urls,
      emails: c.emails,
      phones: c.phones,
      campaignId: c.campaignId,
      investigation: c.investigation || null,
      decision: c.decision || null,
    });

    if (c.submittedAt) row.created_at = c.submittedAt;

    const { error } = await sb.from("fraud_cases").upsert(row, { onConflict: "case_id" });
    if (error) {
      failed += 1;
      console.log("fail=" + c.id + " msg=" + error.message);
    } else {
      ok += 1;
    }
  }

  const { count } = await sb.from("fraud_cases").select("*", { count: "exact", head: true });
  console.log("migrated=" + ok);
  console.log("failed=" + failed);
  console.log("supabase_total=" + (count ?? 0));
})();
