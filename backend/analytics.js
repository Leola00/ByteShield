const fs = require("fs");
const path = require("path");

const DB_FILE = path.join(__dirname, "byteshield_incidents.json");

function loadIncidents() {
  try {
    if (!fs.existsSync(DB_FILE)) return [];
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function persistIncidents(incidents) {
  fs.writeFileSync(DB_FILE, JSON.stringify(incidents, null, 2), "utf8");
}

function classificationFromScore(score) {
  const n = Number(score) || 0;
  if (n >= 61) return "High Risk";
  if (n >= 31) return "Medium Risk";
  return "Low Risk";
}

function estimateFinancialLoss(classification, text) {
  const cls = String(classification || "");
  const lower = String(text || "").toLowerCase();
  const isHigh = cls.includes("High") || cls.includes("خطر مرتفع");
  const isMedium = cls.includes("Medium") || cls.includes("Suspicious") || cls.includes("مشبوه");

  if (isHigh) {
    if (["ceo", "manager", "مدير", "رئيس"].some((word) => lower.includes(word))) {
      return 50000;
    }
    return 5000;
  }
  if (isMedium) return 1500;
  return 0;
}

function saveIncident({ text, score, classification }) {
  const resolvedClassification = classification || classificationFromScore(score);
  const estimatedLoss = estimateFinancialLoss(resolvedClassification, text);
  const incidents = loadIncidents();

  incidents.push({
    timestamp: new Date().toISOString(),
    input_text: String(text || "").slice(0, 5000),
    risk_score: Number(score) || 0,
    classification: resolvedClassification,
    estimated_loss: estimatedLoss,
  });

  persistIncidents(incidents);
  return estimatedLoss;
}

function getMetrics() {
  const incidents = loadIncidents();
  const totalIncidents = incidents.length;
  const highRiskCount = incidents.filter(
    (row) => row.classification === "High Risk" || (row.risk_score || 0) >= 61,
  ).length;
  const totalSavedMoneySAR = incidents.reduce(
    (sum, row) => sum + (Number(row.estimated_loss) || 0),
    0,
  );
  const averageLossPerIncidentSAR =
    totalIncidents > 0 ? Math.round(totalSavedMoneySAR / totalIncidents) : 0;

  return {
    totalIncidents,
    highRiskCount,
    totalSavedMoneySAR,
    averageLossPerIncidentSAR,
  };
}

module.exports = {
  saveIncident,
  getMetrics,
  classificationFromScore,
  estimateFinancialLoss,
};
