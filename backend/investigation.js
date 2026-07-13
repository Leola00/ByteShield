const cases = require("./cases");

const INVESTIGATION_PROMPT = `You are ByteShield Fraud Operations AI for a Saudi bank fraud investigation team.

You receive a customer-submitted fraud report that has already been scored by the first-line AI.
Your job is to produce an investigation-ready package for a human fraud analyst.
Do NOT replace the analyst. Provide clear, actionable decision support.

Return ONLY valid JSON with this exact shape:
{
  "aiInvestigationSummary": "2-3 sentences describing the incident for the analyst",
  "recommendation": {
    "action": "Block Sender | Block Domain | Escalate to Fraud Team | Notify Customer | Continue Monitoring | False Positive",
    "rationale": "1-2 sentences explaining why this action is recommended",
    "confidence": 0-100
  },
  "executiveInvestigationSummary": "Short executive summary for leadership (3-5 sentences)",
  "technicalInvestigationSummary": "Technical summary covering IOCs, attack pattern, and evidence (4-6 sentences)",
  "customerNotificationDraft": "Professional customer notification draft Alinma Bank can send (English, polite, clear next steps). Sign as 'Alinma Bank'.",
  "managementSummary": "1 short paragraph for management on risk and recommended response",
  "investigationNotes": ["note 1", "note 2", "note 3", "note 4"]
}

Rules:
- Prefer precise actions. If clearly phishing with malicious domain/sender, recommend Block Domain or Block Sender.
- If ambiguous, recommend Continue Monitoring or Escalate to Fraud Team.
- If clearly benign, recommend False Positive.
- Always write in English for Fraud Operations.
- Never invent IOCs that are not present in the evidence.`;

const COPILOT_PROMPT = `You are ByteShield Fraud Ops Copilot for bank fraud analysts in Saudi Arabia.

You already know the current fraud case context (evidence, AI score, IOCs, recommendation).
Answer professional fraud investigation questions clearly and concisely in English.

Rules:
- Support the analyst; never claim to make the final decision.
- Do not ask for customer passwords, OTP, or card numbers.
- Prefer actionable investigation guidance (containment, customer outreach, IOC blocking).
- Reference SAMA / banking fraud practice when relevant.
- Keep answers short unless the analyst asks for detail.`;

function buildLocalInvestigation(caseRecord) {
  const score = Number(caseRecord.fraudProbability) || 0;
  const domains = caseRecord.iocs?.domains || [];
  const emails = caseRecord.iocs?.emails || [];
  const category = caseRecord.fraudCategory || caseRecord.threatType || "fraud";

  let action = "Continue Monitoring";
  if (score >= 75 && domains.length) action = "Block Domain";
  else if (score >= 75 && emails.length) action = "Block Sender";
  else if (score >= 61) action = "Escalate to Fraud Team";
  else if (score >= 31) action = "Notify Customer";
  else action = "False Positive";

  const summary =
    `Customer reported a ${category.replace(/_/g, " ")} case with fraud probability ${score}/100. ` +
    `Primary evidence type: ${caseRecord.contentType || "Message"}. ` +
    (domains[0]
      ? `Key domain indicator: ${domains[0]}.`
      : emails[0]
        ? `Key sender indicator: ${emails[0]}.`
        : "No strong domain/email IOC extracted.");

  return {
    aiInvestigationSummary: summary,
    recommendation: {
      action,
      rationale: `Based on score ${score}/100 and extracted indicators, ${action} is the most appropriate next step for analyst review.`,
      confidence: Math.min(95, Math.max(40, score)),
    },
    executiveInvestigationSummary:
      `A customer submitted a potential ${category.replace(/_/g, " ")} report. ` +
      `AI assessed fraud probability at ${score}/100. ` +
      `Recommended analyst action: ${action}. ` +
      `Human confirmation is required before containment.`,
    technicalInvestigationSummary:
      `Evidence type: ${caseRecord.contentType}. ` +
      `IOCs — domains: ${(domains || []).join(", ") || "none"}; ` +
      `URLs: ${(caseRecord.iocs?.urls || []).slice(0, 3).join(", ") || "none"}; ` +
      `emails: ${(emails || []).join(", ") || "none"}; ` +
      `phones: ${(caseRecord.iocs?.phones || []).join(", ") || "none"}. ` +
      `Customer explanation from first-line AI: ${caseRecord.aiExplanation || "n/a"}.`,
    customerNotificationDraft:
      `Dear Customer,\n\nThank you for reporting this suspicious message through ByteShield. ` +
      `Our Fraud Operations team is reviewing the case. Please do not click any links, share OTP codes, or provide account credentials. ` +
      `If you already interacted with the message, contact official bank support immediately.\n\nBest regards,\nAlinma Bank`,
    managementSummary:
      `Fraud Ops received a customer report scored ${score}/100 (${category}). ` +
      `Recommended action pending analyst decision: ${action}.`,
    investigationNotes: [
      `Case ${caseRecord.id} ingested from Personal Protection report.`,
      `Fraud probability: ${score}/100.`,
      `Category: ${category}.`,
      `Campaign linkage: ${caseRecord.campaignId || "none"}.`,
      "Analyst must Approve, Modify, or Reject the AI recommendation.",
    ],
    source: "local",
  };
}

async function generateInvestigation(openai, callOpenAiJson, caseRecord) {
  if (!openai || !callOpenAiJson) {
    return buildLocalInvestigation(caseRecord);
  }

  const userPayload = {
    caseId: caseRecord.id,
    contentType: caseRecord.contentType,
    fraudProbability: caseRecord.fraudProbability,
    fraudCategory: caseRecord.fraudCategory,
    aiExplanation: caseRecord.aiExplanation,
    reasoning: caseRecord.reasoning,
    iocs: caseRecord.iocs,
    content: String(caseRecord.content || "").slice(0, 6000),
  };

  try {
    const data = await callOpenAiJson(
      INVESTIGATION_PROMPT,
      `Produce the investigation package for this case:\n${JSON.stringify(userPayload, null, 2)}`,
    );

    return {
      aiInvestigationSummary: data.aiInvestigationSummary || "",
      recommendation: {
        action: data.recommendation?.action || "Continue Monitoring",
        rationale: data.recommendation?.rationale || "",
        confidence: Number(data.recommendation?.confidence) || 60,
      },
      executiveInvestigationSummary: data.executiveInvestigationSummary || "",
      technicalInvestigationSummary: data.technicalInvestigationSummary || "",
      customerNotificationDraft: data.customerNotificationDraft || "",
      managementSummary: data.managementSummary || "",
      investigationNotes: Array.isArray(data.investigationNotes)
        ? data.investigationNotes
        : [],
      source: "openai",
    };
  } catch (err) {
    console.error("Investigation generation failed, using local fallback:", err.message);
    return buildLocalInvestigation(caseRecord);
  }
}

function buildCaseContext(caseRecord) {
  const inv = caseRecord.investigation || {};
  return [
    `Case ID: ${caseRecord.id}`,
    `Status: ${caseRecord.status}`,
    `Fraud probability: ${caseRecord.fraudProbability}/100`,
    `Category: ${caseRecord.fraudCategory}`,
    `Submitted: ${caseRecord.submittedAt}`,
    `AI explanation: ${caseRecord.aiExplanation || ""}`,
    `Recommendation: ${inv.recommendation?.action || "n/a"} — ${inv.recommendation?.rationale || ""}`,
    `Summary: ${inv.aiInvestigationSummary || ""}`,
    `IOCs: ${JSON.stringify(caseRecord.iocs || {})}`,
    `Evidence:\n${String(caseRecord.content || "").slice(0, 4000)}`,
  ].join("\n");
}

module.exports = {
  INVESTIGATION_PROMPT,
  COPILOT_PROMPT,
  buildLocalInvestigation,
  generateInvestigation,
  buildCaseContext,
};
