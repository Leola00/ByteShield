require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const OpenAI = require("openai");

const app = express();

app.use(cors());
app.use(express.json());

if (!process.env.OPENAI_API_KEY) {
  console.error("❌ OPENAI_API_KEY not found in .env");
  process.exit(1);
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const ANALYZE_PROMPT = `You are ByteShield, a professional cybersecurity analysis engine for users in Saudi Arabia.

Analyze messages for financial fraud, phishing, and social engineering.

Scoring rubric (be consistent — same message ±3 points):
- 0-30 = Low Risk / Safe
- 31-60 = Medium Risk / Suspicious
- 61-100 = High Risk

Return user-facing text in Arabic. JSON field names stay in English.

Return ONLY valid JSON:
{
  "riskScore": 0,
  "classification": "Low Risk | Medium Risk | High Risk",
  "statusMessage": "Large status with emoji: ✅ safe | ⚠️ suspicious | 🚨 high risk (in Arabic)",
  "shortExplanation": "2-3 sentences in natural Arabic explaining the conclusion",
  "confidence": 85,
  "reasoning": ["bullet point why", "another reason"],
  "actionChecklist": ["action 1", "action 2", "action 3"],
  "riskBreakdown": {
    "senderAuthenticity": 0,
    "languageAnalysis": 0,
    "linkSafety": 0,
    "financialFraudIndicators": 0,
    "socialEngineeringIndicators": 0,
    "urgencyDetection": 0
  },
  "detailedAnalysis": "Full paragraph analysis in Arabic for advanced users",
  "detectedBanks": ["Al Rajhi", "SNB"],
  "bankAdvice": "Arabic advice if a bank is impersonated, else empty string",
  "threatType": "phishing | banking_fraud | investment_scam | delivery_scam | social_engineering | general",
  "securityTips": ["tip 1", "tip 2", "tip 3"]
}

riskBreakdown values are 0-100 risk scores per category (higher = more dangerous).
actionChecklist: 4-6 concrete steps. If safe, use positive cautions.
detectedBanks: Saudi banks if impersonated (Samba, SNB, Al Rajhi, Riyad Bank, Alinma, etc.) or empty array.`;

const CHAT_PROMPT = `You are ByteShield AI, a professional Arabic-speaking cybersecurity assistant in Saudi Arabia.

You have context from the user's fraud analysis. Answer follow-up questions clearly and practically.

Rules:
- Never ask for passwords, OTP, or card numbers
- Never tell users to click suspicious links
- Reference SAMA rules: banks never ask for OTP via SMS/email
- Mention official channels when relevant
- Answer in Arabic unless user writes in English

Saudi resources you may cite:
- SAMA fraud awareness & consumer protection: 8001256666
- Financial fraud reporting: samar.gov.sa
- National Cybersecurity Authority (NCA): ncsc.gov.sa
- Cybercrime reporting: 9200343222
- Emergency: 911`;

app.post("/analyze", async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "No text provided",
      });
    }

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      temperature: 0,
      messages: [
        { role: "system", content: ANALYZE_PROMPT },
        { role: "user", content: text },
      ],
      response_format: { type: "json_object" },
    });

    const content = completion.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from OpenAI");
    }

    res.json({
      success: true,
      data: JSON.parse(content),
    });
  } catch (error) {
    console.error("OpenAI Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.post("/chat", async (req, res) => {
  try {
    const { messages, context } = req.body;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        success: false,
        error: "No messages provided",
      });
    }

    const systemContent = context
      ? `${CHAT_PROMPT}\n\n--- Analysis context ---\n${context}`
      : CHAT_PROMPT;

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      temperature: 0.3,
      messages: [
        { role: "system", content: systemContent },
        ...messages.slice(-12).map((m) => ({
          role: m.role === "user" ? "user" : "assistant",
          content: String(m.content || ""),
        })),
      ],
    });

    const reply = completion.choices[0]?.message?.content;
    if (!reply) {
      throw new Error("No response from OpenAI");
    }

    res.json({ success: true, reply });
  } catch (error) {
    console.error("Chat Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.use(express.static(path.join(__dirname, "..")));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 ByteShield running on http://localhost:${PORT}`);
});
