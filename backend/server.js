require("dotenv").config();

const path = require("path");
const { spawn } = require("child_process");
const express = require("express");
const cors = require("cors");
const OpenAI = require("openai");

const app = express();

app.use(cors());
app.use(express.json());

if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ OPENAI_API_KEY not set — /analyze and /chat disabled; /predict-url still works");
}

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

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

const PYTHON_BIN = process.env.PYTHON_BIN || "py";
const PYTHON_ARGS = process.env.PYTHON_ARGS ? process.env.PYTHON_ARGS.split(" ") : ["-3"];
const ML_PREDICT_SCRIPT = path.join(__dirname, "ml", "predict_url.py");

function runUrlMlPrediction(url) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, [...PYTHON_ARGS, ML_PREDICT_SCRIPT, url], {
      cwd: __dirname,
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      reject(error);
    });

    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `ML predictor exited with code ${code}`));
        return;
      }

      try {
        resolve(JSON.parse(stdout.trim()));
      } catch {
        reject(new Error("Invalid JSON from ML predictor"));
      }
    });
  });
}

function buildMlUrlReport(url, ml) {
  const score = Number(ml.riskScore) || 0;
  const tier =
    score <= 30 ? "Low Risk" : score <= 60 ? "Medium Risk" : "High Risk";
  const probability = Number(ml.phishingProbability) || 0;
  const confidence = Number(ml.confidence) || Math.round(Math.abs(probability - 0.5) * 200);

  const statusMessage =
    score <= 30
      ? "✅ يبدو الرابط آمناً وفق نموذج التعلم العميق"
      : score <= 60
        ? "⚠️ الرابط مشبوه وفق نموذج التعلم العميق"
        : "🚨 احتمال عالٍ أن الرابط تصيّد وفق نموذج التعلم العميق";

  const shortExplanation =
    score <= 30
      ? `حلّل نموذج ByteShield Deep Learning الرابط وأعطاه درجة ${score}/100 (منخفض المخاطر). احتمال التصيّد ${Math.round(probability * 100)}%.`
      : score <= 60
        ? `حلّل نموذج ByteShield Deep Learning الرابط وأعطاه درجة ${score}/100 (مشبوه). احتمال التصيّد ${Math.round(probability * 100)}%.`
        : `حلّل نموذج ByteShield Deep Learning الرابط وأعطاه درجة ${score}/100 (خطر مرتفع). احتمال التصيّد ${Math.round(probability * 100)}%.`;

  const reasoning =
    score <= 30
      ? ["لم يُرصد نمط URL مشبوه قوي", "الخصائص الهيكلية للرابط قريبة من الروابط الآمنة"]
      : score <= 60
        ? ["بعض خصائص الرابط تشبه أنماط التصيّد", "يُنصح بالتحقق قبل النقر"]
        : [
            "خصائص الرابط تطابق أنماط تصيّد معروفة",
            "احتمال التصيّد مرتفع وفق النموذج المدرب",
            "لا تنقر على الرابط قبل التحقق عبر القنوات الرسمية",
          ];

  return {
    riskScore: score,
    classification: tier,
    statusMessage,
    shortExplanation,
    confidence,
    reasoning,
    actionChecklist:
      score >= 61
        ? [
            "لا تنقر على الرابط",
            "اكتب عنوان الموقع الرسمي يدوياً في المتصفح",
            "تحقق من النطاق عبر القنوات الرسمية",
            "أبلغ عن الرابط إذا تأكدت أنه احتيال",
          ]
        : score >= 31
          ? [
              "تحقق من النطاق قبل النقر",
              "قارن الرابط بالموقع الرسمي للجهة",
              "لا تدخل بيانات حساسة حتى تتأكد",
            ]
          : [
              "يبدو آمناً نسبياً — تحقق دائماً بشكل مستقل",
              "اكتب عنوان الموقع يدوياً عند الشك",
            ],
    riskBreakdown: {
      senderAuthenticity: Math.round(score * 0.4),
      languageAnalysis: Math.round(score * 0.3),
      linkSafety: score,
      financialFraudIndicators: Math.round(score * 0.85),
      socialEngineeringIndicators: Math.round(score * 0.5),
      urgencyDetection: Math.round(score * 0.35),
    },
    detailedAnalysis: `${shortExplanation}\n\nالرابط المحلّل: ${url}\nالنموذج: phishing_dl_model.h5 (${ml.featureCount || 66} خاصية).`,
    detectedBanks: [],
    bankAdvice: "",
    threatType: "phishing",
    securityTips: [
      "لا تثق بالروابط في الرسائل — اكتب عنوان الموقع يدوياً",
      "البنوك لا تطلب OTP عبر الرسائل",
      "تحقق من هوية المرسل قبل أي إجراء",
    ],
    ml: {
      model: ml.model,
      phishingProbability: ml.phishingProbability,
      isPhishing: ml.isPhishing,
    },
    source: "ml",
  };
}

app.post("/predict-url", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || !String(url).trim()) {
      return res.status(400).json({
        success: false,
        error: "No URL provided",
      });
    }

    const ml = await runUrlMlPrediction(String(url).trim());

    if (!ml.success) {
      return res.status(500).json({
        success: false,
        error: ml.error || "ML prediction failed",
      });
    }

    res.json({
      success: true,
      data: buildMlUrlReport(String(url).trim(), ml),
    });
  } catch (error) {
    console.error("ML URL Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.post("/analyze", async (req, res) => {
  try {
    if (!openai) {
      return res.status(503).json({
        success: false,
        error: "OpenAI is not configured. Set OPENAI_API_KEY in backend/.env",
      });
    }

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
    if (!openai) {
      return res.status(503).json({
        success: false,
        error: "OpenAI is not configured. Set OPENAI_API_KEY in backend/.env",
      });
    }

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
