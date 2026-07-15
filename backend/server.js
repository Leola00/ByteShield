const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env"), override: true });
const { spawn } = require("child_process");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const OpenAI = require("openai");
const analytics = require("./analytics");
const casesStore = require("./cases");
const investigation = require("./investigation");
const { getPublicConfig, isConfigured: isSupabaseConfigured } = require("./supabase");
const fraudCasesService = require("./services/fraudCasesService");
const { createFraudOpsRouter } = require("./routes/fraudOps");
const { createOpsExtrasRouter } = require("./routes/opsExtras");
const { buildCampaignsFromCases } = require("./services/campaignsService");

const app = express();

app.use(cors());
app.use(express.json({ limit: "12mb" }));

if (!process.env.OPENAI_API_KEY) {
  console.warn("âڑ ï¸ڈ OPENAI_API_KEY not set â€” /analyze and /chat disabled; /predict-url still works");
}

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

const ANALYZE_PROMPT = `You are ByteShield, a professional cybersecurity analysis engine for users in Saudi Arabia.

Analyze messages for financial fraud, phishing, and social engineering.

Scoring rubric (be consistent â€” same message آ±3 points):
- 0-30 = Low Risk / Safe
- 31-60 = Medium Risk / Suspicious
- 61-100 = High Risk

Return user-facing text in Arabic. JSON field names stay in English.

Return ONLY valid JSON:
{
  "riskScore": 0,
  "classification": "Low Risk | Medium Risk | High Risk",
  "statusMessage": "Large status with emoji: âœ… safe | âڑ ï¸ڈ suspicious | ًںڑ¨ high risk (in Arabic)",
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

const VISION_EXTRA = `You are analyzing visual content: a screenshot, photo, or scanned PDF page.

Read all visible text carefully (Arabic and English). Note logos, bank names, messaging apps (WhatsApp, SMS, email), URLs, phone numbers, urgency language, OTP/password requests, and fake official branding.
Evaluate whether the content is legitimate or a fraud/phishing attempt.`;

const ALLOWED_FILE_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
  "application/pdf",
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_FILE_TYPES.has(file.mimetype)) {
      cb(null, true);
      return;
    }
    cb(new Error("Unsupported file type. Upload an image (JPG, PNG, WebP, GIF) or PDF."));
  },
});

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
const PYTHON_ARGS = (process.env.PYTHON_ARGS || "").trim()
  ? process.env.PYTHON_ARGS.trim().split(/\s+/).filter(Boolean)
  : [];
const ML_PREDICT_SCRIPT = path.join(__dirname, "ml", "predict_url.py");
const FINANCIAL_FORECAST_SCRIPT = path.join(__dirname, "ml", "predict_financial_risk.py");
const SOC_REPORT_SCRIPT = path.join(__dirname, "app.py");

function getOpenAiModel() {
  return process.env.OPENAI_MODEL || "gpt-4o-mini";
}

async function callOpenAiJson(systemPrompt, userContent) {
  const completion = await openai.chat.completions.create({
    model: getOpenAiModel(),
    temperature: 0,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userContent },
    ],
    response_format: { type: "json_object" },
  });

  const content = completion.choices[0]?.message?.content;
  if (!content) {
    throw new Error("No response from OpenAI");
  }

  return JSON.parse(content);
}

async function callOpenAiVision(userContentParts) {
  const completion = await openai.chat.completions.create({
    model: process.env.OPENAI_VISION_MODEL || getOpenAiModel(),
    temperature: 0,
    messages: [
      { role: "system", content: `${ANALYZE_PROMPT}\n\n${VISION_EXTRA}` },
      { role: "user", content: userContentParts },
    ],
    response_format: { type: "json_object" },
  });

  const content = completion.choices[0]?.message?.content;
  if (!content) {
    throw new Error("No response from OpenAI");
  }

  return JSON.parse(content);
}

async function pdfPagesToImages(buffer, maxPages = 3) {
  const { pdf } = await import("pdf-to-img");
  const doc = await pdf(buffer, { scale: 2 });
  const images = [];

  for await (const page of doc) {
    images.push({
      mime: "image/png",
      base64: Buffer.from(page).toString("base64"),
    });
    if (images.length >= maxPages) {
      break;
    }
  }

  return images;
}

async function analyzePdfBuffer(buffer) {
  const data = await pdfParse(buffer);
  const text = String(data.text || "").replace(/\s+/g, " ").trim();

  if (text.length >= 80) {
    const excerpt = text.slice(0, 12000);
    return callOpenAiJson(
      ANALYZE_PROMPT,
      `[ظ…ط­طھظˆظ‰ ظ…ط³طھط®ط±ط¬ ظ…ظ† ظ…ظ„ظپ PDF â€” ${data.numpages || "?"} طµظپط­ط©]\n\n${excerpt}`
    );
  }

  const pageImages = await pdfPagesToImages(buffer);
  if (!pageImages.length) {
    throw new Error("Could not read PDF pages");
  }

  const parts = [
    {
      type: "text",
      text: "This is a scanned PDF. Analyze every page image for financial fraud, phishing, and social engineering. Read all visible Arabic and English text.",
    },
    ...pageImages.map((img) => ({
      type: "image_url",
      image_url: {
        url: `data:${img.mime};base64,${img.base64}`,
        detail: "high",
      },
    })),
  ];

  return callOpenAiVision(parts);
}

async function analyzeImageBuffer(buffer, mimeType) {
  const base64 = buffer.toString("base64");
  return callOpenAiVision([
    {
      type: "text",
      text: "Analyze this screenshot or photo for financial fraud, phishing, and social engineering. Read all visible text and UI elements.",
    },
    {
      type: "image_url",
      image_url: {
        url: `data:${mimeType};base64,${base64}`,
        detail: "high",
      },
    },
  ]);
}

function runSocReport(payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, [...PYTHON_ARGS, SOC_REPORT_SCRIPT], {
      cwd: __dirname,
      windowsHide: true,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
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

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();

    child.on("close", (code) => {
      const output = stdout.trim();

      if (output) {
        try {
          const parsed = JSON.parse(output);
          if (code !== 0) {
            reject(new Error(parsed.error || stderr.trim() || `SOC report generator exited with code ${code}`));
            return;
          }
          resolve(parsed);
          return;
        } catch {
          // fall through
        }
      }

      if (code !== 0) {
        reject(new Error(stderr.trim() || `SOC report generator exited with code ${code}`));
        return;
      }

      reject(new Error("Invalid JSON from SOC report generator"));
    });
  });
}

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

function runFinancialForecast(payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, [...PYTHON_ARGS, FINANCIAL_FORECAST_SCRIPT], {
      cwd: __dirname,
      windowsHide: true,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
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

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();

    child.on("close", (code) => {
      const output = stdout.trim();

      if (output) {
        try {
          const parsed = JSON.parse(output);
          if (code !== 0) {
            reject(new Error(parsed.error || stderr.trim() || `Financial forecast exited with code ${code}`));
            return;
          }
          resolve(parsed);
          return;
        } catch {
          // fall through
        }
      }

      if (code !== 0) {
        reject(new Error(stderr.trim() || `Financial forecast exited with code ${code}`));
        return;
      }

      reject(new Error("Invalid JSON from financial forecast generator"));
    });
  });
}

function recordAnalysisIncident(text, data) {
  try {
    analytics.saveIncident({
      text,
      score: Number(data.riskScore) || 0,
      classification: data.classification || analytics.classificationFromScore(data.riskScore),
    });
  } catch (error) {
    console.error("Analytics save error:", error);
  }
}

function buildMlUrlReport(url, ml) {
  const score = Number(ml.riskScore) || 0;
  const tier =
    score <= 30 ? "Low Risk" : score <= 60 ? "Medium Risk" : "High Risk";
  const probability = Number(ml.phishingProbability) || 0;
  const confidence = Number(ml.confidence) || Math.round(Math.abs(probability - 0.5) * 200);

  const statusMessage =
    score <= 30
      ? "âœ… ظٹط¨ط¯ظˆ ط§ظ„ط±ط§ط¨ط· ط¢ظ…ظ†ط§ظ‹ ظ†ط³ط¨ظٹط§ظ‹"
      : score <= 60
        ? "âڑ ï¸ڈ ط§ظ„ط±ط§ط¨ط· ظ…ط´ط¨ظˆظ‡ â€” طھط­ظ‚ظ‚ ظ‚ط¨ظ„ ط§ظ„ظ†ظ‚ط±"
        : "ًںڑ¨ ط§ط­طھظ…ط§ظ„ ط¹ط§ظ„ظچ ط£ظ† ط§ظ„ط±ط§ط¨ط· طھطµظٹظ‘ط¯";

  const shortExplanation =
    score <= 30
      ? "ظٹط¨ط¯ظˆ ط£ظ† ظ‡ط°ط§ ط§ظ„ط±ط§ط¨ط· ط¢ظ…ظ†ط§ظ‹ ظ†ط³ط¨ظٹط§ظ‹. طھط­ظ‚ظ‚ ط¯ط§ط¦ظ…ط§ظ‹ ظ…ظ† ط§ظ„ط¹ظ†ظˆط§ظ† ظپظٹ ط§ظ„ظ…طھطµظپط­ ظ‚ط¨ظ„ ط¥ط¯ط®ط§ظ„ ط£ظٹ ط¨ظٹط§ظ†ط§طھ."
      : score <= 60
        ? "ظ‡ط°ط§ ط§ظ„ط±ط§ط¨ط· ظٹط­طھظˆظٹ ط¹ظ„ظ‰ ط¹ظ„ط§ظ…ط§طھ ظ…ط´ط¨ظˆظ‡ط©. ظ„ط§ طھظ†ظ‚ط± ط¹ظ„ظٹظ‡ ظ‚ط¨ظ„ ط§ظ„طھط£ظƒط¯ ظ…ظ† ظ…طµط¯ط±ظ‡ ط¹ط¨ط± ط§ظ„ظ‚ظ†ظˆط§طھ ط§ظ„ط±ط³ظ…ظٹط©."
        : "ظ‡ط°ط§ ط§ظ„ط±ط§ط¨ط· ظٹط­ظ…ظ„ ط§ط­طھظ…ط§ظ„ط§ظ‹ ط¹ط§ظ„ظٹط§ظ‹ ظ„طھطµظٹظ‘ط¯ ط§ط­طھظٹط§ظ„ظٹ. ظ„ط§ طھظپطھط­ظ‡ ظˆظ„ط§ طھظڈط¯ط®ظ„ ط¨ظٹط§ظ†ط§طھظƒ ط§ظ„ط´ط®طµظٹط© ط£ظˆ ط§ظ„ظ…طµط±ظپظٹط©.";

  const reasoning =
    score <= 30
      ? ["ظ„ظ… ظٹظڈط±طµط¯ ظ†ظ…ط· ظ…ط´ط¨ظˆظ‡ ظ‚ظˆظٹ ظپظٹ ط¹ظ†ظˆط§ظ† ط§ظ„ط±ط§ط¨ط·", "ظٹط¨ط¯ظˆ ظ‚ط±ظٹط¨ط§ظ‹ ظ…ظ† ط§ظ„ط±ظˆط§ط¨ط· ط§ظ„ط¢ظ…ظ†ط© â€” طھط­ظ‚ظ‚ ط¨ط´ظƒظ„ ظ…ط³طھظ‚ظ„"]
      : score <= 60
        ? ["ط¨ط¹ط¶ ط®طµط§ط¦طµ ط§ظ„ط±ط§ط¨ط· طھط´ط¨ظ‡ ظ…ظˆط§ظ‚ط¹ ط§ظ„طھطµظٹظ‘ط¯", "ظٹظڈظ†طµط­ ط¨ط§ظ„طھط­ظ‚ظ‚ ظ‚ط¨ظ„ ط§ظ„ظ†ظ‚ط± ط£ظˆ ط¥ط¯ط®ط§ظ„ ط£ظٹ ط¨ظٹط§ظ†ط§طھ"]
        : [
            "ط¹ظ†ظˆط§ظ† ط§ظ„ط±ط§ط¨ط· ظٹط´ط¨ظ‡ ظ…ظˆط§ظ‚ط¹ ط¨ظ†ظƒظٹط© ط£ظˆ ط®ط¯ظ…ط§طھ ظ…ظˆط«ظˆظ‚ط© ط¨ط´ظƒظ„ ظ…ط¶ظ„ظ„",
            "ظ„ط§ طھظ†ظ‚ط± ط¹ظ„ظ‰ ط§ظ„ط±ط§ط¨ط· ظ‚ط¨ظ„ ط§ظ„طھط­ظ‚ظ‚ ط¹ط¨ط± طھط·ط¨ظٹظ‚ ط§ظ„ط¨ظ†ظƒ ط£ظˆ ط§ظ„ظ…ظˆظ‚ط¹ ط§ظ„ط±ط³ظ…ظٹ",
            "ظ„ط§ طھط´ط§ط±ظƒ ط±ظ…ط² ط§ظ„طھط­ظ‚ظ‚ ط£ظˆ ظƒظ„ظ…ط© ط§ظ„ظ…ط±ظˆط± ط¹ط¨ط± ط£ظٹ ط±ط§ط¨ط· ظ…ط³طھظ„ظ…",
          ];

  const detailedAnalysis = [
    shortExplanation,
    "",
    `ط§ظ„ط±ط§ط¨ط· ط§ظ„ط°ظٹ طھظ… ظپط­طµظ‡: ${url}`,
    "",
    "ظ…ط§ ط§ظ„ط°ظٹ ظ„ط§ط­ط¸ظ†ط§ظ‡:",
    ...reasoning.map((line) => `â€¢ ${line}`),
  ].join("\n");

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
            "ظ„ط§ طھظ†ظ‚ط± ط¹ظ„ظ‰ ط§ظ„ط±ط§ط¨ط·",
            "ط§ظƒطھط¨ ط¹ظ†ظˆط§ظ† ط§ظ„ظ…ظˆظ‚ط¹ ط§ظ„ط±ط³ظ…ظٹ ظٹط¯ظˆظٹط§ظ‹ ظپظٹ ط§ظ„ظ…طھطµظپط­",
            "طھط­ظ‚ظ‚ ظ…ظ† ط§ظ„ظ†ط·ط§ظ‚ ط¹ط¨ط± ط§ظ„ظ‚ظ†ظˆط§طھ ط§ظ„ط±ط³ظ…ظٹط©",
            "ط£ط¨ظ„ط؛ ط¹ظ† ط§ظ„ط±ط§ط¨ط· ط¥ط°ط§ طھط£ظƒط¯طھ ط£ظ†ظ‡ ط§ط­طھظٹط§ظ„",
          ]
        : score >= 31
          ? [
              "طھط­ظ‚ظ‚ ظ…ظ† ط§ظ„ظ†ط·ط§ظ‚ ظ‚ط¨ظ„ ط§ظ„ظ†ظ‚ط±",
              "ظ‚ط§ط±ظ† ط§ظ„ط±ط§ط¨ط· ط¨ط§ظ„ظ…ظˆظ‚ط¹ ط§ظ„ط±ط³ظ…ظٹ ظ„ظ„ط¬ظ‡ط©",
              "ظ„ط§ طھط¯ط®ظ„ ط¨ظٹط§ظ†ط§طھ ط­ط³ط§ط³ط© ط­طھظ‰ طھطھط£ظƒط¯",
            ]
          : [
              "ظٹط¨ط¯ظˆ ط¢ظ…ظ†ط§ظ‹ ظ†ط³ط¨ظٹط§ظ‹ â€” طھط­ظ‚ظ‚ ط¯ط§ط¦ظ…ط§ظ‹ ط¨ط´ظƒظ„ ظ…ط³طھظ‚ظ„",
              "ط§ظƒطھط¨ ط¹ظ†ظˆط§ظ† ط§ظ„ظ…ظˆظ‚ط¹ ظٹط¯ظˆظٹط§ظ‹ ط¹ظ†ط¯ ط§ظ„ط´ظƒ",
            ],
    riskBreakdown: {
      senderAuthenticity: Math.round(score * 0.4),
      languageAnalysis: Math.round(score * 0.3),
      linkSafety: score,
      financialFraudIndicators: Math.round(score * 0.85),
      socialEngineeringIndicators: Math.round(score * 0.5),
      urgencyDetection: Math.round(score * 0.35),
    },
    detailedAnalysis,
    detectedBanks: [],
    bankAdvice: "",
    threatType: "phishing",
    securityTips: [
      "ظ„ط§ طھط«ظ‚ ط¨ط§ظ„ط±ظˆط§ط¨ط· ظپظٹ ط§ظ„ط±ط³ط§ط¦ظ„ â€” ط§ظƒطھط¨ ط¹ظ†ظˆط§ظ† ط§ظ„ظ…ظˆظ‚ط¹ ظٹط¯ظˆظٹط§ظ‹",
      "ط§ظ„ط¨ظ†ظˆظƒ ظ„ط§ طھط·ظ„ط¨ OTP ط¹ط¨ط± ط§ظ„ط±ط³ط§ط¦ظ„",
      "طھط­ظ‚ظ‚ ظ…ظ† ظ‡ظˆظٹط© ط§ظ„ظ…ط±ط³ظ„ ظ‚ط¨ظ„ ط£ظٹ ط¥ط¬ط±ط§ط،",
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

    const data = buildMlUrlReport(String(url).trim(), ml);
    recordAnalysisIncident(String(url).trim(), data);

    res.json({
      success: true,
      data,
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

    const data = await callOpenAiJson(ANALYZE_PROMPT, text);
    recordAnalysisIncident(text, data);

    res.json({
      success: true,
      data,
    });
  } catch (error) {
    console.error("OpenAI Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.post("/analyze-file", upload.single("file"), async (req, res) => {
  try {
    if (!openai) {
      return res.status(503).json({
        success: false,
        error: "OpenAI is not configured. Set OPENAI_API_KEY in backend/.env",
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No file uploaded",
      });
    }

    const { buffer, mimetype, originalname } = req.file;
    let data;

    if (mimetype === "application/pdf") {
      data = await analyzePdfBuffer(buffer);
    } else if (mimetype.startsWith("image/")) {
      data = await analyzeImageBuffer(buffer, mimetype);
    } else {
      return res.status(400).json({
        success: false,
        error: "Unsupported file type",
      });
    }

    const responseData = {
      ...data,
      fileName: originalname,
      fileType: mimetype,
    };
    recordAnalysisIncident(`[file: ${originalname}]`, responseData);

    res.json({
      success: true,
      data: responseData,
    });
  } catch (error) {
    console.error("File Analysis Error:", error);

    const message = error.message || "File analysis failed";
    const userMessage =
      message.includes("Could not read PDF") || message.includes("PDF")
        ? "ظ„ظ… ظ†طھظ…ظƒظ† ظ…ظ† ظ‚ط±ط§ط،ط© PDF â€” ط¬ط±ظ‘ط¨ ط±ظپط¹ ظ„ظ‚ط·ط© ط´ط§ط´ط© ظ„ظ„ظ…ط­طھظˆظ‰"
        : message;

    res.status(500).json({
      success: false,
      error: userMessage,
    });
  }
});

app.use((err, _req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        success: false,
        error: "File too large â€” maximum size is 10 MB",
      });
    }
    return res.status(400).json({ success: false, error: err.message });
  }

  if (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  return next();
});

app.post("/soc-report", async (req, res) => {
  try {
    const { text, contentType, triage } = req.body;

    if (!text || !String(text).trim()) {
      return res.status(400).json({
        success: false,
        error: "No evidence text provided",
      });
    }

    const result = await runSocReport({
      text: String(text).trim(),
      contentType: contentType || "Message",
      triage: triage || {},
    });

    if (!result.success) {
      return res.status(500).json({
        success: false,
        error: result.error || "SOC report generation failed",
      });
    }

    res.json({
      success: true,
      data: result.data,
    });
  } catch (error) {
    console.error("SOC Report Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.post("/api/financial-forecast", async (req, res) => {
  try {
    const {
      text,
      riskScore,
      classification,
      estimatedLossSAR,
      riskBreakdown,
      contentType,
    } = req.body;

    const score = Number(riskScore) || 0;
    const resolvedClassification =
      classification || analytics.classificationFromScore(score);
    const estimatedLoss =
      estimatedLossSAR ??
      analytics.estimateFinancialLoss(resolvedClassification, String(text || ""));

    const result = await runFinancialForecast({
      text: String(text || ""),
      riskScore: score,
      classification: resolvedClassification,
      estimatedLossSAR: estimatedLoss,
      riskBreakdown: riskBreakdown || {},
      contentType: contentType || "Message",
    });

    if (!result.success) {
      return res.status(500).json({
        success: false,
        error: result.error || "Financial forecast failed",
      });
    }

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    console.error("Financial Forecast Error:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

app.get("/api/analytics", (_req, res) => {
  try {
    res.json({
      success: true,
      metrics: analytics.getMetrics(),
    });
  } catch (error) {
    console.error("Analytics Error:", error);
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

/* --- Fraud Operations case APIs --- */

// Inject frontend Supabase env (anon key only — safe for browser)
app.get("/js/supabase-env.js", (_req, res) => {
  const cfg = getPublicConfig();
  res.type("application/javascript");
  res.set("Cache-Control", "no-store");
  res.send(
    `window.__BYTESHIELD_SUPABASE__=${JSON.stringify({
      url: cfg.url,
      anonKey: cfg.anonKey,
      configured: cfg.configured,
    })};`,
  );
});

app.get("/api/supabase-config", (_req, res) => {
  const cfg = getPublicConfig();
  res.json({
    success: true,
    configured: isSupabaseConfigured || cfg.configured,
    url: cfg.url || null,
  });
});

// POST /api/report · GET|POST /api/cases · GET|PATCH /api/cases/:id · POST /api/cases/:id/decision
app.use(
  "/api",
  createFraudOpsRouter({
    casesStore,
    investigation,
    openai,
    callOpenAiJson,
  }),
);

// Auth, analysts, internal notes
app.use("/api", createOpsExtrasRouter());

app.post("/api/cases/:id/investigate", async (req, res) => {
  try {
    let found = null;
    if (fraudCasesService.isConfigured) {
      found = await fraudCasesService.getCaseByIdOrCaseId(req.params.id);
    } else {
      found = await casesStore.getCaseById(req.params.id);
    }
    if (!found) {
      return res.status(404).json({ success: false, error: "Case not found" });
    }

    const package_ = await investigation.generateInvestigation(openai, callOpenAiJson, found);
    let saved;
    if (fraudCasesService.isConfigured) {
      saved = await fraudCasesService.patchCase(found.id, {
        investigation: package_,
        status: found.status === "Closed" ? "Closed" : "Under Review",
        assigned_to: found.assignedTo || "Analyst",
        ai_summary: package_?.aiInvestigationSummary || found.aiSummary,
        ai_recommendation: package_?.recommendation?.action || found.aiRecommendation,
      });
    } else {
      saved = await casesStore.updateCase(found.id, (c) => ({
        ...c,
        investigation: package_,
        status: c.status === "Closed" ? "Closed" : "Under Review",
        assignedTo: c.assignedTo || "Analyst",
      }));
    }
    res.json({ success: true, case: saved });
  } catch (error) {
    console.error("Investigate Case Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/campaigns", async (_req, res) => {
  try {
    if (fraudCasesService.isConfigured) {
      const cases = await fraudCasesService.listAllCases();
      return res.json({
        success: true,
        source: "derived",
        campaigns: buildCampaignsFromCases(cases),
      });
    }
    res.json({ success: true, source: "local", campaigns: await casesStore.listCampaigns() });
  } catch (error) {
    console.error("Campaigns Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/cases/:id/copilot", async (req, res) => {
  try {
    if (!openai) {
      return res.status(503).json({
        success: false,
        error: "OpenAI is not configured. Set OPENAI_API_KEY in backend/.env",
      });
    }

    let found = null;
    if (fraudCasesService.isConfigured) {
      found = await fraudCasesService.getCaseByIdOrCaseId(req.params.id);
    } else {
      found = await casesStore.getCaseById(req.params.id);
    }
    if (!found) {
      return res.status(404).json({ success: false, error: "Case not found" });
    }

    const { messages } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ success: false, error: "No messages provided" });
    }

    const systemContent = `${investigation.COPILOT_PROMPT}\n\n--- Current case ---\n${investigation.buildCaseContext(found)}`;

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      temperature: 0.25,
      messages: [
        { role: "system", content: systemContent },
        ...messages.slice(-12).map((m) => ({
          role: m.role === "user" ? "user" : "assistant",
          content: String(m.content || ""),
        })),
      ],
    });

    const reply = completion.choices[0]?.message?.content;
    if (!reply) throw new Error("No response from OpenAI");

    res.json({ success: true, reply });
  } catch (error) {
    console.error("Copilot Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.use(express.static(path.join(__dirname, "..")));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 ByteShield running on http://localhost:${PORT}`);
  if (openai) {
    console.log("✅ OpenAI configured — /analyze, /chat, and Fraud Ops enabled");
  }
  if (isSupabaseConfigured) {
    console.log("✅ Supabase configured — fraud_cases live storage enabled");
    console.log("   POST /api/report · GET /api/cases · PATCH /api/cases/:id");
  } else {
    console.warn("⚠️ Supabase not configured — using local fraud_cases.json fallback");
    console.warn("   Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in backend/.env");
  }
  console.log("✅ Fraud Operations API ready at /api/cases");
});
