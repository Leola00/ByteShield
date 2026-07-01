require("dotenv").config();

const path = require("path");
const { spawn } = require("child_process");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const pdfParse = require("pdf-parse");
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
const PYTHON_ARGS = process.env.PYTHON_ARGS ? process.env.PYTHON_ARGS.split(" ") : ["-3"];
const ML_PREDICT_SCRIPT = path.join(__dirname, "ml", "predict_url.py");

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
      `[محتوى مستخرج من ملف PDF — ${data.numpages || "?"} صفحة]\n\n${excerpt}`
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

    const data = await callOpenAiJson(ANALYZE_PROMPT, text);

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

    res.json({
      success: true,
      data: {
        ...data,
        fileName: originalname,
        fileType: mimetype,
      },
    });
  } catch (error) {
    console.error("File Analysis Error:", error);

    const message = error.message || "File analysis failed";
    const userMessage =
      message.includes("Could not read PDF") || message.includes("PDF")
        ? "لم نتمكن من قراءة PDF — جرّب رفع لقطة شاشة للمحتوى"
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
        error: "File too large — maximum size is 10 MB",
      });
    }
    return res.status(400).json({ success: false, error: err.message });
  }

  if (err) {
    return res.status(400).json({ success: false, error: err.message });
  }

  return next();
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
