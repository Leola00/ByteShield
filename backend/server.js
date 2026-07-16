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
  "securityTips": ["tip 1", "tip 2", "tip 3"],
  "extractedUrls": []
}

riskBreakdown values are 0-100 risk scores per category (higher = more dangerous).
If the content contains NO URLs/links, set linkSafety to 0 and extractedUrls to [].
If any URL is present, put EXACT full URL(s) in extractedUrls and set linkSafety to a real risk score for those links.
actionChecklist: 4-6 concrete steps. If safe, use positive cautions.
detectedBanks: Saudi banks if impersonated (Samba, SNB, Al Rajhi, Riyad Bank, Alinma, etc.) or empty array.`;

const URL_ANALYZE_PROMPT = `You are ByteShield, a URL phishing and fraud analyzer for users in Saudi Arabia.

Analyze the given URL for phishing, typosquatting, credential harvesting, fake login pages, and impersonation of Saudi banks (Alinma, SNB, Al Rajhi, Riyad Bank, etc.).

Consider: domain age signals, HTTPS, suspicious TLDs, homoglyphs, IP-based hosts, URL shorteners, @- tricks, and lookalike domains.

Scoring rubric (be consistent):
- 0-30 = Low Risk / Safe
- 31-60 = Medium Risk / Suspicious
- 61-100 = High Risk

Return user-facing text in Arabic. JSON field names stay in English.

Return ONLY valid JSON:
{
  "riskScore": 0,
  "classification": "Low Risk | Medium Risk | High Risk",
  "statusMessage": "Large status with emoji in Arabic",
  "shortExplanation": "2-3 sentences in natural Arabic",
  "confidence": 85,
  "reasoning": ["reason 1", "reason 2"],
  "actionChecklist": ["action 1", "action 2", "action 3", "action 4"],
  "riskBreakdown": {
    "senderAuthenticity": 0,
    "languageAnalysis": 0,
    "linkSafety": 0,
    "financialFraudIndicators": 0,
    "socialEngineeringIndicators": 0,
    "urgencyDetection": 0
  },
  "detailedAnalysis": "Full paragraph in Arabic",
  "detectedBanks": [],
  "bankAdvice": "",
  "threatType": "phishing | banking_fraud | general",
  "securityTips": ["tip 1", "tip 2", "tip 3"]
}

actionChecklist: 4-6 concrete Arabic steps tailored to this URL. securityTips: practical Arabic tips.`;

const VISION_EXTRA = `You are analyzing visual content: a screenshot, photo, or scanned PDF page.

Read all visible text carefully (Arabic and English). Note logos, bank names, messaging apps (WhatsApp, SMS, email), URLs, phone numbers, urgency language, OTP/password requests, and fake official branding.
Evaluate whether the content is legitimate or a fraud/phishing attempt.

CRITICAL for extractedUrls:
- Copy every URL exactly as shown in the image (full http/https links).
- If no URL is visible, return extractedUrls: [].
- Do NOT invent example URLs that are not in the image.
- When a phishing link is visible, extractedUrls MUST include it and linkSafety MUST be a high risk score.`;

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

const PYTHON_BIN =
  process.env.PYTHON_BIN || (process.platform === "win32" ? "py" : "python");
const PYTHON_ARGS = (process.env.PYTHON_ARGS || "").trim()
  ? process.env.PYTHON_ARGS.trim().split(/\s+/).filter(Boolean)
  : process.platform === "win32" && !process.env.PYTHON_ARGS && !process.env.PYTHON_BIN
    ? ["-3"]
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

async function callOpenAiVision(userContentParts, systemPrompt) {
  const completion = await openai.chat.completions.create({
    model: process.env.OPENAI_VISION_MODEL || getOpenAiModel(),
    temperature: 0,
    messages: [
      { role: "system", content: systemPrompt || `${ANALYZE_PROMPT}\n\n${VISION_EXTRA}` },
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

const OCR_EXTRACT_PROMPT = `You are an OCR and content-extraction engine. Read the provided image(s) precisely.

Return ONLY valid JSON:
{
  "visibleText": "ALL text visible in the image, transcribed exactly (keep Arabic and English as-is, preserve line breaks with \\n)",
  "extractedUrls": ["every full URL exactly as shown, or [] if none"],
  "sender": "sender name/number/handle if visible, else empty string",
  "channel": "WhatsApp | SMS | Email | Web | Unknown",
  "brandsSeen": ["any bank/company/brand names or logos visible"],
  "hasOtpOrPasswordRequest": false,
  "notes": "short note of visual cues: logos, urgency, fake branding, buttons"
}

Rules:
- Transcribe text verbatim; do NOT summarize or translate.
- Copy URLs exactly (reconstruct full link if wrapped). If none, extractedUrls = [].
- Do NOT invent text or URLs that are not visible.`;

function buildAnalysisInputFromExtraction(extraction) {
  const parts = [];
  if (extraction.channel && extraction.channel !== "Unknown") {
    parts.push(`[Channel: ${extraction.channel}]`);
  }
  if (extraction.sender) parts.push(`[Sender: ${extraction.sender}]`);
  if (Array.isArray(extraction.brandsSeen) && extraction.brandsSeen.length) {
    parts.push(`[Brands/logos visible: ${extraction.brandsSeen.join(", ")}]`);
  }
  if (extraction.hasOtpOrPasswordRequest) {
    parts.push("[Visible request for OTP/password/verification code]");
  }
  if (Array.isArray(extraction.extractedUrls) && extraction.extractedUrls.length) {
    parts.push(`[Links visible: ${extraction.extractedUrls.join(" , ")}]`);
  }
  if (extraction.notes) parts.push(`[Visual cues: ${extraction.notes}]`);
  parts.push("");
  parts.push("Content transcribed from the uploaded image/screenshot:");
  parts.push(String(extraction.visibleText || "").trim() || "(no readable text)");
  return parts.join("\n");
}

// Two-step image analysis: OCR/extract → score the extracted content like a text message.
// This makes each image get a real, content-driven score instead of a generic vision score.
async function analyzeImageParts(imageParts, ocrHint) {
  const extraction = await callOpenAiVision(
    [
      {
        type: "text",
        text:
          ocrHint ||
          "Extract ALL visible text and every URL from this image. Do not score, just transcribe.",
      },
      ...imageParts,
    ],
    OCR_EXTRACT_PROMPT,
  );

  const visibleText = String(extraction.visibleText || "").trim();
  const analysisInput = buildAnalysisInputFromExtraction(extraction);

  // Score the extracted content with the same engine used for text messages.
  const report = await callOpenAiJson(ANALYZE_PROMPT, analysisInput);

  report.extractedText = visibleText;
  report.extractedUrls = Array.isArray(extraction.extractedUrls)
    ? extraction.extractedUrls.map((u) => String(u || "").trim()).filter(Boolean)
    : [];
  report.detectedBanks = report.detectedBanks?.length
    ? report.detectedBanks
    : Array.isArray(extraction.brandsSeen)
      ? extraction.brandsSeen
      : [];
  return report;
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

  const imageParts = pageImages.map((img) => ({
    type: "image_url",
    image_url: {
      url: `data:${img.mime};base64,${img.base64}`,
      detail: "high",
    },
  }));

  return analyzeImageParts(
    imageParts,
    "This is a scanned PDF. Transcribe ALL visible text from every page and list every URL. Do not score, just extract.",
  );
}

async function analyzeImageBuffer(buffer, mimeType) {
  const base64 = buffer.toString("base64");
  const imageParts = [
    {
      type: "image_url",
      image_url: {
        url: `data:${mimeType};base64,${base64}`,
        detail: "high",
      },
    },
  ];

  return analyzeImageParts(
    imageParts,
    "Transcribe ALL visible text from this screenshot/photo and list every URL exactly. Do not score, just extract.",
  );
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

const RISK_BREAKDOWN_KEYS = [
  "senderAuthenticity",
  "languageAnalysis",
  "linkSafety",
  "financialFraudIndicators",
  "socialEngineeringIndicators",
  "urgencyDetection",
];

function scoreToClassification(score) {
  const n = Number(score) || 0;
  if (n <= 30) return "Low Risk";
  if (n <= 60) return "Medium Risk";
  return "High Risk";
}

function averageNumbers(a, b) {
  const x = Number(a);
  const y = Number(b);
  if (Number.isFinite(x) && Number.isFinite(y)) return Math.round((x + y) / 2);
  if (Number.isFinite(x)) return Math.round(x);
  if (Number.isFinite(y)) return Math.round(y);
  return 0;
}

function averageRiskBreakdown(mlBreakdown, aiBreakdown, fallbackScore) {
  const out = {};
  for (const key of RISK_BREAKDOWN_KEYS) {
    const mlVal = mlBreakdown?.[key];
    const aiVal = aiBreakdown?.[key];
    if (Number.isFinite(mlVal) && Number.isFinite(aiVal)) {
      out[key] = Math.round((mlVal + aiVal) / 2);
    } else if (Number.isFinite(aiVal)) {
      out[key] = Math.round(aiVal);
    } else if (Number.isFinite(mlVal)) {
      out[key] = Math.round(mlVal);
    } else {
      out[key] = Math.round(fallbackScore);
    }
  }
  return out;
}

const URL_IN_TEXT_RE = /https?:\/\/[^\s<>"'\]\)]+/gi;
const WWW_URL_RE = /\bwww\.[a-z0-9][-a-z0-9.]*\.[a-z]{2,}(?:\/[^\s<>"'\]\)]*)?/gi;
const SUSPICIOUS_BARE_DOMAIN_RE =
  /\b(?:[a-z0-9-]+\.)+(?:xyz|top|club|icu|tk|ml|ga|cf|gq|click|link|online|site|support)(?:\/[a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?/gi;

function extractUrlsFromText(text) {
  if (!text) return [];
  const cleaned = String(text)
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/[\u00A0\u202F]/g, " ");
  const found = [];
  for (const match of cleaned.match(URL_IN_TEXT_RE) || []) found.push(match);
  for (const match of cleaned.match(WWW_URL_RE) || []) {
    found.push(/^https?:\/\//i.test(match) ? match : `https://${match}`);
  }
  for (const match of cleaned.match(SUSPICIOUS_BARE_DOMAIN_RE) || []) {
    if (/^https?:\/\//i.test(match)) found.push(match);
    else found.push(`http://${match}`);
  }
  return [
    ...new Set(
      found.map((url) => url.replace(/[.,;:!?)>\]]+$/g, "")).filter(Boolean),
    ),
  ];
}

function heuristicUrlRiskScore(url) {
  let score = 15;
  const full = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  try {
    const host = new URL(full).hostname.replace(/^www\./, "").toLowerCase();
    if (/bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|short/i.test(full)) score += 15;
    if (
      ["secure-", "-verify", "-login", "-update", "-support", "account-", "banking-"].some(
        (s) => host.includes(s),
      )
    ) {
      score += 22;
    }
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host)) score += 20;
    if (!/^https:\/\//i.test(full)) score += 12;
    if ((full.match(/\./g) || []).length > 3) score += 10;
    if (/\.(xyz|top|club|icu|tk|ml|ga|cf|gq)\b/i.test(host)) score += 18;
  } catch {
    score = 70;
  }
  return Math.min(98, score);
}

async function resolveLinkSafetyForContent(text, contentType, existingBreakdown = {}) {
  const type = String(contentType || "Message");
  const isUrlTab = type.toUpperCase() === "URL";

  if (isUrlTab) {
    const raw = String(text || "").trim();
    const url = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const localScore = heuristicUrlRiskScore(url);
    try {
      const ml = await runUrlMlPrediction(url);
      if (ml.success) {
        const aiLink = Number(existingBreakdown.linkSafety);
        const mlScore = Number(ml.riskScore) || 0;
        const parts = [mlScore, localScore];
        if (Number.isFinite(aiLink) && aiLink > 0) parts.push(aiLink);
        return {
          linkSafety: Math.round(Math.max(...parts)),
          linksNotApplicable: false,
          detectedUrls: [url],
        };
      }
    } catch {
      /* fall through */
    }
    const aiLink = Number(existingBreakdown.linkSafety);
    return {
      linkSafety: Math.max(localScore, Number.isFinite(aiLink) ? aiLink : 0),
      linksNotApplicable: false,
      detectedUrls: [url],
    };
  }

  const urls = extractUrlsFromText(text);
  if (!urls.length) {
    return { linkSafety: 0, linksNotApplicable: true, detectedUrls: [] };
  }

  let maxMlScore = 0;
  let mlOk = false;
  for (const url of urls) {
    try {
      const ml = await runUrlMlPrediction(url);
      if (ml.success) {
        mlOk = true;
        maxMlScore = Math.max(maxMlScore, Number(ml.riskScore) || 0);
      }
    } catch {
      /* try next url */
    }
  }

  const localScore = Math.max(...urls.map((u) => heuristicUrlRiskScore(u)));
  const aiLink = Number(existingBreakdown.linkSafety);
  const candidates = [localScore];
  if (mlOk) candidates.push(maxMlScore);
  // Never let OpenAI's 0 wipe a real URL score when a link is present
  if (Number.isFinite(aiLink) && aiLink > 0) candidates.push(Math.round(aiLink));

  return {
    linkSafety: Math.round(Math.max(...candidates)),
    linksNotApplicable: false,
    detectedUrls: urls,
  };
}

function collectUrlsFromAnalysis(data, extraText = "") {
  const fromField = Array.isArray(data?.extractedUrls)
    ? data.extractedUrls.map((u) => String(u || "").trim()).filter(Boolean)
    : [];
  const fromDetected = Array.isArray(data?.detectedUrls)
    ? data.detectedUrls.map((u) => String(u || "").trim()).filter(Boolean)
    : [];
  const blob = [
    extraText,
    ...(fromField),
    ...(fromDetected),
    data?.detailedAnalysis,
    data?.shortExplanation,
    ...(Array.isArray(data?.reasoning) ? data.reasoning : []),
  ]
    .filter(Boolean)
    .join("\n");
  return [...new Set([...fromField, ...fromDetected, ...extractUrlsFromText(blob)])];
}

async function applyLinkSafetyToReport(text, contentType, data) {
  const type = String(contentType || "Message");
  const isScreenshot = /screenshot|file|image|pdf/i.test(type);

  // For screenshots/files: use URLs extracted by vision + any http links in analysis.
  // For messages/emails: only use the original user text (avoid invented example URLs).
  const scanText = isScreenshot
    ? collectUrlsFromAnalysis(data, text).join("\n")
    : text;

  const resolved = await resolveLinkSafetyForContent(
    scanText || text,
    isScreenshot ? "Message" : type,
    data.riskBreakdown || {},
  );

  // If vision returned extractedUrls but regex missed them, score those URLs directly
  if (isScreenshot && resolved.linksNotApplicable) {
    const visionUrls = collectUrlsFromAnalysis(data, text);
    if (visionUrls.length) {
      const localScore = Math.max(...visionUrls.map((u) => heuristicUrlRiskScore(u)));
      let maxMl = 0;
      for (const url of visionUrls) {
        try {
          const ml = await runUrlMlPrediction(url);
          if (ml.success) maxMl = Math.max(maxMl, Number(ml.riskScore) || 0);
        } catch {
          /* ignore */
        }
      }
      resolved.linkSafety = Math.max(localScore, maxMl);
      resolved.linksNotApplicable = false;
      resolved.detectedUrls = visionUrls;
    }
  }

  data.riskBreakdown = { ...(data.riskBreakdown || {}), linkSafety: resolved.linkSafety };
  data.linksNotApplicable = resolved.linksNotApplicable;
  if (resolved.detectedUrls?.length) {
    data.detectedUrls = resolved.detectedUrls;
  }
  if (Array.isArray(data.extractedUrls) && data.extractedUrls.length && !data.detectedUrls?.length) {
    data.detectedUrls = data.extractedUrls;
  }
  return data;
}

async function analyzeUrlWithOpenAi(url) {
  if (!openai) return null;
  try {
    return await callOpenAiJson(
      URL_ANALYZE_PROMPT,
      `Analyze this URL for phishing and financial fraud:\n${url}`,
    );
  } catch (error) {
    console.warn("OpenAI URL analysis failed:", error.message);
    return null;
  }
}

function buildMlUrlReport(url, ml) {
  const score = Number(ml.riskScore) || 0;
  const tier = scoreToClassification(score);
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

function buildHybridUrlReport(url, ml, ai) {
  const mlReport = buildMlUrlReport(url, ml);
  if (!ai) return mlReport;

  const mlScore = Number(ml.riskScore) || 0;
  const aiScore = Number(ai.riskScore) || 0;
  const combinedScore = averageNumbers(mlScore, aiScore);
  const tier = scoreToClassification(combinedScore);
  const probability = Number(ml.phishingProbability) || 0;

  const reasoning = [
    ...(Array.isArray(ai.reasoning) && ai.reasoning.length ? ai.reasoning : mlReport.reasoning),
    `نموذج التعلم العميق (phishing_dl_model): ${mlScore}/100 — احتمال تصيد ${Math.round(probability * 100)}%`,
    `تحليل OpenAI (${getOpenAiModel()}): ${aiScore}/100`,
  ].slice(0, 6);

  const detailedAnalysis = [
    ai.detailedAnalysis || ai.shortExplanation || mlReport.shortExplanation,
    "",
    `الرابط: ${url}`,
    `الدرجة المدمجة: ${combinedScore}/100 (متوسط ML ${mlScore} + OpenAI ${aiScore})`,
    "",
    "ما الذي لاحظناه:",
    ...reasoning.map((line) => `• ${line}`),
  ].join("\n");

  return {
    riskScore: combinedScore,
    classification: tier,
    statusMessage: ai.statusMessage || mlReport.statusMessage,
    shortExplanation:
      ai.shortExplanation ||
      `متوسط تحليلين: نموذج التعلم العميق (${mlScore}/100) وOpenAI (${aiScore}/100). ${mlReport.shortExplanation}`,
    confidence: averageNumbers(mlReport.confidence, ai.confidence),
    reasoning,
    actionChecklist:
      Array.isArray(ai.actionChecklist) && ai.actionChecklist.length
        ? ai.actionChecklist
        : mlReport.actionChecklist,
    riskBreakdown: averageRiskBreakdown(mlReport.riskBreakdown, ai.riskBreakdown, combinedScore),
    detailedAnalysis,
    detectedBanks: Array.isArray(ai.detectedBanks) ? ai.detectedBanks : [],
    bankAdvice: ai.bankAdvice || "",
    threatType: ai.threatType || mlReport.threatType,
    securityTips:
      Array.isArray(ai.securityTips) && ai.securityTips.length
        ? ai.securityTips
        : mlReport.securityTips,
    ml: {
      model: ml.model,
      phishingProbability: ml.phishingProbability,
      isPhishing: ml.isPhishing,
      riskScore: mlScore,
    },
    openAi: {
      model: getOpenAiModel(),
      riskScore: aiScore,
    },
    source: "hybrid",
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

    const normalizedUrl = String(url).trim();

    const [ml, ai] = await Promise.all([
      runUrlMlPrediction(normalizedUrl),
      analyzeUrlWithOpenAi(normalizedUrl),
    ]);

    if (!ml.success) {
      return res.status(500).json({
        success: false,
        error: ml.error || "ML prediction failed",
      });
    }

    const data = buildHybridUrlReport(normalizedUrl, ml, ai);
    recordAnalysisIncident(normalizedUrl, data);

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

    const { text, contentType } = req.body;

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "No text provided",
      });
    }

    const data = await callOpenAiJson(ANALYZE_PROMPT, text);
    await applyLinkSafetyToReport(text, contentType || "Message", data);
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
    // Score links visible in the screenshot (extractedUrls + URLs in OCR/analysis text)
    await applyLinkSafetyToReport("", "Screenshot", responseData);
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
      try {
        saved = await fraudCasesService.patchCase(found.id, {
          investigation: package_,
          status: found.status === "Closed" ? "Closed" : "Under Review",
          assigned_to: found.assignedTo || "Analyst",
          ai_summary: package_?.aiInvestigationSummary || found.aiSummary,
          ai_recommendation: package_?.recommendation?.action || found.aiRecommendation,
        });
      } catch (saveErr) {
        console.warn("Investigate save failed:", saveErr.message);
        saved = {
          ...found,
          investigation: package_,
          status: found.status === "Closed" ? "Closed" : "Under Review",
          assignedTo: found.assignedTo || "Analyst",
          aiExplanation: package_?.aiInvestigationSummary || found.aiExplanation,
          aiSummary: package_?.aiInvestigationSummary || found.aiSummary,
          aiRecommendation: package_?.recommendation?.action || found.aiRecommendation,
        };
      }
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
    const { getLocalDevCredentials } = require("./services/localDevAuth");
    const dev = getLocalDevCredentials();
    console.warn(`   Local dev login: ${dev.email} (override with FRAUD_DEV_EMAIL / FRAUD_DEV_PASSWORD)`);
  }
  console.log("✅ Fraud Operations API ready at /api/cases");
});
