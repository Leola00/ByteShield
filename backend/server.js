require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();

app.use(cors());
app.use(express.json());

if (!process.env.GEMINI_API_KEY) {
  console.error("❌ GEMINI_API_KEY not found in .env");
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({
  model: process.env.GEMINI_MODEL || "gemini-2.0-flash",
  systemInstruction: `
You are ByteShield, an AI cybersecurity assistant.

Analyze messages for financial fraud, phishing, and social engineering.

Return ONLY valid JSON in this format:
{
  "riskScore": 0,
  "classification": "Low Risk | Medium Risk | High Risk",
  "reasons": [],
  "recommendation": ""
}
`,
  generationConfig: {
    responseMimeType: "application/json",
  },
});

app.get("/", (req, res) => {
  res.send("✅ ByteShield Backend Running");
});

app.post("/analyze", async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "No text provided",
      });
    }

    const result = await model.generateContent(text);
    const content = result.response.text();

    res.json({
      success: true,
      data: JSON.parse(content),
    });
  } catch (error) {
    console.error("Gemini Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 ByteShield running on http://localhost:${PORT}`);
});
