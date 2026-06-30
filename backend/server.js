const dotenv = require("dotenv");

dotenv.config({
  path: "./.env",
  override: true,
});

console.log(process.env.OPENAI_API_KEY);


const express = require("express");
const cors = require("cors");
const OpenAI = require("openai");

const app = express();

app.use(cors());
app.use(express.json());

// Check if API key exists
if (!process.env.OPENAI_API_KEY) {
  console.error("❌ OPENAI_API_KEY not found in .env");
  process.exit(1);
}

// Create OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Test route
app.get("/", (req, res) => {
  res.send("✅ ByteShield Backend is Running!");
});

// AI analysis route
app.post("/analyze", async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({
        success: false,
        error: "No text provided.",
      });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: `
You are ByteShield, an AI cybersecurity assistant.

Analyze financial fraud and phishing messages.

Return ONLY valid JSON in this format:

{
  "riskScore": 0,
  "classification": "Low Risk",
  "reasons": [],
  "recommendation": ""
}
`,
        },
        {
          role: "user",
          content: text,
        },
      ],
    });

    res.json({
      success: true,
      data: JSON.parse(completion.choices[0].message.content),
    });
  } catch (error) {
    console.error("OpenAI Error:", error);

    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 ByteShield Backend running on http://localhost:${PORT}`);
});