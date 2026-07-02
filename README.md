# ByteShield

**AI-powered fraud and phishing detection for Saudi banking customers**

ByteShield helps users analyze suspicious messages, emails, URLs, and screenshots before they act on them. This project demonstrates how the feature could be integrated into a bank portal — styled after **Alinma Bank** — as a quick-access security service.

**Repository:** [https://github.com/Leola00/ByteShield](https://github.com/Leola00/ByteShield)

---

## The problem

Financial fraud and phishing in Saudi Arabia often arrive through SMS, email, fake links, and chat screenshots. Many users cannot tell whether a message is real or a scam until it is too late.

## Our solution

ByteShield provides:

- A **risk score (0–100)** with clear low / medium / high classification
- **Arabic explanations** of why content looks suspicious
- **Actionable recommendations** (what to do next)
- **Bank-aware guidance** when a Saudi bank appears to be impersonated
- An **AI assistant** to ask follow-up questions about the scan result

---

## Features

| Input | What it does |
|-------|----------------|
| **Message** | Detects urgency, OTP requests, impersonation, and scam language |
| **Email** | Analyzes subject and body for phishing patterns |
| **URL** | Uses a deep-learning model plus heuristics to flag phishing links |
| **File / screenshot** | Supports images and PDFs via OpenAI vision analysis |
| **AI chat** | Answers questions about the latest scan result |
| **Support contacts** | Links to official Saudi fraud-reporting and bank helplines |

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML, CSS, JavaScript (Arabic RTL UI) |
| Backend | Node.js, Express |
| AI analysis | OpenAI API (`gpt-4o-mini` for text, vision for images/PDFs) |
| URL detection | Python + TensorFlow deep-learning model |
| Hosting (local) | Express serves the frontend and API on one port |

---

## Prerequisites

- **Node.js** (LTS recommended) — [https://nodejs.org](https://nodejs.org)
- **Python 3** — required for URL deep-learning predictions (`backend/ml/`)
- **OpenAI API key** — [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)

Install Python dependencies (for URL scanning):

```bash
cd backend
pip install -r requirements.txt
```

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Leola00/ByteShield.git
cd ByteShield
```

### 2. Configure environment variables

Copy the example file and add your OpenAI key:

```bash
cd backend
copy .env.example .env
```

Edit `backend/.env`:

```env
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
PORT=3000
PYTHON_BIN=python
PYTHON_ARGS=
```

> **Important:** Never commit your real API key. Keep it only in `backend/.env` (this file is gitignored).

### 3. Install backend dependencies

```bash
cd backend
npm install
```

---

## Run the project

Start the backend (this also serves the website):

```bash
cd backend
npm start
```

Open in your browser:

**http://localhost:3000**

> Use port **3000**, not a static file server. The frontend calls the API on the same origin.

---

## Demo walkthrough (for judges)

1. Open **http://localhost:3000**
2. On the Alinma landing page, click the **ByteShield** service card (*تحقق من الاحتيال*)
3. Paste a suspicious message, email, or URL — or click **جرب رسالة احتيال نموذجية** for a sample
4. Click **بدء التحليل الأمني**
5. Review the **risk score**, explanation, recommendations, and category breakdown
6. Optional: open **ByteShield AI** chat to ask follow-up questions

---

## Project structure

```
ByteShield/
├── index.html          # Alinma landing + ByteShield scanner UI
├── styles.css          # Bank-themed styling
├── app.js              # Frontend logic and results dashboard
├── backend/
│   ├── server.js       # Express API + static file server
│   ├── ml/             # URL feature extraction and prediction
│   ├── requirements.txt
│   ├── package.json
│   └── .env.example    # Template for environment variables
└── README.md
```

---

## API endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze` | POST | AI analysis of text (messages, emails) |
| `/analyze-file` | POST | AI analysis of uploaded image or PDF |
| `/predict-url` | POST | URL phishing detection (Python ML model) |
| `/chat` | POST | Follow-up questions about a scan |

---

## Fallback behavior

If the backend is offline or the OpenAI key is missing, the app falls back to **local pattern matching** in the browser so the UI still works — but results are less accurate. For full AI analysis, run the backend with a valid `OPENAI_API_KEY`.

---

## Security notes

- Do not share OTP codes, passwords, or real banking credentials in demos
- Replace placeholder support numbers/emails with official values before production use
- This Alinma-themed UI is a **demonstration** of a possible bank integration, not an official Alinma product

---

## License

ISC (see backend `package.json`)
