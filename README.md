# ByteShield

AI-powered security platform that analyzes text messages, emails, URLs, and conversation screenshots to detect financial fraud and phishing attempts.

## Features

- **Message scan** — Analyze SMS and chat content for scam patterns
- **Email scan** — Check subject and body for phishing indicators
- **URL scan** — Detect typosquatting, shorteners, and suspicious domains
- **Screenshot upload** — UI ready for vision/OCR analysis (demo mode)
- **Risk score** — 0–100 score with low / medium / high rating
- **Recommendations** — Actionable guidance to stay safe

## Run locally

No build step required. Open `index.html` in a browser, or use a local server:

```bash
# Python (if installed)
python -m http.server 8080
```

Then visit `http://localhost:8080`

## Project structure

```
index.html   — Main page
styles.css   — Styles
app.js       — Scan UI and demo analysis logic
```

## Demo vs production

The current version uses **local pattern matching** in the browser. For production, connect a backend with a generative AI API (OpenAI, Gemini, etc.) for real analysis.

## Team workflow

1. Clone the repo
2. Create a branch for your feature: `git checkout -b feature/your-feature`
3. Make changes and commit
4. Push and open a Pull Request on GitHub
