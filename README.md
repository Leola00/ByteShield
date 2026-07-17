# ByteShield

**AI-powered fraud detection for customers — and a Fraud Operations desk for bank analysts**

ByteShield is a two-sided security platform demonstrated inside an **Alinma Bank**-styled portal:

1. **Customers** can scan suspicious messages, emails, URLs, and screenshots before they act.
2. **Fraud analysts** get a full **Fraud Operations** workspace to review cases, run AI investigations, track campaigns, and follow playbooks.

**Repository:** [https://github.com/Leola00/ByteShield](https://github.com/Leola00/ByteShield)

---

## The problem

Financial fraud and phishing in Saudi Arabia arrive through SMS, email, fake links, and chat screenshots. Customers often cannot tell what is real until it is too late — and bank teams need a faster way to turn those alerts into investigated, tracked cases.

## Our solution

ByteShield connects **customer reporting** with **live analyst workflow**:

| Side | What you get |
|------|----------------|
| **Customer scanner** | Risk score (0–100), Arabic explanations, recommendations, bank-impersonation warnings, AI follow-up chat |
| **Fraud Operations** | Employee sign-in, case queue, AI investigation & recommendations, campaigns, playbooks, internal notes, analytics |
| **Shared backend** | OpenAI analysis + Python ML (URL / financial risk) + Supabase live case storage |

---

## Features

### Customer — scan before you click

| Input | What it does |
|-------|----------------|
| **Message** | Detects urgency, OTP requests, impersonation, and scam language |
| **Email** | Analyzes subject and body for phishing patterns |
| **URL** | Deep-learning model + heuristics to flag phishing links |
| **File / screenshot** | Images and PDFs via OpenAI vision |
| **Report to bank** | Submits a case into Fraud Operations for analyst review |
| **AI chat** | Answers questions about the latest scan result |

### Fraud Operations — investigate and act

| Capability | What it does |
|------------|----------------|
| **Analyst login** | Email + password against the `analysts` table (bcrypt, Supabase) |
| **Case queue** | Pending / under review / decided cases with search and filters |
| **AI investigation** | Summaries, IOCs, threat category, and recommended next action |
| **Campaigns** | Group related cases into active fraud campaigns |
| **Playbooks** | Step-by-step response guides for common fraud types |
| **Copilot** | Ask follow-up questions on an open case |
| **Internal notes** | Team notes saved to the database |
| **Analytics** | Queue KPIs and risk / threat overview |

---

## Tech stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML, CSS, JavaScript (Arabic RTL customer UI + English Fraud Ops) |
| Backend | Node.js, Express |
| AI analysis | OpenAI API (`gpt-4o-mini` for text, vision, SOC / investigation) |
| ML models | Python + TensorFlow (URL phishing, financial risk) |
| Data | Supabase (`fraud_cases`, `analysts`, notes, campaigns) |
| Hosting (local) | Express serves the frontend and API on one port |

---

## Prerequisites

- **Node.js** (LTS recommended) — [https://nodejs.org](https://nodejs.org)
- **Python 3** — for ML predictions (`backend/ml/`)
- **OpenAI API key** — [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- **Supabase project** — for Fraud Operations live storage & analyst sign-in

Install Python dependencies (for URL / financial ML):

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

```bash
cd backend
copy .env.example .env
```

Edit `backend/.env`:

```env
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o-mini
OPENAI_VISION_MODEL=gpt-4o-mini
OPENAI_SOC_MODEL=gpt-4o-mini
PORT=3000
PYTHON_BIN=python
PYTHON_ARGS=

# Must be the full project URL (with .supabase.co)
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-or-publishable-key
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-or-secret-key
```

> **Important:** Never commit real keys. Keep them only in `backend/.env` (gitignored).  
> `SUPABASE_URL` must look like `https://xxxxx.supabase.co` — not a bare project ref or dashboard path.

### 3. Set up Supabase (Fraud Ops)

In the Supabase SQL Editor, run (in order as needed):

1. [`supabase/schema.sql`](supabase/schema.sql) — core `fraud_cases` table  
2. [`supabase/schema-fraud-ops.sql`](supabase/schema-fraud-ops.sql) — ops extensions  
3. [`supabase/schema-employees-auth.sql`](supabase/schema-employees-auth.sql) — `analysts` + login  
4. [`supabase/schema-password-hash.sql`](supabase/schema-password-hash.sql) — password hashing trigger  

Add an analyst in **Table Editor → `analysts`** (plain password is auto-hashed on save), or:

```bash
node scripts/add-employee.js sara@alinma.com ChangeMe123 "Sara Al-Qahtani"
```

See [`supabase/SETUP-FRAUD-OPS.md`](supabase/SETUP-FRAUD-OPS.md) for sign-in details.

### 4. Install backend dependencies

```bash
cd backend
npm install
```

---

## Run the project

```bash
cd backend
npm start
```

Open **http://localhost:3000**

> Use port **3000**, not a static file server. The frontend calls the API on the same origin.

---

## Demo walkthrough

### Customer scanner

1. Open **http://localhost:3000**
2. On the Alinma landing page, click the **ByteShield** card (*تحقق من الاحتيال*)
3. Paste a suspicious message, email, or URL — or use the sample scam button
4. Click **بدء التحليل الأمني**
5. Review the risk score, explanation, and recommendations
6. Optionally **report** the case to Fraud Operations or open **ByteShield AI** chat

### Fraud Operations

1. Open Fraud Ops login and sign in with an `analysts` email + password
2. Review the **dashboard** KPIs and active **campaigns**
3. Open the **case queue**, filter/search, and investigate a case
4. Check AI recommendation, IOCs, and run **Copilot** or add **internal notes**
5. Use **Playbooks** for guided response steps

---

## Project structure

```
ByteShield/
├── index.html              # Alinma landing + scanner + Fraud Ops UI
├── styles.css              # Bank + Fraud Ops styling
├── app.js                  # Frontend: scanner, results, Fraud Ops UI
├── playbooks-data.js       # Investigation playbooks
├── js/
│   ├── fraud-ops-live.js   # Fraud Ops API client
│   └── supabase-config.js  # Frontend Supabase helper
├── backend/
│   ├── server.js           # Express API + static hosting
│   ├── supabase.js         # Supabase client
│   ├── routes/             # Fraud Ops + auth / notes routes
│   ├── services/           # Cases, analysts, auth, campaigns, notes
│   ├── ml/                 # URL + financial risk Python models
│   ├── scripts/            # e.g. add-employee.js
│   ├── requirements.txt
│   ├── package.json
│   └── .env.example
├── supabase/               # SQL schemas + setup docs
└── README.md
```

---

## API endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze` | POST | AI analysis of text (messages, emails) |
| `/analyze-file` | POST | AI analysis of uploaded image or PDF |
| `/predict-url` | POST | URL phishing detection (TensorFlow ML + OpenAI hybrid) |
| `/chat` | POST | Follow-up questions about a scan |
| `/soc-report` | POST | SOC-style incident report |
| `/api/auth/login` | POST | Analyst sign-in |
| `/api/report` | POST | Customer fraud report → case |
| `/api/cases` | GET / POST | List or create cases |
| `/api/cases/:id` | GET / PATCH | Open or update a case |
| `/api/cases/:id/investigate` | POST | Run AI investigation |
| `/api/cases/:id/copilot` | POST | Case follow-up AI |
| `/api/campaigns` | GET | Active fraud campaigns |
| `/api/analytics` | GET | Ops analytics |

---

## Fallback behavior

If the backend is offline or the OpenAI key is missing, the customer scanner falls back to **local pattern matching** in the browser so the UI still works — results are less accurate. Fraud Operations needs a running backend plus valid **Supabase** keys for live cases and login.

---

## Security notes

- Do not share OTP codes, passwords, or real banking credentials in demos
- Replace placeholder support numbers/emails with official values before production use
- Use the **service role** key only on the server; never expose it in frontend code
- This Alinma-themed UI is a **demonstration** of a possible bank integration, not an official Alinma product

---

## License

ISC (see backend `package.json`)
