# Supabase + Fraud Ops API

## Files

| File | Role |
|------|------|
| `backend/supabase.js` | Reusable Supabase client |
| `backend/services/fraudCasesService.js` | CRUD for `fraud_cases` |
| `backend/routes/fraudOps.js` | HTTP routes |
| `supabase/schema.sql` | Table definition |

## Setup

1. Run `supabase/schema.sql` in the Supabase SQL Editor.
2. Set in `backend/.env`:

```env
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
SUPABASE_ANON_KEY=your-anon-key
```

3. Restart: `cd backend && npm start`

## Endpoints

- `POST /api/report` — insert a fraud report
- `GET /api/cases` — list all cases (newest first)
- `PATCH /api/cases/:id` — update `status`, `assigned_to`, `internal_notes`
- `GET /api/cases/:id` — open case (auto Under Review + assign)
- `POST /api/cases` — UI submit button (same store + AI investigation)
