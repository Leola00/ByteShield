# Employee sign-in (table auth)

Employees sign in with rows in **`public.analysts`**.

You add them in Supabase **Table Editor** — no Auth → Users needed.

## 1. Run this SQL once

Open Supabase → **SQL Editor** → paste and run the full file:

[`schema-employees-auth.sql`](./schema-employees-auth.sql)

## 2. Add an employee

**Table Editor → `analysts` → Insert row:**

| Column | Example |
|--------|---------|
| `full_name` | Sara Al-Qahtani |
| `email` | sara@alinma.com |
| `password` | ChangeMe123 |
| `role` | Fraud Analyst |
| `team` | Fraud Team |

Type the **plain password**. On save it is **bcrypt-hashed** (looks like `$2a$10$...`). That hash cannot be decrypted — only checked at login.

Also run [`schema-password-hash.sql`](./schema-password-hash.sql) if the trigger is missing.

## 3. Sign in

Fraud Ops login → that email + password.

## 4. Change password later

- **Employee:** Settings → Security → set new password  
- **Admin:** Table Editor → edit the `password` cell → type a new plain password → save (auto-hashed again)

## Optional API

```bash
node scripts/add-employee.js sara@alinma.com ChangeMe123 "Sara Al-Qahtani"
```
