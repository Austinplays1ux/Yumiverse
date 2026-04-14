# Yumiverse Auth Server (No-Build Version)

No Express, no frameworks, no build tools. Just Node.js + 4 small packages.

## Quick Start

### 1. Install
```bash
npm install
```

### 2. Configure
```bash
cp .env.example .env
```
Edit `.env` — the only **required** change before going public:
- **JWT_SECRET** — generate a strong one:
  ```bash
  node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
  ```
- **CORS_ORIGIN** — set to your public domain (e.g. `https://yumiverse.gg`)
- **APP_URL** — same as CORS_ORIGIN (used in reset-password links)
- **SMTP settings** — for real password-reset emails (Gmail):
  1. Google Account → Security → App Passwords → create one
  2. `SMTP_USER` = your Gmail, `SMTP_PASS` = the 16-char app password

> **Never run in production with `NODE_ENV` unset** — the server will refuse
> to start if `JWT_SECRET` is missing or still the placeholder value.

### 3. Run
```bash
node server.js
```
Open **http://localhost:3000**

> No email configured? In non-production mode the reset link prints to
> your terminal so you can still test locally.

---

## What's inside
- `server.js` — entire backend in one file, Node's built-in `http` module only
- `public/index.html` — the frontend
- `yumiverse.db` — SQLite database (created automatically on first run)

## Dependencies (4 packages, no frameworks)
| Package | Purpose |
|---|---|
| `bcryptjs` | Password hashing |
| `better-sqlite3` | Database |
| `jsonwebtoken` | Session tokens |
| `nodemailer` | Password reset emails |

---

## Security hardening applied (vs original)

| Area | Change |
|---|---|
| **JWT secret** | Server refuses to start in production without a real secret |
| **CORS** | Explicit allowlist (`CORS_ORIGIN`) instead of wildcard `*` |
| **Path traversal** | `path.resolve` + prefix check instead of naive string replacement |
| **Rate limiting** | Login: 20/min, Register: 10/min, Forgot/Reset: 5-10/min per IP |
| **Request body** | Hard limit of 10 KB (was 1 MB) |
| **Cookie flags** | `SameSite=Strict` (was `Lax`); `Secure` flag in production |
| **Username validation** | Alphanumeric + `_-` only — no spaces or injection chars |
| **Password policy** | Requires a letter + digit/symbol, not just 8 chars |
| **Security headers** | `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `HSTS`, `Referrer-Policy` |
| **Dev reset link** | Only printed to console outside of production |
| **Token cleanup** | Expired/used reset tokens purged every 10 minutes |
| **Error responses** | Internal details never exposed to clients |
