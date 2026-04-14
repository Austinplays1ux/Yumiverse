// ─────────────────────────────────────────────────────────
//  Yumiverse Auth Server  —  zero build, zero frameworks
//  Uses only Node.js built-ins + 4 small npm packages:
//    bcryptjs  (password hashing)
//    jsonwebtoken  (sessions)
//    better-sqlite3  (database)
//    nodemailer  (verification + reset emails)
// ─────────────────────────────────────────────────────────
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Database   = require('better-sqlite3');

// ── Config ────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3000;
const JWT_EXPIRY = process.env.JWT_EXPIRY || '7d';
const APP_URL    = process.env.APP_URL    || `http://localhost:${PORT}`;

// SECURITY: Refuse to start with a default/missing JWT secret in production.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'CHANGE_THIS_TO_A_LONG_RANDOM_STRING') {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: JWT_SECRET is not set. Refusing to start in production.');
    process.exit(1);
  } else {
    console.warn('WARNING: JWT_SECRET not set — using insecure dev default. Never run this way in production.');
  }
}
const EFFECTIVE_JWT_SECRET = JWT_SECRET || 'dev_secret_change_me_in_production';

// SECURITY: Explicit CORS allowlist. Set CORS_ORIGIN in .env for production.
const CORS_ORIGIN = process.env.CORS_ORIGIN || `http://localhost:${PORT}`;

// ── Database ──────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'yumiverse.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS verify_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS rate_limits (
    key          TEXT NOT NULL,
    window_start TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
  );
`);
console.log('Database ready');

// Periodically clean up expired tokens and stale rate limit records.
setInterval(() => {
  db.prepare("DELETE FROM verify_tokens WHERE expires_at < datetime('now') OR used = 1").run();
  db.prepare("DELETE FROM reset_tokens WHERE expires_at < datetime('now') OR used = 1").run();
  db.prepare("DELETE FROM rate_limits WHERE window_start < datetime('now', '-1 hour')").run();
}, 10 * 60 * 1000);

// ── Rate Limiter ──────────────────────────────────────────
function checkRateLimit(key, maxPerMinute) {
  const window = new Date(Math.floor(Date.now() / 60000) * 60000).toISOString();
  const row = db.prepare('SELECT count FROM rate_limits WHERE key = ? AND window_start = ?').get(key, window);
  if (row) {
    if (row.count >= maxPerMinute) return false;
    db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ? AND window_start = ?').run(key, window);
  } else {
    db.prepare('INSERT OR IGNORE INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)').run(key, window);
  }
  return true;
}

function getClientIp(req) {
  return req.socket.remoteAddress || 'unknown';
}

// ── Helpers ───────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.svg':  'image/svg+xml',
};

const PUBLIC_DIR = path.resolve(__dirname, 'public');

function safeUser(u) {
  return { id: u.id, username: u.username, email: u.email, email_verified: !!u.email_verified, created_at: u.created_at };
}

function setCookie(res, name, value, maxAgeSec) {
  // SECURITY: SameSite=Strict is tighter than Lax; Secure flag enforced in production.
  const secure   = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const cookie   = `${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`;
  const existing = res.getHeader('Set-Cookie');
  if (existing) {
    res.setHeader('Set-Cookie', Array.isArray(existing) ? [...existing, cookie] : [existing, cookie]);
  } else {
    res.setHeader('Set-Cookie', cookie);
  }
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return Object.fromEntries(raw.split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
}

function issueToken(res, user) {
  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email, email_verified: !!user.email_verified },
    EFFECTIVE_JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
  setCookie(res, 'token', token, 7 * 24 * 60 * 60);
  return token;
}

function getAuthUser(req) {
  try {
    const token = parseCookies(req).token || (req.headers.authorization || '').replace('Bearer ', '');
    if (!token) return null;
    return jwt.verify(token, EFFECTIVE_JWT_SECRET);
  } catch { return null; }
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

// SECURITY: 10 KB hard limit for JSON request bodies — auth payloads never need more.
const MAX_BODY_BYTES = 10 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (Buffer.byteLength(data) > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error('Request body too large'));
      }
    });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function validateEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

// SECURITY: Alphanumeric + underscore/hyphen only — no spaces or special chars.
function validateUsername(u) { return /^[a-zA-Z0-9_-]{3,20}$/.test(u); }

// SECURITY: Require at least one letter and one digit/symbol for basic complexity.
function validatePassword(p) {
  return p.length >= 8 && /[a-zA-Z]/.test(p) && /[\d\W]/.test(p);
}

async function sendVerificationEmail(to, verifyUrl) {
  const transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transporter.sendMail({
    from:    process.env.EMAIL_FROM || 'Yumiverse <no-reply@yumiverse.gg>',
    to,
    subject: 'Verify your Yumiverse email',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h2>Verify your email</h2>
        <p style="color:#555">Click below to confirm your address. This link expires in <strong>24 hours</strong>.</p>
        <a href="${verifyUrl}" style="display:inline-block;margin:24px 0;padding:12px 28px;
           background:#4361ee;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">
          Verify email
        </a>
        <p style="color:#999;font-size:12px">Didn't create a Yumiverse account? You can safely ignore this email.</p>
      </div>`,
  });
}

async function sendResetEmail(to, resetUrl) {
  const transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transporter.sendMail({
    from:    process.env.EMAIL_FROM || 'Yumiverse <no-reply@yumiverse.gg>',
    to,
    subject: 'Reset your Yumiverse password',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
        <h2>Reset your password</h2>
        <p style="color:#555">Click below to set a new password. This link expires in <strong>1 hour</strong>.</p>
        <a href="${resetUrl}" style="display:inline-block;margin:24px 0;padding:12px 28px;
           background:#4361ee;color:#fff;border-radius:8px;text-decoration:none;font-weight:600">
          Reset password
        </a>
        <p style="color:#999;font-size:12px">Didn't request this? You can safely ignore this email.</p>
      </div>`,
  });
}

// ── Security headers ──────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
  );
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
}

// ── Email verification helpers ────────────────────────────
async function issueVerificationToken(user) {
  db.prepare('DELETE FROM verify_tokens WHERE user_id = ?').run(user.id);
  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO verify_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expiresAt);
  const verifyUrl = `${APP_URL}/verify-email?token=${token}`;
  try {
    await sendVerificationEmail(user.email, verifyUrl);
  } catch (e) {
    console.error('Verification email send failed:', e.message);
    if (process.env.NODE_ENV !== 'production') {
      console.log(`\nDEV VERIFY LINK (paste in browser):\n${verifyUrl}\n`);
    }
  }
}

// ── Route handlers ────────────────────────────────────────
const routes = {

  'POST /api/auth/register': async (req, res) => {
    if (!checkRateLimit(`register:${getClientIp(req)}`, 10))
      return sendJson(res, 429, { error: 'Too many registration attempts. Please try again later.' });

    const { username, email, password } = await readBody(req);
    if (!username || !email || !password)
      return sendJson(res, 400, { error: 'All fields are required.' });
    if (!validateUsername(username))
      return sendJson(res, 400, { error: 'Username must be 3-20 characters and contain only letters, numbers, hyphens, or underscores.' });
    if (!validateEmail(email))
      return sendJson(res, 400, { error: 'Invalid email address.' });
    if (!validatePassword(password))
      return sendJson(res, 400, { error: 'Password must be at least 8 characters and include at least one letter and one number or symbol.' });

    if (db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email.toLowerCase(), username))
      return sendJson(res, 409, { error: 'Email or username is already taken.' });

    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email.toLowerCase(), hash);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);

    // Send verification email — account is created but not yet verified.
    await issueVerificationToken(user);

    sendJson(res, 201, { pending_verification: true, message: 'Account created. Please check your email to verify your address before logging in.' });
  },

  'POST /api/auth/login': async (req, res) => {
    if (!checkRateLimit(`login:${getClientIp(req)}`, 20))
      return sendJson(res, 429, { error: 'Too many login attempts. Please try again later.' });

    const { identifier, password } = await readBody(req);
    if (!identifier || !password)
      return sendJson(res, 400, { error: 'Email/username and password are required.' });

    const user = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(identifier.toLowerCase(), identifier);
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return sendJson(res, 401, { error: 'Incorrect email/username or password.' });

    // Block login until email is verified.
    if (!user.email_verified)
      return sendJson(res, 403, { error: 'Please verify your email address before logging in. Check your inbox or request a new verification link.', unverified: true });

    issueToken(res, user);
    sendJson(res, 200, { user: safeUser(user) });
  },

  'POST /api/auth/logout': (req, res) => {
    setCookie(res, 'token', '', 0);
    sendJson(res, 200, { ok: true });
  },

  'GET /api/auth/me': (req, res) => {
    const authUser = getAuthUser(req);
    if (!authUser) return sendJson(res, 401, { error: 'Not authenticated.' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(authUser.id);
    if (!user) return sendJson(res, 404, { error: 'User not found.' });
    sendJson(res, 200, { user: safeUser(user) });
  },

  'GET /api/auth/verify-email': (req, res) => {
    if (!checkRateLimit(`verify:${getClientIp(req)}`, 10))
      return sendJson(res, 429, { error: 'Too many verification attempts. Please try again later.' });

    const { query } = url.parse(req.url, true);
    const token = query.token;
    if (!token) return sendJson(res, 400, { error: 'Verification token is required.' });

    const record = db.prepare('SELECT * FROM verify_tokens WHERE token = ? AND used = 0').get(token);
    if (!record) return sendJson(res, 400, { error: 'Invalid or already used verification link.' });
    if (new Date(record.expires_at) < new Date())
      return sendJson(res, 400, { error: 'Verification link has expired. Please request a new one.' });

    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(record.user_id);
    db.prepare('UPDATE verify_tokens SET used = 1 WHERE id = ?').run(record.id);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(record.user_id);
    issueToken(res, user);
    sendJson(res, 200, { user: safeUser(user), message: 'Email verified. You are now logged in.' });
  },

  'POST /api/auth/resend-verification': async (req, res) => {
    // Rate limit per IP — 3 resends per minute to prevent email bombing.
    if (!checkRateLimit(`resend:${getClientIp(req)}`, 3))
      return sendJson(res, 429, { error: 'Too many resend requests. Please try again later.' });

    const { email } = await readBody(req);
    if (!email) return sendJson(res, 400, { error: 'Email is required.' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    // SECURITY: Same response regardless of whether the email exists.
    if (!user || user.email_verified) return sendJson(res, 200, { ok: true });

    await issueVerificationToken(user);
    sendJson(res, 200, { ok: true });
  },

  'POST /api/auth/forgot-password': async (req, res) => {
    if (!checkRateLimit(`forgot:${getClientIp(req)}`, 5))
      return sendJson(res, 429, { error: 'Too many reset requests. Please try again later.' });

    const { email } = await readBody(req);
    if (!email) return sendJson(res, 400, { error: 'Email is required.' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    // SECURITY: Return the same response regardless — prevents user enumeration.
    // Also silently skip unverified accounts (no point resetting a password on an unverified address).
    if (!user || !user.email_verified) return sendJson(res, 200, { ok: true });

    db.prepare('DELETE FROM reset_tokens WHERE user_id = ?').run(user.id);
    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expiresAt);

    const resetUrl = `${APP_URL}/reset-password?token=${token}`;
    try {
      await sendResetEmail(user.email, resetUrl);
    } catch (e) {
      console.error('Email send failed:', e.message);
      // SECURITY: Only print the dev link outside of production.
      if (process.env.NODE_ENV !== 'production') {
        console.log(`\nDEV RESET LINK (paste in browser):\n${resetUrl}\n`);
      }
    }
    sendJson(res, 200, { ok: true });
  },

  'POST /api/auth/reset-password': async (req, res) => {
    if (!checkRateLimit(`reset:${getClientIp(req)}`, 10))
      return sendJson(res, 429, { error: 'Too many reset attempts. Please try again later.' });

    const { token, password } = await readBody(req);
    if (!token || !password)
      return sendJson(res, 400, { error: 'Token and password are required.' });
    if (!validatePassword(password))
      return sendJson(res, 400, { error: 'Password must be at least 8 characters and include at least one letter and one number or symbol.' });

    const record = db.prepare('SELECT * FROM reset_tokens WHERE token = ? AND used = 0').get(token);
    if (!record)
      return sendJson(res, 400, { error: 'Invalid or already used reset link.' });
    if (new Date(record.expires_at) < new Date())
      return sendJson(res, 400, { error: 'Reset link has expired. Please request a new one.' });

    const hash = await bcrypt.hash(password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, record.user_id);
    db.prepare('UPDATE reset_tokens SET used = 1 WHERE id = ?').run(record.id);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(record.user_id);
    issueToken(res, user);
    sendJson(res, 200, { user: safeUser(user) });
  },
};

// ── Static file server ────────────────────────────────────
function serveStatic(res, filePath) {
  // SECURITY: Resolve and verify the path stays within public/ — prevents path traversal.
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(PUBLIC_DIR + path.sep) && resolved !== PUBLIC_DIR) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(resolved, (err, data) => {
    if (err) {
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, html) => {
        if (err2) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
      });
      return;
    }
    const ext  = path.extname(resolved);
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

// ── Main server ───────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res);

  // SECURITY: Restrict CORS to the configured origin only — never wildcard with credentials.
  const origin = req.headers.origin;
  if (origin === CORS_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const parsed   = url.parse(req.url);
  const pathname = parsed.pathname;
  const routeKey = `${req.method} ${pathname}`;

  try {
    if (routes[routeKey]) {
      await routes[routeKey](req, res);
      return;
    }

    // SECURITY: Use path.resolve + prefix check for traversal prevention (not string replacement).
    const safePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
    serveStatic(res, safePath);

  } catch (err) {
    // SECURITY: Never expose internal error details to clients.
    console.error('Server error:', err.message, err.stack);
    sendJson(res, 500, { error: 'Internal server error.' });
  }
});

server.listen(PORT, () => {
  console.log(`\nYumiverse running at http://localhost:${PORT}\n`);
});
