import bcrypt from 'bcryptjs';
import { Resend } from 'resend';
import { neon } from '@neondatabase/serverless';
import { OAuth2Client } from 'google-auth-library';
import { randomBytes } from 'crypto';

export const config = { maxDuration: 30 };

const DB_URL = process.env.POSTGRES_URL || process.env.DATABASE_URL;
if (!DB_URL) console.error('[auth] ❌ POSTGRES_URL / DATABASE_URL belum di-set!');
const sql = neon(DB_URL);

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
  || '119383914932-8s2ltp64kncsanklhmo6u2bi8eblvije.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

let schemaReady = false;
async function ensureSchema() {
  if (schemaReady) return;
  await sql`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT,
    verified BOOLEAN DEFAULT FALSE,
    google_id TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS otps (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    purpose TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`;
  await sql`CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0,
    window_start TIMESTAMPTZ DEFAULT NOW()
  )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email, purpose)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_rate_limits_start ON rate_limits(window_start)`;
  try {
    await sql`ALTER TABLE users ALTER COLUMN created_at TYPE TIMESTAMPTZ`;
    await sql`ALTER TABLE otps ALTER COLUMN expires_at TYPE TIMESTAMPTZ`;
    await sql`ALTER TABLE sessions ALTER COLUMN expires_at TYPE TIMESTAMPTZ`;
  } catch (e) {}
  schemaReady = true;
}

function genToken() { return randomBytes(32).toString('hex'); }
function genCode() { return String(randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, '0'); }
function getIP(req) {
  const xff = req.headers['x-forwarded-for'] || '';
  return String(xff).split(',')[0].trim() || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}
function sanitizeEmail(e) { return String(e || '').toLowerCase().trim(); }

async function checkRateLimit(key, max, windowSec) {
  try {
    const rows = await sql`SELECT count, window_start FROM rate_limits WHERE key = ${key}`;
    if (!rows.length) {
      await sql`INSERT INTO rate_limits (key, count, window_start) VALUES (${key}, 1, NOW())`;
      return true;
    }
    const r = rows[0];
    const elapsedSec = (Date.now() - new Date(r.window_start).getTime()) / 1000;
    if (elapsedSec > windowSec) {
      await sql`UPDATE rate_limits SET count = 1, window_start = NOW() WHERE key = ${key}`;
      return true;
    }
    if (r.count >= max) return false;
    await sql`UPDATE rate_limits SET count = count + 1 WHERE key = ${key}`;
    return true;
  } catch (e) { return true; }
}
async function enforceRateLimit(req, res, scope, max, windowSec) {
  const key = `${scope}:${getIP(req)}`;
  const ok = await checkRateLimit(key, max, windowSec);
  if (!ok) {
    res.status(429).json({ error: `Terlalu banyak permintaan. Coba lagi beberapa menit.`, retryAfter: windowSec });
    return false;
  }
  return true;
}

async function sendEmail(to, subject, htmlContent) {
  if (!resend) throw new Error('Email service tidak dikonfigurasi (RESEND_API_KEY kosong)');
  const from = process.env.EMAIL_FROM || 'Syon AI <onboarding@resend.dev>';
  const result = await resend.emails.send({ from, to, subject, html: htmlContent });
  if (result.error) throw new Error(result.error.message);
  return result;
}

function emailTemplate(code, title, desc) {
  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <div style="display: inline-block; width: 60px; height: 60px; background: #0b5cff; border-radius: 16px; line-height: 60px; font-size: 28px; font-weight: 700; color: #fff;">S</div>
      </div>
      <h1 style="font-size: 22px; font-weight: 600; color: #0d0d0d; margin: 0 0 12px; text-align: center;">${title}</h1>
      <p style="font-size: 14px; color: #565869; line-height: 1.6; margin: 0 0 24px; text-align: center;">${desc}</p>
      <div style="background: #f9f9f9; border: 1px solid #e5e5e5; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
        <div style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #0b5cff; font-family: 'Courier New', monospace;">${code}</div>
      </div>
      <p style="font-size: 12px; color: #8e8ea0; text-align: center; line-height: 1.6; margin: 0;">Kode berlaku 10 menit.<br>Kalau bukan kamu yang minta, abaikan email ini.</p>
    </div>`;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST' && req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  try {
    await ensureSchema();
    const action = (req.query && req.query.action) || (req.body && req.body.action);
    switch (action) {
      case 'register':    return await handleRegister(req, res);
      case 'verify':      return await handleVerify(req, res);
      case 'resend-otp':  return await handleResendOtp(req, res);
      case 'login':       return await handleLogin(req, res);
      case 'me':          return await handleMe(req, res);
      case 'logout':      return await handleLogout(req, res);
      case 'forgot':      return await handleForgot(req, res);
      case 'reset':       return await handleReset(req, res);
      case 'google-sync': return await handleGoogleSync(req, res);
      default: return res.status(400).json({ error: 'Action tidak dikenal: ' + action });
    }
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ error: err.message || 'Server error' });
  }
}

async function handleRegister(req, res) {
  if (!(await enforceRateLimit(req, res, 'register', 5, 3600))) return;
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Semua kolom wajib diisi' });
  const em = sanitizeEmail(email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em) || em.length > 254) return res.status(400).json({ error: 'Email tidak valid' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
  if (String(name).trim().length < 1 || String(name).length > 60) return res.status(400).json({ error: 'Nama tidak valid' });
  const existing = await sql`SELECT id, verified FROM users WHERE email = ${em}`;
  if (existing.length && existing[0].verified) return res.status(400).json({ error: 'Email sudah terdaftar. Coba masuk.' });
  const hash = await bcrypt.hash(String(password), 10);
  if (existing.length) {
    await sql`UPDATE users SET name = ${String(name).trim()}, password_hash = ${hash}, verified = FALSE WHERE id = ${existing[0].id}`;
    await sql`UPDATE otps SET used = TRUE WHERE email = ${em} AND purpose = 'verify' AND used = FALSE`;
  } else {
    await sql`INSERT INTO users (email, name, password_hash, verified) VALUES (${em}, ${String(name).trim()}, ${hash}, FALSE)`;
  }
  const code = genCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await sql`INSERT INTO otps (email, code, purpose, expires_at) VALUES (${em}, ${code}, 'verify', ${expires})`;
  try { await sendEmail(em, 'Kode Verifikasi Syon AI', emailTemplate(code, 'Verifikasi Email', 'Masukkan kode berikut untuk mengaktifkan akun Anda.')); }
  catch (e) { return res.status(500).json({ error: 'Gagal kirim email: ' + e.message }); }
  return res.status(200).json({ ok: true, message: 'Kode dikirim ke email' });
}

async function handleVerify(req, res) {
  if (!(await enforceRateLimit(req, res, 'verify', 20, 900))) return;
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'Email dan kode wajib diisi' });
  const em = sanitizeEmail(email);
  const rows = await sql`SELECT id FROM otps WHERE email = ${em} AND code = ${String(code).trim()} AND purpose = 'verify' AND used = FALSE AND expires_at > NOW() ORDER BY id DESC LIMIT 1`;
  if (!rows.length) return res.status(400).json({ error: 'Kode salah atau kadaluarsa' });
  await sql`UPDATE otps SET used = TRUE WHERE id = ${rows[0].id}`;
  await sql`UPDATE users SET verified = TRUE WHERE email = ${em}`;
  const userRows = await sql`SELECT id, email, name FROM users WHERE email = ${em}`;
  if (!userRows.length) return res.status(500).json({ error: 'User tidak ditemukan' });
  const u = userRows[0];
  const token = await createSession(u.id);
  return res.status(200).json({ ok: true, token, user: { id: u.id, email: u.email, name: u.name } });
}

async function handleResendOtp(req, res) {
  if (!(await enforceRateLimit(req, res, 'resend', 5, 900))) return;
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email wajib diisi' });
  const em = sanitizeEmail(email);
  const users = await sql`SELECT id, verified FROM users WHERE email = ${em}`;
  if (!users.length) return res.status(400).json({ error: 'Email tidak terdaftar' });
  if (users[0].verified) return res.status(400).json({ error: 'Email sudah diverifikasi' });
  await sql`UPDATE otps SET used = TRUE WHERE email = ${em} AND purpose = 'verify' AND used = FALSE`;
  const code = genCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await sql`INSERT INTO otps (email, code, purpose, expires_at) VALUES (${em}, ${code}, 'verify', ${expires})`;
  try { await sendEmail(em, 'Kode Verifikasi Syon AI', emailTemplate(code, 'Verifikasi Email', 'Masukkan kode berikut untuk mengaktifkan akun Anda.')); }
  catch (e) { return res.status(500).json({ error: 'Gagal kirim email: ' + e.message }); }
  return res.status(200).json({ ok: true, message: 'Kode baru dikirim' });
}

async function handleLogin(req, res) {
  if (!(await enforceRateLimit(req, res, 'login', 15, 900))) return;
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email dan password wajib diisi' });
  const em = sanitizeEmail(email);
  const users = await sql`SELECT id, email, name, password_hash, verified FROM users WHERE email = ${em}`;
  if (!users.length) return res.status(401).json({ error: 'Email atau password salah' });
  const u = users[0];
  if (!u.password_hash) return res.status(401).json({ error: 'Akun ini pakai Google. Klik tombol Google.' });
  if (!u.verified) return res.status(401).json({ error: 'Email belum diverifikasi', needsVerify: true, email: em });
  const ok = await bcrypt.compare(String(password), u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Email atau password salah' });
  const token = await createSession(u.id);
  return res.status(200).json({ ok: true, token, user: { id: u.id, email: u.email, name: u.name } });
}

async function handleMe(req, res) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token kosong' });
  const rows = await sql`SELECT u.id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ${token} AND s.expires_at > NOW()`;
  if (!rows.length) return res.status(401).json({ error: 'Session tidak valid' });
  return res.status(200).json({ ok: true, user: { id: rows[0].id, email: rows[0].email, name: rows[0].name } });
}

async function handleLogout(req, res) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (token) await sql`DELETE FROM sessions WHERE token = ${token}`;
  return res.status(200).json({ ok: true });
}

async function handleForgot(req, res) {
  if (!(await enforceRateLimit(req, res, 'forgot', 5, 3600))) return;
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email wajib diisi' });
  const em = sanitizeEmail(email);
  const users = await sql`SELECT id FROM users WHERE email = ${em}`;
  if (!users.length) return res.status(200).json({ ok: true, message: 'Jika email terdaftar, kode reset telah dikirim' });
  await sql`UPDATE otps SET used = TRUE WHERE email = ${em} AND purpose = 'reset' AND used = FALSE`;
  const code = genCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await sql`INSERT INTO otps (email, code, purpose, expires_at) VALUES (${em}, ${code}, 'reset', ${expires})`;
  try { await sendEmail(em, 'Reset Password Syon AI', emailTemplate(code, 'Reset Password', 'Masukkan kode berikut untuk mengganti password Anda.')); }
  catch (e) { return res.status(500).json({ error: 'Gagal kirim email: ' + e.message }); }
  return res.status(200).json({ ok: true, message: 'Kode reset dikirim ke email' });
}

async function handleReset(req, res) {
  if (!(await enforceRateLimit(req, res, 'reset', 20, 900))) return;
  const { email, code, newPassword } = req.body || {};
  if (!email || !code || !newPassword) return res.status(400).json({ error: 'Semua kolom wajib diisi' });
  if (String(newPassword).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
  const em = sanitizeEmail(email);
  const rows = await sql`SELECT id FROM otps WHERE email = ${em} AND code = ${String(code).trim()} AND purpose = 'reset' AND used = FALSE AND expires_at > NOW() ORDER BY id DESC LIMIT 1`;
  if (!rows.length) return res.status(400).json({ error: 'Kode salah atau kadaluarsa' });
  const hash = await bcrypt.hash(String(newPassword), 10);
  await sql`UPDATE otps SET used = TRUE WHERE id = ${rows[0].id}`;
  await sql`UPDATE users SET password_hash = ${hash}, verified = TRUE WHERE email = ${em}`;
  await sql`DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email = ${em})`;
  return res.status(200).json({ ok: true, message: 'Password berhasil direset' });
}

async function handleGoogleSync(req, res) {
  if (!(await enforceRateLimit(req, res, 'google', 20, 900))) return;
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: 'Credential Google tidak ditemukan' });
  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    payload = ticket.getPayload();
  } catch (e) {
    console.error('Google token verify failed:', e.message);
    return res.status(401).json({ error: 'Token Google tidak valid' });
  }
  if (!payload || !payload.email || !payload.sub) return res.status(401).json({ error: 'Data Google tidak lengkap' });
  if (payload.email_verified === false) return res.status(401).json({ error: 'Email Google belum diverifikasi' });
  const em = sanitizeEmail(payload.email);
  const name = (payload.name || em).slice(0, 60);
  const googleId = String(payload.sub);
  const picture = payload.picture || null;
  const users = await sql`SELECT id, email, name, google_id FROM users WHERE email = ${em}`;
  let userId;
  if (users.length) {
    userId = users[0].id;
    if (users[0].google_id && users[0].google_id !== googleId) {
      return res.status(409).json({ error: 'Email ini terhubung ke akun Google lain' });
    }
    await sql`UPDATE users SET google_id = ${googleId}, verified = TRUE, name = COALESCE(NULLIF(name,''), ${name}) WHERE id = ${userId}`;
  } else {
    const inserted = await sql`INSERT INTO users (email, name, google_id, verified) VALUES (${em}, ${name}, ${googleId}, TRUE) RETURNING id`;
    userId = inserted[0].id;
  }
  const token = await createSession(userId);
  const userRows = await sql`SELECT id, email, name FROM users WHERE id = ${userId}`;
  const u = userRows[0];
  return res.status(200).json({ ok: true, token, user: { id: u.id, email: u.email, name: u.name, picture } });
}

async function createSession(userId) {
  const token = genToken();
  const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await sql`INSERT INTO sessions (token, user_id, expires_at) VALUES (${token}, ${userId}, ${expires})`;
  return token;
}
