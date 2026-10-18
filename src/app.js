const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const config = require('./config');
const { createDb, verifyPassword, allBound } = require('./db');

// Helper Output Encoding untuk Mencegah XSS
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function createApp() {
  const app = express();
  const db = await createDb();
  let settings = _.cloneDeep(config.defaultSettings);

  app.disable('x-powered-by');
  app.use(express.json());

  // Security headers (temuan DAST: CSP, anti-clickjacking, nosniff, X-Powered-By)
  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy':
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cache-Control': 'no-store',
    });
    next();
  });

  // Pembatasan percobaan login (anti brute force): maks 10 gagal / 15 menit per IP+username
  const failedLogins = new Map();
  const LOGIN_WINDOW_MS = 15 * 60 * 1000;
  const LOGIN_MAX_FAILS = 10;
  function loginKey(req) {
    return `${req.ip}|${String((req.body && req.body.username) || '').toLowerCase()}`;
  }
  function isLoginBlocked(key) {
    const entry = failedLogins.get(key);
    if (!entry) return false;
    if (Date.now() - entry.first > LOGIN_WINDOW_MS) {
      failedLogins.delete(key);
      return false;
    }
    return entry.count >= LOGIN_MAX_FAILS;
  }
  function recordLoginFail(key) {
    const entry = failedLogins.get(key);
    if (!entry || Date.now() - entry.first > LOGIN_WINDOW_MS) {
      failedLogins.set(key, { count: 1, first: Date.now() });
    } else {
      entry.count += 1;
    }
  }

  // Middleware autentikasi JWT
  function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.replace('Bearer ', '');
    try {
      req.user = jwt.verify(token, config.jwtSecret);
      next();
    } catch (err) {
      res.status(401).json({ error: 'Token tidak valid' });
    }
  }

  // Health check
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  // Halaman sambutan (Diperbaiki: Output Encoding untuk XSS)
  app.get('/welcome', (req, res) => {
    const name = req.query.name || 'Tamu';
    res.send(`<h1>Selamat datang di SecurePay, ${escapeHtml(name)}!</h1>`);
  });

  // Login -> mengembalikan JWT (Diperbaiki: Verifikasi Password)
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    const key = loginKey(req);
    if (isLoginBlocked(key)) {
      return res.status(429).json({ error: 'Terlalu banyak percobaan login, coba lagi nanti' });
    }
    const rows = allBound(
      db,
      'SELECT id, username, password_hash, role FROM users WHERE username = ?',
      [username]
    );
    
    if (rows.length === 0 || !verifyPassword(String(password), rows[0].password_hash)) {
      recordLoginFail(key);
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const token = jwt.sign(
      { id: rows[0].id, username: rows[0].username, role: rows[0].role },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
    res.json({ token });
  });

  // Cari pengguna berdasarkan nama (Diperbaiki: Parameterized Query)
  app.get('/api/users/search', (req, res) => {
    const q = req.query.q || '';
    const rows = allBound(
      db,
      'SELECT id, username, full_name FROM users WHERE full_name LIKE ?',
      [`%${q}%`]
    );
    res.json(rows);
  });

  // Detail pengguna berdasarkan id (Diperbaiki: Parameterized Query & Validasi Angka)
  app.get('/api/users/:id', (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: 'ID tidak valid' });
    }

    const rows = allBound(
      db,
      'SELECT id, username, full_name, role FROM users WHERE id = ?',
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    res.json(rows[0]);
  });

  // Transfer uang antar pengguna
  app.post('/api/transfer', requireAuth, (req, res) => {
    const { from, to, amount } = req.body || {};
    // Otorisasi: hanya boleh memindahkan uang dari akun milik sendiri (cegah BOLA/IDOR)
    if (from !== req.user.username) {
      return res.status(403).json({ error: 'Tidak boleh mentransfer dari akun orang lain' });
    }
    // Validasi input: nominal harus bilangan bulat positif, dan tujuan harus akun lain
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Nominal tidak valid' });
    }
    if (to === from) {
      return res.status(400).json({ error: 'Akun tujuan tidak valid' });
    }
    const sender = allBound(db, 'SELECT * FROM users WHERE username = ?', [from])[0];
    const receiver = allBound(db, 'SELECT * FROM users WHERE username = ?', [to])[0];
    if (!sender || !receiver) return res.status(404).json({ error: 'Akun tidak ditemukan' });
    if (sender.balance < amount) return res.status(400).json({ error: 'Saldo tidak cukup' });

    db.run('UPDATE users SET balance = balance - ? WHERE username = ?', [amount, from]);
    db.run('UPDATE users SET balance = balance + ? WHERE username = ?', [amount, to]);
    res.json({ message: 'Transfer berhasil', from, to, amount });
  });

  // Lihat saldo
  app.get('/api/balance/:username', requireAuth, (req, res) => {
    // Otorisasi: hanya pemilik akun atau admin
    if (req.params.username !== req.user.username && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Akses ditolak' });
    }
    const rows = allBound(db, 'SELECT username, balance FROM users WHERE username = ?', [req.params.username]);
    if (rows.length === 0) return res.status(404).json({ error: 'Akun tidak ditemukan' });
    res.json(rows[0]);
  });

  // Ubah pengaturan aplikasi
  app.post('/api/settings', requireAuth, (req, res) => {
    // Otorisasi: hanya admin; hanya key yang diizinkan (cegah mass assignment & prototype pollution)
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Akses ditolak' });
    }
    const body = req.body || {};
    const next = { ...settings, notifications: { ...settings.notifications } };
    if (body.currency !== undefined) {
      if (typeof body.currency !== 'string' || !/^[A-Z]{3}$/.test(body.currency)) {
        return res.status(400).json({ error: 'Mata uang tidak valid' });
      }
      next.currency = body.currency;
    }
    if (body.dailyTransferLimit !== undefined) {
      if (!Number.isSafeInteger(body.dailyTransferLimit) || body.dailyTransferLimit <= 0) {
        return res.status(400).json({ error: 'Limit tidak valid' });
      }
      next.dailyTransferLimit = body.dailyTransferLimit;
    }
    if (body.notifications && typeof body.notifications === 'object') {
      for (const k of ['email', 'sms']) {
        if (typeof body.notifications[k] === 'boolean') next.notifications[k] = body.notifications[k];
      }
    }
    settings = next;
    res.json(settings);
  });

  // Penanganan error (Diperbaiki: Catat ke console, sembunyikan stack trace dari klien)
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
  });

  return app;
}

module.exports = { createApp };