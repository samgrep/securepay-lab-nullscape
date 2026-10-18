const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const config = require('./config');
const { createDb, hashPassword, all, allBound } = require('./db');

async function createApp() {
  const app = express();
  const db = await createDb();
  let settings = _.cloneDeep(config.defaultSettings);

  app.use(express.json());

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
  function escapeHtml(unsafe) {
    return String(unsafe)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Health check
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Halaman sambutan
  app.get('/welcome', (req, res) => {
    const name = req.query.name || 'Tamu';
    const safeName = escapeHtml(name); // Input diamankan di sini
    res.send(`<h1>Selamat datang di SecurePay, ${safeName}!</h1>`);
  });

// Login -> mengembalikan JWT
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // 1. HANYA cari berdasarkan username (Jangan ada cek password di SQL)
    const rows = allBound(db, 'SELECT id, username, role, password_hash FROM users WHERE username = ?', [username]);
    
    // Jika username tidak ada di database
    if (rows.length === 0) return res.status(401).json({ error: 'Username atau password salah' });
    
    const user = rows[0];
    
    // 2. Pisahkan salt dan hash yang tersimpan di database
    const [savedSalt, savedHash] = user.password_hash.split(':');
    
    // 3. Hash ulang password input menggunakan salt dari database
    const crypto = require('crypto');
    const hashAttempt = crypto.scryptSync(String(password), savedSalt, 64).toString('hex');
    
    // 4. Bandingkan dengan timingSafeEqual (diubah ke format buffer 'hex' agar akurat)
    const isMatch = crypto.timingSafeEqual(Buffer.from(savedHash, 'hex'), Buffer.from(hashAttempt, 'hex'));
    
    // Jika password tidak cocok
    if (!isMatch) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    // Jika berhasil, buat token
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, config.jwtSecret, {
      expiresIn: '1h',
    });
    res.json({ token });
  });

// 1. Cari pengguna berdasarkan nama
  app.get('/api/users/search', (req, res) => {
    const q = req.query.q || '';
    // Ganti fungsi all() menjadi allBound() dengan parameter array
    const rows = allBound(db, `SELECT id, username, full_name FROM users WHERE full_name LIKE ?`, [`%${q}%`]);
    res.json(rows);
  });

  // 2. Detail pengguna berdasarkan id
  app.get('/api/users/:id', (req, res) => {
    // Ganti fungsi all() menjadi allBound() dengan parameter array
    const rows = allBound(db, 'SELECT id, username, full_name, role FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Pengguna tidak ditemukan' });
    res.json(rows[0]);
  });
  
  // Transfer uang antar pengguna (Diperbaiki dari Celah Logika Bisnis)
  app.post('/api/transfer', requireAuth, (req, res) => {
    const { from, to, amount } = req.body;
    // FIX 1: Pastikan pengirim adalah user yang sedang terautentikasi (Cegah IDOR)
    if (from !== req.user.username) {
      return res.status(403).json({ error: 'Anda tidak diizinkan melakukan transfer dari akun ini' });
    }
    // FIX 2: Validasi amount harus berupa angka dan bernilai positif
    if (typeof amount !== 'number' || amount <= 0 || isNaN(amount)) {
      return res.status(400).json({ error: 'Jumlah transfer harus berupa angka positif' });
    }
    // FIX Tambahan: Mencegah transfer ke diri sendiri
    if (from === to) {
      return res.status(400).json({ error: 'Tidak dapat melakukan transfer ke akun sendiri' });
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
    const rows = allBound(db, 'SELECT username, balance FROM users WHERE username = ?', [req.params.username]);
    if (rows.length === 0) return res.status(404).json({ error: 'Akun tidak ditemukan' });
    res.json(rows[0]);
  });

  // Ubah pengaturan aplikasi (digabung dengan pengaturan yang ada)
  app.post('/api/settings', requireAuth, (req, res) => {
    settings = _.merge(settings, req.body);
    res.json(settings);
  });

  // Penanganan error
  app.use((err, req, res, next) => {
    console.error(err.stack); // Catat detail error secara diam-diam di terminal server
    res.status(500).send('Maaf, terjadi kesalahan pada sistem kami.'); // Tampilkan pesan aman ke pengguna
  });

  return app;
}

module.exports = { createApp };