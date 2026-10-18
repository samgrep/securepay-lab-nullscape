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

  // Health check
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  // Halaman sambutan (Diperbaiki: Output Encoding untuk XSS)
  app.get('/welcome', (req, res) => {
    const name = req.query.name || 'Tamu';
    res.send(`<h1>Selamat datang di SecurePay, ${escapeHtml(name)}!</h1>`);
  });

  // Login -> mengembalikan JWT (Diperbaiki: Verifikasi Password)
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const rows = allBound(
      db,
      'SELECT id, username, password_hash, role FROM users WHERE username = ?',
      [username]
    );
    
    if (rows.length === 0 || !verifyPassword(String(password), rows[0].password_hash)) {
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

  // Ubah pengaturan aplikasi
  app.post('/api/settings', requireAuth, (req, res) => {
    settings = _.merge(settings, req.body);
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