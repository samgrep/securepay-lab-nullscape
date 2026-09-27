const crypto = require('crypto');
const initSqlJs = require('sql.js');

// Hash password menggunakan scrypt + salt acak
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}

// Verifikasi password secara aman (Timing Safe)
function verifyPassword(password, storedHash) {
  const [salt, key] = storedHash.split(':');
  if (!salt || !key) return false;
  
  const keyBuffer = Buffer.from(key, 'hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  
  return crypto.timingSafeEqual(keyBuffer, derivedKey);
}

// Membuat database SQLite in-memory berisi data contoh
async function createDb() {
  const SQL = await initSqlJs();
  const db = new SQL.Database();

  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    full_name TEXT,
    role TEXT,
    balance INTEGER
  )`);

  const seed = [
    ['admin', 'Admin#2024', 'Administrator SecurePay', 'admin', 0],
    ['budi', 'budi123', 'Budi Santoso', 'customer', 5000000],
    ['sari', 'sari123', 'Sari Wulandari', 'customer', 7500000],
    ['andi', 'andi123', 'Andi Pratama', 'customer', 2500000],
  ];
  const stmt = db.prepare(
    'INSERT INTO users (username, password_hash, full_name, role, balance) VALUES (?, ?, ?, ?, ?)'
  );
  for (const [u, p, name, role, bal] of seed) {
    stmt.run([u, hashPassword(p), name, role, bal]);
  }
  stmt.free();

  return db;
}

// Helper: jalankan query SELECT dan kembalikan array of object
function all(db, sql) {
  const result = db.exec(sql);
  if (result.length === 0) return [];
  const { columns, values } = result[0];
  return values.map((row) => Object.fromEntries(row.map((v, i) => [columns[i], v])));
}

// Helper: SELECT dengan parameter (prepared statement)
function allBound(db, sql, params) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

module.exports = { createDb, hashPassword, verifyPassword, all, allBound };