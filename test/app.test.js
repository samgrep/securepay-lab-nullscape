const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { createApp } = require('../src/app');

let server;
let base;

before(async () => {
  const app = await createApp();
  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });
  base = `http://localhost:${server.address().port}`;
});

after(() => server.close());

async function login(username, password) {
  return fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
}

test('GET /health mengembalikan status ok', async () => {
  const res = await fetch(`${base}/health`);
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(await res.json(), { status: 'ok' });
});

test('GET /welcome menyapa pengguna', async () => {
  const res = await fetch(`${base}/welcome?name=Budi`);
  assert.match(await res.text(), /Budi/);
});

test('pencarian pengguna berdasarkan nama', async () => {
  const res = await fetch(`${base}/api/users/search?q=Budi`);
  const data = await res.json();
  assert.strictEqual(data.length, 1);
  assert.strictEqual(data[0].username, 'budi');
});

test('login berhasil mengembalikan token', async () => {
  const res = await login('budi', 'budi123');
  assert.strictEqual(res.status, 200);
  assert.ok((await res.json()).token);
});

test('login dengan password salah ditolak', async () => {
  const res = await login('budi', 'salah');
  assert.strictEqual(res.status, 401);
});

test('transfer dari budi ke sari berhasil', async () => {
  const { token } = await (await login('budi', 'budi123')).json();
  const res = await fetch(`${base}/api/transfer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ from: 'budi', to: 'sari', amount: 100000 }),
  });
  assert.strictEqual(res.status, 200);
});

test('transfer tanpa token ditolak', async () => {
  const res = await fetch(`${base}/api/transfer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'budi', to: 'sari', amount: 1000 }),
  });
  assert.strictEqual(res.status, 401);
});

// ---------- Security tests (gagal sebelum perbaikan, lulus sesudahnya) ----------
async function tokenOf(u, p) {
  return (await (await login(u, p)).json()).token;
}
function authPost(path, token, body) {
  return fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
}

test('SEC: response memiliki security header & tanpa X-Powered-By', async () => {
  const res = await fetch(`${base}/welcome?name=x`);
  assert.ok(res.headers.get('content-security-policy'));
  assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
  assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
  assert.strictEqual(res.headers.get('x-powered-by'), null);
});

test('SEC: tidak bisa transfer dari akun orang lain', async () => {
  const t = await tokenOf('budi', 'budi123');
  const res = await authPost('/api/transfer', t, { from: 'sari', to: 'budi', amount: 1000 });
  assert.strictEqual(res.status, 403);
});

test('SEC: nominal negatif / nol / bukan angka ditolak', async () => {
  const t = await tokenOf('budi', 'budi123');
  for (const amount of [-500000, 0, '1000', 1.5, null]) {
    const res = await authPost('/api/transfer', t, { from: 'budi', to: 'sari', amount });
    assert.strictEqual(res.status, 400, `amount=${JSON.stringify(amount)}`);
  }
});

test('SEC: customer tidak bisa melihat saldo orang lain', async () => {
  const t = await tokenOf('budi', 'budi123');
  const res = await fetch(`${base}/api/balance/sari`, { headers: { Authorization: `Bearer ${t}` } });
  assert.strictEqual(res.status, 403);
  const own = await fetch(`${base}/api/balance/budi`, { headers: { Authorization: `Bearer ${t}` } });
  assert.strictEqual(own.status, 200);
});

test('SEC: /api/settings hanya untuk admin & kebal prototype pollution', async () => {
  const t = await tokenOf('budi', 'budi123');
  const res = await authPost('/api/settings', t, { dailyTransferLimit: 999999999 });
  assert.strictEqual(res.status, 403);

  const admin = await tokenOf('admin', 'Admin#2024');
  const raw = '{"currency":"USD","__proto__":{"polluted":"yes"}}';
  const r2 = await fetch(`${base}/api/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${admin}` },
    body: raw,
  });
  assert.strictEqual(r2.status, 200);
  assert.strictEqual({}.polluted, undefined);
});

test('SEC: login dibatasi setelah terlalu banyak percobaan gagal', async () => {
  let last;
  for (let i = 0; i < 12; i++) last = await login('andi', 'salah');
  assert.strictEqual(last.status, 429);
});
