const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 4000;
const SECRET = process.env.LICENSE_SECRET || 'mude-este-segredo';
const DB = new Database('licenses.db');

DB.prepare(`
CREATE TABLE IF NOT EXISTS licenses (
  license TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  issuedAt INTEGER NOT NULL,
  durationDays INTEGER,
  nonce TEXT NOT NULL,
  boundHwid TEXT,
  activatedAt INTEGER,
  revoked INTEGER DEFAULT 0
)`).run();

function signLicense(payload) {
  const unsigned = JSON.stringify({ ...payload, sig: undefined });
  const sig = crypto.createHmac('sha256', SECRET).update(unsigned).digest('base64url');
  return Buffer.from(JSON.stringify({ ...payload, sig })).toString('base64url');
}

function parseLicense(licenseStr) {
  try {
    return JSON.parse(Buffer.from(licenseStr, 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

function validateLicense(licenseStr, hwid) {
  const obj = parseLicense(licenseStr);
  if (!obj) return { ok: false, reason: 'Licença inválida' };
  const { type, issuedAt, durationDays, nonce, sig } = obj;
  if (!type || !issuedAt || !nonce || !sig) return { ok: false, reason: 'Campos faltando' };
  const unsigned = JSON.stringify({ type, issuedAt, durationDays, nonce, sig: undefined });
  const expected = crypto.createHmac('sha256', SECRET).update(unsigned).digest('base64url');
  if (expected !== sig) return { ok: false, reason: 'Assinatura inválida' };
  if (type !== 'lifetime') {
    const days = type === 'daily' ? 1 : type === 'monthly' ? 30 : durationDays || 30;
    const expires = issuedAt + days * 24 * 60 * 60 * 1000;
    if (Date.now() > expires) return { ok: false, reason: 'Licença expirada' };
  }
  return { ok: true, payload: obj };
}

const app = express();
app.use(cors());
app.use(express.json());

// Servir arquivos estáticos (frontend)
const path = require('path');
const fs = require('fs');
const publicPath = path.join(__dirname, '../public');
console.log('📁 Public path:', publicPath);
console.log('📁 Public exists:', fs.existsSync(publicPath));
if (fs.existsSync(publicPath)) {
  console.log('📁 Files in public:', fs.readdirSync(publicPath));
}
app.use(express.static(publicPath));

app.get('/api/health', (_req, res) => res.json({ ok: true, version: '1.0.0' }));

app.post('/api/license/create', (req, res) => {
  const { type } = req.body || {};
  if (!['daily', 'monthly', 'lifetime'].includes(type)) {
    return res.status(400).json({ ok: false, reason: 'Tipo inválido' });
  }
  const durationDays = type === 'daily' ? 1 : type === 'monthly' ? 30 : null;
  const payload = {
    type,
    issuedAt: Date.now(),
    durationDays,
    nonce: crypto.randomUUID()
  };
  const license = signLicense(payload);
  DB.prepare(`INSERT INTO licenses
    (license, type, issuedAt, durationDays, nonce, boundHwid, activatedAt, revoked)
    VALUES (?, ?, ?, ?, ?, NULL, NULL, 0)
  `).run(license, payload.type, payload.issuedAt, payload.durationDays, payload.nonce);
  return res.json({ ok: true, license });
});

app.post('/api/license/activate', (req, res) => {
  const { license, hwid } = req.body || {};
  if (!license || !hwid) return res.status(400).json({ ok: false, reason: 'Faltam dados' });
  const parsed = validateLicense(license, hwid);
  if (!parsed.ok) return res.status(400).json(parsed);
  const rec = DB.prepare('SELECT * FROM licenses WHERE license = ?').get(license);
  if (!rec) return res.status(400).json({ ok: false, reason: 'Licença não encontrada' });
  if (rec.revoked) return res.status(400).json({ ok: false, reason: 'Licença revogada' });
  if (rec.boundHwid && rec.boundHwid !== hwid) {
    return res.status(400).json({ ok: false, reason: 'Licença já usada em outro hardware' });
  }
  const activatedAt = rec.activatedAt || Date.now();
  const boundHwid = rec.boundHwid || hwid;
  DB.prepare('UPDATE licenses SET boundHwid = ?, activatedAt = ? WHERE license = ?')
    .run(boundHwid, activatedAt, license);
  return res.json({ ok: true, boundHwid, activatedAt, payload: parsed.payload });
});

app.post('/api/license/validate', (req, res) => {
  const { license, hwid } = req.body || {};
  if (!license || !hwid) return res.status(400).json({ ok: false, reason: 'Faltam dados' });
  const parsed = validateLicense(license, hwid);
  if (!parsed.ok) return res.status(400).json(parsed);
  const rec = DB.prepare('SELECT * FROM licenses WHERE license = ?').get(license);
  if (!rec) return res.status(400).json({ ok: false, reason: 'Licença não encontrada' });
  if (rec.revoked) return res.status(400).json({ ok: false, reason: 'Licença revogada' });
  if (!rec.boundHwid) return res.status(400).json({ ok: false, reason: 'Licença não ativada' });
  if (rec.boundHwid !== hwid) return res.status(400).json({ ok: false, reason: 'HWID diferente do ativado' });
  return res.json({ ok: true, payload: parsed.payload, boundHwid: rec.boundHwid });
});

// Rota raiz para servir o index.html
app.get('/', (_req, res) => {
  const indexPath = path.join(__dirname, '../public/index.html');
  console.log('🏠 Root route hit, serving:', indexPath);
  console.log('🏠 File exists:', fs.existsSync(indexPath));
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('index.html not found at: ' + indexPath);
  }
});

const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`License server on http://${HOST}:${PORT}`);
});

