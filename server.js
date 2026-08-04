import express from 'express';
import mongoose from 'mongoose';
import crypto from 'crypto';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3100;
const MONGO_URI = process.env.MONGODB_URI;

// --- MONGODB MODELLE ---

const UserSchema = new mongoose.Schema({
  id: String,
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true },
  jid: String,
  phone: String,
  token: String,
  role: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: { type: Date, default: Date.now },
  botProfile: Object
});
const User = mongoose.model('User', UserSchema);

const BotUserSchema = new mongoose.Schema({
  jid: { type: String, required: true, unique: true },
  name: String,
  phone: String,
  age: Number,
  music_tokens: { type: Number, default: 0 },
  banned: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  registered_at: Date,
  last_reset: Date
});
const BotUser = mongoose.model('BotUser', BotUserSchema);

// --- HILFSFUNKTIONEN (Aus deinem Original-Code) ---

function normalizePhone(value) {
  return String(value || '').replace(/\D/g, '');
}

function normalizeJid(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  if (raw.includes('@')) return raw.toLowerCase();
  return `${raw}@s.whatsapp.net`;
}

function hashPassword(password) {
  return crypto.pbkdf2Sync(password, 'luna-bot-app-secret', 100000, 64, 'sha512').toString('hex');
}

function createToken() {
  return crypto.randomBytes(24).toString('hex');
}

// Erstellt eine schöne Antwort für die App
function buildBotProfilePayload(entry = {}, fallbackKey = '') {
  return {
    jid: entry.jid || fallbackKey,
    phone: normalizePhone(entry.jid || entry.phone || fallbackKey),
    name: entry.name || null,
    registered: Boolean(entry.registered_at && !entry.deleted),
    musicTokens: Number(entry.music_tokens ?? 0),
    banned: Boolean(entry.banned),
    deleted: Boolean(entry.deleted),
    registeredAt: entry.registered_at ?? null
  };
}

// --- API ENDPUNKTE ---

// Health & Status
app.get('/api/health', (req, res) => res.json({ success: true }));

app.get('/api/status', async (req, res) => {
  const count = await BotUser.countDocuments({ registered_at: { $exists: true }, deleted: false });
  res.json({
    success: true,
    data: { botName: 'Luna Bot', connected: true, registeredUsers: count, version: '2.0.0' }
  });
});

// Registrierung
app.post('/api/auth/register', async (req, res) => {
  const { username, password, name, jid, phone } = req.body;
  const botIdentifier = jid || phone;

  if (!username || !password || !botIdentifier) {
    return res.status(400).json({ success: false, error: 'Fehlende Daten' });
  }

  // 1. Prüfen, ob Nummer im Bot-System (MongoDB) ist
  const botEntry = await BotUser.findOne({ 
    $or: [{ jid: normalizeJid(botIdentifier) }, { phone: normalizePhone(botIdentifier) }] 
  });

  if (!botEntry) {
    return res.status(404).json({ success: false, error: 'Nummer nicht im Bot registriert' });
  }

  // 2. Prüfen, ob Account schon existiert
  const exists = await User.findOne({ username: username.toLowerCase() });
  if (exists) return res.status(409).json({ success: false, error: 'Benutzername vergeben' });

  const newUser = new User({
    username: username.toLowerCase(),
    passwordHash: hashPassword(password),
    name,
    jid: botEntry.jid,
    phone: normalizePhone(botEntry.jid),
    token: createToken(),
    botProfile: buildBotProfilePayload(botEntry)
  });

  await newUser.save();
  res.status(201).json({ success: true, data: newUser });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username: username.toLowerCase() });

  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json({ success: false, error: 'Login fehlgeschlagen' });
  }

  user.token = createToken();
  user.lastLoginAt = new Date();
  await user.save();
  res.json({ success: true, data: user });
});

// Profil (ME)
app.get('/api/auth/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await User.findOne({ token });
  if (!user) return res.status(401).json({ success: false });

  // Bot-Profil live aktualisieren
  const botEntry = await BotUser.findOne({ jid: user.jid });
  user.botProfile = buildBotProfilePayload(botEntry || {});

  res.json({ success: true, data: user });
});

// Start
mongoose.connect(MONGO_URI).then(() => {
  app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
});
