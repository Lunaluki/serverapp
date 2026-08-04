import express from 'express';
import mongoose from 'mongoose';
import crypto from 'crypto';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// Datenbank-Struktur
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true },
  jid: { type: String, required: true, unique: true },
  token: String,
  botProfile: Object
}));

const BotUser = mongoose.model('BotUser', new mongoose.Schema({
  jid: { type: String, required: true, unique: true },
  name: String,
  musicTokens: { type: Number, default: 0 },
  banned: { type: Boolean, default: false },
  registered_at: Date
}));

const hashPassword = (pw) => crypto.pbkdf2Sync(pw, 'luna-bot-secret', 100000, 64, 'sha512').toString('hex');
const createToken = () => crypto.randomBytes(24).toString('hex');

// Endpunkte
app.post('/api/auth/register', async (req, res) => {
  const { username, password, name, jid } = req.body;
  const botEntry = await BotUser.findOne({ jid: jid.toLowerCase() });
  if (!botEntry) return res.status(404).json({ success: false, error: 'Nummer nicht im Bot-System' });

  const newUser = new User({
    username: username.toLowerCase(),
    passwordHash: hashPassword(password),
    name, jid: jid.toLowerCase(), token: createToken(), botProfile: botEntry
  });
  await newUser.save();
  res.status(201).json({ success: true, data: newUser });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username: username.toLowerCase() });
  if (!user || user.passwordHash !== hashPassword(password)) return res.status(401).json({ success: false, error: 'Fehler' });
  user.token = createToken();
  await user.save();
  res.json({ success: true, data: user });
});

app.get('/api/auth/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = await User.findOne({ token });
  if (!user) return res.status(401).json({ success: false });
  const botData = await BotUser.findOne({ jid: user.jid });
  res.json({ success: true, data: { ...user.toObject(), botProfile: botData } });
});

app.get('/api/status', (req, res) => res.json({ success: true, data: { botName: 'Luna Bot', connected: true } }));

const PORT = process.env.PORT || 3100;
mongoose.connect(process.env.MONGODB_URI).then(() => {
  app.listen(PORT, () => console.log(`🚀 Server läuft auf Port ${PORT}`));
});
