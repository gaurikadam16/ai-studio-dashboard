// ---------------------------------------------------------------
//  AI Studio backend — works on your computer AND on Vercel
//  ✅ Sign up / log in   (accounts saved in an Upstash Redis database)
//  ✅ Credits per user   (checked and charged HERE, so nobody can cheat)
//  ✅ Images: fal.ai Nano Banana 2 (+ Edit model when you upload photos, up to 10)
//  ✅ Videos: fal.ai Kling (text -> video, 1 photo -> video, 2–4 photos -> video with references)
//  ✅ Smart suggestions + "Improve my prompt" (a vision AI looks at your photos and words)
//  ✅ Languages: English / हिंदी / मराठी — typing converts to the language, pasted text is translated
// ---------------------------------------------------------------
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { fal } from '@fal-ai/client';
import { Redis } from '@upstash/redis';

const PORT = Number(process.env.PORT) || 5000;
const FAL_KEY = process.env.FAL_KEY;
const AUTH_SECRET = process.env.AUTH_SECRET;
const WEB_SEARCH = process.env.IMAGE_WEB_SEARCH === 'true';

// Websites allowed to call this server (comma-separated in CLIENT_URL)
const ALLOWED_ORIGINS = [
  ...String(process.env.CLIENT_URL || '').split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean),
  'http://localhost:5173',
  'http://127.0.0.1:5173',
];

const MODELS = {
  image: process.env.IMAGE_MODEL || 'fal-ai/nano-banana-2',
  imageEdit: process.env.IMAGE_EDIT_MODEL || 'fal-ai/nano-banana-2/edit',               // images WITH your photos
  textToVideo: process.env.VIDEO_MODEL || 'fal-ai/kling-video/v3/pro/text-to-video',
  imageToVideo: process.env.VIDEO_FROM_IMAGE_MODEL || 'fal-ai/kling-video/v3/pro/image-to-video',   // 1 photo = first frame
  referenceToVideo: process.env.VIDEO_FROM_REFERENCES_MODEL || 'fal-ai/kling-video/o3/pro/reference-to-video', // 2–4 photos
};
// The AI that looks at your photos and writes suggestions (cheap, fast). Change it in .env if you like.
const TEXT_AI = { endpoint: 'openrouter/router/vision', model: process.env.SUGGEST_MODEL || 'google/gemini-2.5-flash' };
const LANGS = { en: 'English', hi: 'Hindi', mr: 'Marathi' };
const langOf = (code) => (LANGS[code] ? code : 'en');
const MAX_IMAGE_REFS = 10; // photos you can upload for an image (the model allows up to 14)
const MAX_VIDEO_REFS = 4;  // photos you can upload for a video
const VIDEO_ENDPOINTS = { t2v: MODELS.textToVideo, i2v: MODELS.imageToVideo, r2v: MODELS.referenceToVideo };

// Clean list of uploaded photo links (only https links, no duplicates)
function readImageUrls(body, max) {
  const list = Array.isArray(body.imageUrls) ? body.imageUrls : body.imageUrl ? [body.imageUrl] : [];
  const urls = [...new Set(list.map(String).filter((u) => /^https:\/\//.test(u)))];
  return { urls, tooMany: urls.length > max, bad: list.length !== urls.length && list.some((u) => !/^https:\/\//.test(String(u))) };
}

// Credit prices — the app shows the same numbers (src/data/constants.js)
const PRICING = {
  imageEach: 2,          // 1 image
  videoPerSecSound: 10,  // 1 second of video WITH sound
  videoPerSecSilent: 5,  // 1 second of video without sound
  signupBonus: 500,      // free credits for every new account
};

// ---- Settings check (a clear message instead of a crash)
const missing = [];
if (!FAL_KEY || FAL_KEY.includes('paste')) missing.push('FAL_KEY');
if (!AUTH_SECRET || AUTH_SECRET.length < 20) missing.push('AUTH_SECRET (at least 20 characters)');
if (!(process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL)) missing.push('Upstash Redis (UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)');
if (missing.length) console.error(`\n  ❌ Missing settings: ${missing.join(', ')}\n`);

if (FAL_KEY) fal.config({ credentials: FAL_KEY });

// ===============================================================
//  DATABASE: Upstash Redis (online, so it works on Vercel)
//   user:<id>         -> { id, name, email, salt, passwordHash, createdAt }
//   email:<email>     -> <id>
//   credits:<id>      -> number
//   job:<jobId>       -> { userId, cost }
//   job:<jobId>:refunded -> 1 (so a video is refunded only once)
// ===============================================================
const redis = missing.some((m) => m.startsWith('Upstash')) ? null : Redis.fromEnv();

const getUser = (id) => redis.get(`user:${id}`);
const getUserByEmail = async (email) => {
  const id = await redis.get(`email:${email}`);
  return id ? getUser(id) : null;
};
const creditsOf = async (id) => Number((await redis.get(`credits:${id}`)) ?? 0);
const publicUser = async (u) => ({ id: u.id, name: u.name, email: u.email, credits: await creditsOf(u.id), createdAt: u.createdAt });

// Take credits (negative amount) or give them back (positive). Returns the new balance, or null if not enough.
async function changeCredits(userId, amount) {
  const left = await redis.incrby(`credits:${userId}`, amount);
  if (left < 0) {
    await redis.incrby(`credits:${userId}`, -amount); // undo: not enough credits
    return null;
  }
  return left;
}

// ===============================================================
//  Passwords + login tokens (built into Node, no extra packages)
// ===============================================================
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function checkPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'));
}

// Token = data + signature. Valid for 30 days. Nobody can fake it without AUTH_SECRET.
function makeToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Date.now() + 30 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function readToken(token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() ? data.uid : null;
  } catch {
    return null;
  }
}

// Express 4 doesn't catch errors in async routes by itself — this does
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Only logged-in users get past this
const requireAuth = wrap(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const userId = readToken(header.startsWith('Bearer ') ? header.slice(7) : '');
  const user = userId && (await getUser(userId));
  if (!user) return res.status(401).json({ error: 'Please log in again.' });
  req.user = user;
  next();
});

// ===============================================================
//  App setup
// ===============================================================
const app = express();
app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.json({ limit: '4mb' })); // Vercel allows up to 4.5 MB per request

// Settings missing -> clear error on every API call (instead of a crash)
app.use('/api', (req, res, next) => {
  if (missing.length && req.path !== '/health') {
    return res.status(503).json({ error: `Server setup is incomplete (admin: add ${missing.join(', ')}).` });
  }
  next();
});

// Limit requests per user (or per computer) per minute — protects your fal.ai money
function rateLimit(maxPerMinute) {
  const hits = new Map();
  return (req, res, next) => {
    const key = req.user?.id || req.ip;
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((t) => now - t < 60_000);
    if (recent.length >= maxPerMinute) return res.status(429).json({ error: 'Too many requests. Please wait a minute and try again.' });
    recent.push(now);
    hits.set(key, recent);
    next();
  };
}

app.get('/', (req, res) => res.json({ ok: true, message: 'AI Studio backend is running. Try /api/health' }));
app.get('/api/health', (req, res) => res.json({ ok: missing.length === 0, missing, models: MODELS, textAI: TEXT_AI.model }));

// ===============================================================
//  ACCOUNTS
// ===============================================================
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/auth/signup', rateLimit(10), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!name) return res.status(400).json({ error: 'Please enter your name.' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const id = crypto.randomUUID();
  // NX = only if this email isn't taken yet (safe even if two people sign up at the same moment)
  const claimed = await redis.set(`email:${email}`, id, { nx: true });
  if (!claimed) return res.status(409).json({ error: 'An account with this email already exists. Please log in.' });

  const { salt, hash } = hashPassword(password);
  const user = { id, name, email, salt, passwordHash: hash, createdAt: Date.now() };
  await redis.set(`user:${id}`, user);
  await redis.set(`credits:${id}`, PRICING.signupBonus);
  console.log(`  👤 New account: ${email}`);
  res.status(201).json({ token: makeToken(id), user: await publicUser(user) });
}));

app.post('/api/auth/login', rateLimit(10), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = await getUserByEmail(email);
  if (!user || !checkPassword(password, user)) return res.status(401).json({ error: 'Email or password is wrong.' });
  res.json({ token: makeToken(user.id), user: await publicUser(user) });
}));

app.get('/api/auth/me', requireAuth, wrap(async (req, res) => res.json({ user: await publicUser(req.user) })));

app.patch('/api/auth/me', requireAuth, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'Name cannot be empty.' });
  const user = { ...req.user, name };
  await redis.set(`user:${user.id}`, user);
  res.json({ user: await publicUser(user) });
}));

// ===============================================================
//  SMART HELPERS (free for users, tiny cost for you)
// ===============================================================
async function askTextAI(prompt, imageUrls, systemPrompt) {
  const result = await fal.subscribe(TEXT_AI.endpoint, {
    input: {
      model: TEXT_AI.model,
      prompt,
      system_prompt: systemPrompt,
      ...(imageUrls.length ? { image_urls: imageUrls } : {}),
      temperature: 0.8,
      max_tokens: 700,
    },
  });
  return String(result.data?.output || '').trim();
}

// Pull the JSON list out of the AI's answer (it sometimes wraps it in ```json ... ```)
function readSuggestionList(text) {
  const start = text.indexOf('[');
  const end = text.lastIndexOf(']');
  if (start === -1 || end <= start) return [];
  try {
    const list = JSON.parse(text.slice(start, end + 1));
    return list
      .filter((s) => s && typeof s.prompt === 'string' && s.prompt.trim())
      .map((s) => ({ title: String(s.title || 'Idea').slice(0, 40), prompt: String(s.prompt).trim().slice(0, 600) }))
      .slice(0, 4);
  } catch {
    return [];
  }
}

app.post('/api/suggest', requireAuth, rateLimit(20), wrap(async (req, res) => {
  const mode = req.body.mode === 'video' ? 'video' : 'image';
  const lang = langOf(req.body.language);
  const text = String(req.body.text || '').trim().slice(0, 500);
  const refs = readImageUrls(req.body, mode === 'video' ? MAX_VIDEO_REFS : MAX_IMAGE_REFS);
  if (refs.bad || !refs.urls.length) return res.status(400).json({ error: 'Add at least one photo to get suggestions.' });

  const n = refs.urls.length;
  const what = mode === 'video'
    ? n === 1
      ? 'short videos (5–10 seconds) where THIS photo is the first frame and comes to life. Describe the motion, camera movement and mood.'
      : `short videos (5–10 seconds) that use these ${n} photos together as references (refer to them as "the person in photo 1", "the product in photo 2" etc.). Describe the scene, motion and camera.`
    : n === 1
      ? 'new images made FROM this photo (for example a new background, a festival poster, a different art style, a product ad). Keep the main subject.'
      : `new images that COMBINE these ${n} photos (refer to them as "photo 1", "photo 2" etc.), for example putting people together, a person holding a product, or a poster.`;

  const system = 'You are a creative director inside an AI image and video app used in India. Look carefully at the photos. '
    + 'Reply with ONLY a JSON array, no other words, in this exact shape: '
    + '[{"title":"2 to 5 words","prompt":"one detailed sentence the user can send to the AI"}]. Give exactly 4 different, practical, eye-catching ideas.'
    + (lang !== 'en' ? ` Write every title and prompt in ${LANGS[lang]} using Devanagari script (keep the JSON keys in English).` : '');
  const ask = `Suggest 4 ideas for ${what}${text ? ` The user's own idea so far: "${text}". Build on it.` : ''}`;

  try {
    const suggestions = readSuggestionList(await askTextAI(ask, refs.urls, system));
    if (!suggestions.length) throw new Error('No suggestions in the answer');
    res.json({ suggestions });
  } catch (err) {
    logFalError('Suggest', req.user.email, err);
    res.status(502).json({ error: 'Could not get suggestions right now. You can still type your own idea.' });
  }
}));

app.post('/api/prompt/improve', requireAuth, rateLimit(20), wrap(async (req, res) => {
  const mode = req.body.mode === 'video' ? 'video' : 'image';
  const lang = langOf(req.body.language);
  const prompt = String(req.body.prompt || '').trim().slice(0, 1500);
  const refs = readImageUrls(req.body, MAX_IMAGE_REFS);
  if (prompt.length < 3) return res.status(400).json({ error: 'Type a few words first.' });

  const system = 'You improve prompts for AI image and video generators. Reply with ONLY the improved prompt: one rich paragraph, no quotes, no lists, no explanations. '
    + 'Keep the user\'s idea and language, add helpful details (subject, setting, lighting, mood, style'
    + (mode === 'video' ? ', motion and camera movement' : ', composition') + '). Keep it under 90 words.'
    + (refs.urls.length ? ' The user also attached photos; mention them as "photo 1", "photo 2" where useful.' : '')
    + ` Write the improved prompt in ${LANGS[lang]}${lang !== 'en' ? ' using Devanagari script' : ''}.`;
  try {
    const better = (await askTextAI(`Improve this ${mode} prompt: ${prompt}`, refs.urls.slice(0, 4), system)).replace(/^["']|["']$/g, '');
    if (better.length < 5) throw new Error('Empty answer');
    res.json({ prompt: better.slice(0, 1500) });
  } catch (err) {
    logFalError('Improve prompt', req.user.email, err);
    res.status(502).json({ error: 'Could not improve the prompt right now. Please try again.' });
  }
}));

// ===============================================================
//  LANGUAGES
// ===============================================================
app.post('/api/translate', requireAuth, rateLimit(60), wrap(async (req, res) => {
  const to = langOf(req.body.to);
  const text = String(req.body.text || '').trim().slice(0, 3000);
  if (!text) return res.json({ text: '' });

  const system = `You are a professional translator. Translate the user's text into ${LANGS[to]}`
    + (to !== 'en' ? ' using Devanagari script' : '')
    + '. Keep the exact meaning, names, brand names and numbers. Make it sound natural. '
    + `If the text is already in ${LANGS[to]}, return it unchanged. Reply with ONLY the translation: no quotes, no notes, no explanations.`;
  try {
    const out = (await askTextAI(text, [], system)).replace(/^["'“”]+|["'“”]+$/g, '').trim();
    res.json({ text: out || text });
  } catch (err) {
    logFalError('Translate', req.user.email, err);
    res.status(502).json({ error: 'Could not translate right now. Please try again.' });
  }
}));

// Typing in English letters -> Marathi/Hindi letters (same tool as Google's Indian keyboards). Free.
app.post('/api/transliterate', requireAuth, rateLimit(300), wrap(async (req, res) => {
  const lang = req.body.lang;
  const text = String(req.body.text || '').slice(0, 60);
  if (!['hi', 'mr'].includes(lang) || !/^[A-Za-z]+$/.test(text)) return res.json({ text });
  try {
    const url = `https://inputtools.google.com/request?text=${encodeURIComponent(text)}&itc=${lang}-t-i0-und&num=1&cp=0&cs=1&ie=utf-8&oe=utf-8&app=aistudio`;
    const r = await fetch(url, { signal: AbortSignal.timeout(4000) });
    const data = await r.json();
    const best = data?.[0] === 'SUCCESS' ? data?.[1]?.[0]?.[1]?.[0] : null;
    res.json({ text: best || text });
  } catch {
    res.json({ text }); // if the tool is unreachable, keep what the user typed
  }
}));

// ===============================================================
//  IMAGES  (takes credits first, gives them back if it fails)
// ===============================================================
const IMAGE_RATIOS = ['1:1', '4:5', '9:16', '16:9'];

app.post('/api/images', requireAuth, rateLimit(15), wrap(async (req, res) => {
  const prompt = String(req.body.prompt || '').trim();
  const count = Number(req.body.count) || 1;
  const aspectRatio = String(req.body.aspectRatio || '1:1');

  if (prompt.length < 2) return res.status(400).json({ error: 'Please describe your idea first.' });
  if (prompt.length > 3000) return res.status(400).json({ error: 'Your description is too long. Keep it under 3000 characters.' });
  if (![1, 2, 3, 4].includes(count)) return res.status(400).json({ error: 'You can make 1 to 4 images at a time.' });
  if (!IMAGE_RATIOS.includes(aspectRatio)) return res.status(400).json({ error: 'Please pick a valid size.' });

  const refs = readImageUrls(req.body, MAX_IMAGE_REFS);
  if (refs.bad) return res.status(400).json({ error: 'Please upload your photos again.' });
  if (refs.tooMany) return res.status(400).json({ error: `You can use up to ${MAX_IMAGE_REFS} photos for an image.` });

  const cost = count * PRICING.imageEach;
  if ((await changeCredits(req.user.id, -cost)) === null) {
    return res.status(402).json({ error: `Not enough credits. This needs ${cost} credits.`, credits: await creditsOf(req.user.id) });
  }

  const started = Date.now();
  try {
    const result = refs.urls.length
      ? await fal.subscribe(MODELS.imageEdit, { input: { prompt, image_urls: refs.urls, num_images: count } })
      : await fal.subscribe(MODELS.image, {
          input: { prompt, num_images: count, aspect_ratio: aspectRatio, output_format: 'jpeg', resolution: '1K', enable_web_search: WEB_SEARCH },
        });
    const images = (result.data?.images || []).map((img, i) => ({ id: `img_${Date.now()}_${i}`, url: img.url }));
    if (!images.length) throw new Error('The AI did not return an image.');

    console.log(`  🖼️  ${req.user.email}: ${images.length} image(s) in ${secs(started)}s${refs.urls.length ? ` using ${refs.urls.length} photo(s)` : ''}`);
    res.json({ images, description: result.data?.description || '', credits: await creditsOf(req.user.id) });
  } catch (err) {
    const credits = await changeCredits(req.user.id, cost); // give the credits back
    const { status, message } = explainFalError(err);
    logFalError('Image', req.user.email, err);
    res.status(status).json({ error: `${message} Your credits were returned.`, credits });
  }
}));

// ===============================================================
//  PHOTO UPLOAD (one photo per request; the app sends them one by one)
// ===============================================================
app.post('/api/uploads', requireAuth, rateLimit(40), wrap(async (req, res) => {
  const match = /^data:(image\/(png|jpeg|jpg|webp));base64,(.+)$/.exec(String(req.body.dataUrl || ''));
  if (!match) return res.status(400).json({ error: 'Please upload a PNG, JPG or WEBP image.' });
  const buffer = Buffer.from(match[3], 'base64');
  try {
    const url = await fal.storage.upload(new Blob([buffer], { type: match[1] }));
    console.log(`  📤 ${req.user.email}: photo uploaded (${(buffer.length / 1024).toFixed(0)} KB)`);
    res.json({ url });
  } catch (err) {
    logFalError('Upload', req.user.email, err);
    const { status, message } = explainFalError(err);
    res.status(status).json({ error: message });
  }
}));

// ===============================================================
//  VIDEOS (Kling) — takes credits when starting, refunds if it fails
// ===============================================================
const VIDEO_RATIOS = ['16:9', '9:16'];
const MIN_SECONDS = 3;
const MAX_SECONDS = 15;

app.post('/api/videos', requireAuth, rateLimit(5), wrap(async (req, res) => {
  const prompt = String(req.body.prompt || '').trim();
  const seconds = Math.round(Number(req.body.seconds) || 5);
  const aspectRatio = String(req.body.aspectRatio || '16:9');
  const sound = req.body.sound === true;
  const refs = readImageUrls(req.body, MAX_VIDEO_REFS);

  if (prompt.length < 2) return res.status(400).json({ error: 'Please describe your video first.' });
  if (prompt.length > 2500) return res.status(400).json({ error: 'Your description is too long. Keep it under 2500 characters.' });
  if (seconds < MIN_SECONDS || seconds > MAX_SECONDS) return res.status(400).json({ error: `Video length must be ${MIN_SECONDS}–${MAX_SECONDS} seconds.` });
  if (!VIDEO_RATIOS.includes(aspectRatio)) return res.status(400).json({ error: 'Pick Landscape 16:9 or Reels 9:16.' });
  if (refs.bad) return res.status(400).json({ error: 'Please upload your photos again.' });
  if (refs.tooMany) return res.status(400).json({ error: `You can use up to ${MAX_VIDEO_REFS} photos for a video.` });

  const cost = seconds * (sound ? PRICING.videoPerSecSound : PRICING.videoPerSecSilent);
  if ((await changeCredits(req.user.id, -cost)) === null) {
    return res.status(402).json({ error: `Not enough credits. This video needs ${cost} credits.`, credits: await creditsOf(req.user.id) });
  }

  // 0 photos = text -> video | 1 photo = it becomes the first frame | 2–4 photos = references
  const kind = refs.urls.length === 0 ? 't2v' : refs.urls.length === 1 ? 'i2v' : 'r2v';
  const endpoint = VIDEO_ENDPOINTS[kind];
  let input;
  if (kind === 'r2v') {
    const tags = refs.urls.map((_, i) => `@Image${i + 1}`).join(', ');
    input = {
      prompt: `${prompt}. Use ${tags} as references for the people, objects and style.`,
      image_urls: refs.urls,
      duration: String(seconds),
      aspect_ratio: aspectRatio,
      generate_audio: sound,
    };
  } else {
    input = {
      prompt,
      duration: String(seconds),
      generate_audio: sound,
      negative_prompt: 'blur, distort, low quality, extra limbs, deformed hands, watermark, text',
      ...(kind === 'i2v' ? { start_image_url: refs.urls[0] } : { aspect_ratio: aspectRatio }),
    };
  }

  try {
    const { request_id } = await fal.queue.submit(endpoint, { input });
    const jobId = `${kind}~${Date.now()}~${request_id}`;
    await redis.set(`job:${jobId}`, { userId: req.user.id, cost }, { ex: 60 * 60 * 24 * 30 }); // keep 30 days
    console.log(`  🎬 ${req.user.email}: video started (${seconds}s, ${aspectRatio}, sound ${sound ? 'ON' : 'OFF'}, ${kind}, ${refs.urls.length} photo(s))`);
    res.json({ jobId, credits: await creditsOf(req.user.id) });
  } catch (err) {
    const credits = await changeCredits(req.user.id, cost); // give the credits back
    logFalError('Video start', req.user.email, err);
    const { status, message } = explainFalError(err);
    res.status(status).json({ error: `${message} Your credits were returned.`, credits });
  }
}));

// Give the credits back ONCE if a video fails
async function refundVideo(jobId) {
  const job = await redis.get(`job:${jobId}`);
  if (!job) return null;
  const first = await redis.set(`job:${jobId}:refunded`, 1, { nx: true, ex: 60 * 60 * 24 * 30 });
  if (!first) return null; // already refunded
  return changeCredits(job.userId, job.cost);
}

app.get('/api/videos/:jobId', requireAuth, wrap(async (req, res) => {
  const jobId = String(req.params.jobId);
  const [kind, startedAt, requestId] = jobId.split('~');
  const job = await redis.get(`job:${jobId}`);
  if (!VIDEO_ENDPOINTS[kind] || !requestId || (job && job.userId !== req.user.id)) {
    return res.status(404).json({ error: 'Video not found.' });
  }
  const endpoint = VIDEO_ENDPOINTS[kind];
  const elapsed = (Date.now() - Number(startedAt)) / 1000;
  const estimate = Math.min(95, Math.round(5 + (elapsed / 200) * 90)); // fal gives no %, so we estimate

  try {
    const st = await fal.queue.status(endpoint, { requestId, logs: false });
    if (st.status === 'IN_QUEUE') return res.json({ status: 'running', progress: Math.min(estimate, 10) });
    if (st.status === 'IN_PROGRESS') return res.json({ status: 'running', progress: estimate });
    if (st.status === 'COMPLETED') {
      try {
        const result = await fal.queue.result(endpoint, { requestId });
        const url = result.data?.video?.url;
        if (url) return res.json({ status: 'done', progress: 100, url });
        const credits = await refundVideo(jobId);
        return res.json({ status: 'failed', error: 'The AI did not return a video. Your credits were returned.', credits });
      } catch (err) {
        logFalError('Video', req.user.email, err);
        const credits = await refundVideo(jobId);
        return res.json({ status: 'failed', error: `${explainFalError(err).message} Your credits were returned.`, credits });
      }
    }
    res.json({ status: 'running', progress: estimate });
  } catch (err) {
    const { status, message } = explainFalError(err);
    res.status(status).json({ error: message });
  }
}));

// ===============================================================
//  Helpers
// ===============================================================
const secs = (start) => ((Date.now() - start) / 1000).toFixed(1);

function readFalText(err) {
  const detail = err?.body?.detail;
  if (Array.isArray(detail)) return detail.map((d) => d?.msg || JSON.stringify(d)).join(' | ');
  if (typeof detail === 'string') return detail;
  if (err?.body) return JSON.stringify(err.body).slice(0, 300);
  return err?.message || '';
}

function logFalError(what, email, err) {
  console.error(`  ❌ ${what} failed for ${email} (${err?.status || '?'}): ${readFalText(err) || 'no details'}`);
}

// Turn fal.ai errors into simple messages for the user
function explainFalError(err) {
  const code = err?.status;
  const text = readFalText(err);
  if (/user is locked|admin lock/i.test(text)) return { status: 503, message: 'The AI service is temporarily unavailable. Please try again later.' };
  if (code === 402 || /balance|billing|payment|exhausted|insufficient/i.test(text)) {
    return { status: 503, message: 'The AI service is paused right now (admin: add credits on fal.ai).' };
  }
  if (code === 401 || code === 403) return { status: 503, message: 'The AI service key is not working (admin: check FAL_KEY).' };
  if (/did not generate the expected output/i.test(text)) {
    return { status: 400, message: "The AI couldn't make this. Try simpler words, avoid real famous people or brand names, and if your text mentions \"photo 1\", add that photo first." };
  }
  if (/safety|content|policy|nsfw|moderation/i.test(text)) return { status: 400, message: 'This idea was blocked by the safety filter. Try different words.' };
  if (/dimensions are too small|minimum dimensions/i.test(text)) return { status: 400, message: 'A photo is too small. Use photos of at least 300 × 300 pixels.' };
  if (code === 422) return { status: 400, message: text || 'The AI could not use this request. Try different words.' };
  if (code === 429) return { status: 429, message: 'The AI service is busy. Wait a few seconds and try again.' };
  return { status: 502, message: 'The AI service had a problem. Please try again.' };
}

// Last safety net: any unexpected error -> a clear JSON message (never an empty crash)
app.use((err, req, res, next) => {
  console.error('  ⚠️  Unexpected error:', err?.message || err);
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'The photo is too big. Please use a smaller one.' });
  res.status(500).json({ error: 'Something went wrong on the server. Please try again.' });
});

// ===============================================================
//  Start
//  On Vercel: Vercel runs the app itself (we only export it).
//  On your computer: we start it on port 5000.
// ===============================================================
if (!process.env.VERCEL) {
  process.on('unhandledRejection', (err) => console.error('  ⚠️  Unhandled error (server kept running):', err?.message || err));
  const server = app.listen(PORT, () => {
    console.log(`\n  🚀 Backend running on http://localhost:${PORT}`);
    console.log(`  🗄️  Accounts & credits: Upstash Redis ${redis ? '(connected)' : '(NOT set up)'}`);
    console.log(`  🖼️  Images: ${MODELS.image}  |  with photos: ${MODELS.imageEdit}`);
    console.log(`  💡 Suggestions, improve prompt & translation: ${TEXT_AI.model}`);
    console.log(`  🎬 Videos: ${MODELS.textToVideo}  |  1 photo: ${MODELS.imageToVideo}  |  2–4 photos: ${MODELS.referenceToVideo}\n`);
  });
  server.keepAliveTimeout = 120_000;
  server.headersTimeout = 121_000;
  server.requestTimeout = 0;
}

export default app;