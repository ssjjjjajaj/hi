/*
 * The CX Algorithm — site server with hidden admin.
 *
 * Run:   node server.js          (serves the site on http://localhost:4173)
 * Admin: http://localhost:4173/admin  — browser will ask for the credentials below.
 *
 * CHANGE THIS PASSWORD before putting the site anywhere public:
 */
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'cxalgorithm2026';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 4173;
const UPLOAD_DIR = path.join(ROOT, 'assets', 'uploads');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.mp3': 'audio/mpeg',
  '.m4a': 'audio/mp4',
  '.wav': 'audio/wav',
  '.aac': 'audio/aac',
  '.ogg': 'audio/ogg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/quicktime'
};

const MEDIA_EXT = new Set(['.mp3', '.m4a', '.wav', '.aac', '.ogg', '.mp4', '.webm', '.mov', '.pdf', '.zip']);
const MEDIA_DIR = path.join(ROOT, 'assets', 'media');
const MEDIA_MAX_BYTES = 1024 * 1024 * 1024; // 1 GB per file

const MESSAGES_FILE = path.join(ROOT, 'messages.json');
const contactHits = new Map(); // naive per-IP rate limit for /api/contact

function readMessages() {
  try { return JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf-8')); } catch (e) { return []; }
}
function writeMessages(list) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(list, null, 2), 'utf-8');
}

function timingSafeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function isAuthed(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) return false;
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf-8');
  const idx = decoded.indexOf(':');
  if (idx < 0) return false;
  const user = decoded.slice(0, idx);
  const pass = decoded.slice(idx + 1);
  return timingSafeEqual(user, ADMIN_USER) && timingSafeEqual(pass, ADMIN_PASS);
}

function demandAuth(res) {
  res.writeHead(401, {
    'WWW-Authenticate': 'Basic realm="CX Algorithm Admin", charset="UTF-8"',
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Authentication required.');
}

function readBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limitBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJSON(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function serveFile(res, filePath, extraHeaders, req) {
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const headers = Object.assign(
      {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache',
        'Accept-Ranges': 'bytes'
      },
      extraHeaders || {}
    );

    // Byte-range support so <audio>/<video> can seek
    const range = req && req.headers.range && /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
    if (range && (range[1] !== '' || range[2] !== '')) {
      let start, end;
      if (range[1] === '') { // suffix: last N bytes
        start = Math.max(0, st.size - parseInt(range[2], 10));
        end = st.size - 1;
      } else {
        start = parseInt(range[1], 10);
        end = range[2] === '' ? st.size - 1 : Math.min(parseInt(range[2], 10), st.size - 1);
      }
      if (start <= end && start < st.size) {
        res.writeHead(206, Object.assign({}, headers, {
          'Content-Range': `bytes ${start}-${end}/${st.size}`,
          'Content-Length': end - start + 1
        }));
        fs.createReadStream(filePath, { start, end }).pipe(res);
        return;
      }
      res.writeHead(416, { 'Content-Range': `bytes */${st.size}` });
      return res.end();
    }

    res.writeHead(200, Object.assign({}, headers, { 'Content-Length': st.size }));
    fs.createReadStream(filePath).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  let pathname = decodeURIComponent(url.pathname);

  // --- Hidden admin page (never linked from the site, auth required) ---
  if (pathname === '/admin' || pathname === '/admin/') {
    if (!isAuthed(req)) return demandAuth(res);
    return serveFile(res, path.join(ROOT, 'admin.html'), { 'X-Robots-Tag': 'noindex, nofollow' }, req);
  }
  // Block direct access to the admin file itself
  if (pathname === '/admin.html') {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  }

  // --- Admin APIs ---
  // Local-dev twin of the Vercel function: GET /api/content serves the content file,
  // so pages use the same path locally and in production.
  if (pathname === '/api/content' && req.method === 'GET') {
    return serveFile(res, path.join(ROOT, 'content.json'), null, req);
  }

  if (pathname === '/api/content' && req.method === 'POST') {
    if (!isAuthed(req)) return demandAuth(res);
    try {
      const body = await readBody(req, 2 * 1024 * 1024);
      const content = JSON.parse(body.toString('utf-8'));
      if (typeof content !== 'object' || content === null || Array.isArray(content)) {
        return sendJSON(res, 400, { error: 'Content must be a JSON object' });
      }
      fs.writeFileSync(path.join(ROOT, 'content.json'), JSON.stringify(content, null, 2), 'utf-8');
      return sendJSON(res, 200, { ok: true });
    } catch (e) {
      return sendJSON(res, 400, { error: 'Invalid JSON: ' + e.message });
    }
  }

  // Public contact-form submissions → messages.json (viewed in the admin's Messages tab)
  if (pathname === '/api/contact' && req.method === 'POST') {
    const ip = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const hits = (contactHits.get(ip) || []).filter(t => now - t < 60_000);
    if (hits.length >= 5) return sendJSON(res, 429, { error: 'Too many messages. Please wait a minute and try again.' });
    hits.push(now);
    contactHits.set(ip, hits);
    try {
      const body = await readBody(req, 32 * 1024);
      const { intent, fields, message } = JSON.parse(body.toString('utf-8'));
      if (typeof intent !== 'string' || intent.length > 32) return sendJSON(res, 400, { error: 'Invalid intent' });
      if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) return sendJSON(res, 400, { error: 'Invalid fields' });
      const cleanFields = {};
      let any = false;
      for (const [k, v] of Object.entries(fields).slice(0, 20)) {
        if (typeof v !== 'string') continue;
        cleanFields[String(k).slice(0, 80)] = v.slice(0, 500);
        if (v.trim()) any = true;
      }
      const cleanMessage = typeof message === 'string' ? message.slice(0, 5000) : '';
      if (!any && !cleanMessage.trim()) return sendJSON(res, 400, { error: 'Empty message' });
      const list = readMessages();
      list.push({
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
        receivedAt: new Date().toISOString(),
        intent: intent,
        fields: cleanFields,
        message: cleanMessage
      });
      writeMessages(list);
      return sendJSON(res, 200, { ok: true });
    } catch (e) {
      return sendJSON(res, 400, { error: 'Invalid submission' });
    }
  }

  // Admin: read + delete contact messages
  if (pathname === '/api/messages' && req.method === 'GET') {
    if (!isAuthed(req)) return demandAuth(res);
    return sendJSON(res, 200, { ok: true, messages: readMessages().slice().reverse() });
  }
  if (pathname === '/api/messages/delete' && req.method === 'POST') {
    if (!isAuthed(req)) return demandAuth(res);
    try {
      const body = await readBody(req, 4 * 1024);
      const { id } = JSON.parse(body.toString('utf-8'));
      const list = readMessages();
      const next = list.filter(m => m.id !== id);
      writeMessages(next);
      return sendJSON(res, 200, { ok: true, removed: list.length - next.length });
    } catch (e) {
      return sendJSON(res, 400, { error: e.message });
    }
  }

  // Streaming media upload (audio/video) — raw body, not base64, so large files work
  if (pathname === '/api/upload-media' && req.method === 'POST') {
    if (!isAuthed(req)) return demandAuth(res);
    const rawName = url.searchParams.get('name') || 'media';
    const ext = path.extname(rawName).toLowerCase();
    if (!MEDIA_EXT.has(ext)) {
      return sendJSON(res, 400, { error: 'Allowed media types: ' + [...MEDIA_EXT].join(', ') });
    }
    const safeBase = rawName
      .replace(/\.[^.]*$/, '')
      .replace(/[^a-zA-Z0-9_-]+/g, '-')
      .slice(0, 60) || 'media';
    const fileName = Date.now() + '-' + safeBase + ext;
    fs.mkdirSync(MEDIA_DIR, { recursive: true });
    const dest = path.join(MEDIA_DIR, fileName);
    const out = fs.createWriteStream(dest);
    let size = 0;
    let failed = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MEDIA_MAX_BYTES && !failed) {
        failed = true;
        out.destroy();
        fs.unlink(dest, () => {});
        sendJSON(res, 413, { error: 'File too large (max 1 GB)' });
        req.destroy();
      }
    });
    req.pipe(out);
    out.on('finish', () => {
      if (!failed) sendJSON(res, 200, { ok: true, path: 'assets/media/' + fileName, bytes: size });
    });
    out.on('error', (e) => {
      if (!failed) { failed = true; fs.unlink(dest, () => {}); sendJSON(res, 500, { error: e.message }); }
    });
    return;
  }

  if (pathname === '/api/upload' && req.method === 'POST') {
    if (!isAuthed(req)) return demandAuth(res);
    try {
      const body = await readBody(req, 10 * 1024 * 1024);
      const { name, data } = JSON.parse(body.toString('utf-8'));
      const match = /^data:(image\/(png|jpeg|webp|gif));base64,(.+)$/.exec(data || '');
      if (!match) return sendJSON(res, 400, { error: 'Only PNG, JPEG, WEBP or GIF images are allowed' });
      const ext = { 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp', 'image/gif': '.gif' }[match[1]];
      const safeBase = String(name || 'image')
        .replace(/\.[^.]*$/, '')
        .replace(/[^a-zA-Z0-9_-]+/g, '-')
        .slice(0, 60) || 'image';
      const fileName = Date.now() + '-' + safeBase + ext;
      fs.mkdirSync(UPLOAD_DIR, { recursive: true });
      fs.writeFileSync(path.join(UPLOAD_DIR, fileName), Buffer.from(match[3], 'base64'));
      return sendJSON(res, 200, { ok: true, path: 'assets/uploads/' + fileName });
    } catch (e) {
      return sendJSON(res, 400, { error: e.message });
    }
  }

  // --- Static site ---
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Method not allowed');
  }
  if (pathname === '/') pathname = '/index.html';

  const filePath = path.normalize(path.join(ROOT, pathname));
  if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Forbidden');
  }
  // Never expose the server source, its password, or private contact submissions
  const base = path.basename(filePath);
  if (base === 'server.js' || base === 'messages.json') {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Not found');
  }
  serveFile(res, filePath, null, req);
});

server.listen(PORT, () => {
  console.log(`The CX Algorithm site running at http://localhost:${PORT}`);
  console.log(`Admin panel (password protected): http://localhost:${PORT}/admin`);
});
