const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3001;
const DIST = path.join(__dirname, 'dist');
const DATA_DIR = path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ============================================================
//  User management — env var (survives deploys) + in-memory for new registrations
// ============================================================
// USERS_JSON env var format: {"username":{"hash":"sha256hex","created":timestamp}, ...}
let users = {};
try {
  if (process.env.USERS_JSON) {
    users = JSON.parse(process.env.USERS_JSON);
    console.log(`[AUTH] Loaded ${Object.keys(users).length} users from USERS_JSON env var`);
  }
} catch (e) {
  console.error('[AUTH] Failed to parse USERS_JSON:', e.message);
}

// Also try local file as fallback (for local dev)
const USERS_FILE = path.join(DATA_DIR, 'users.json');
try {
  if (fs.existsSync(USERS_FILE)) {
    const fileUsers = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    // Merge: env var takes precedence, but add any file-only users
    for (const [k, v] of Object.entries(fileUsers)) {
      if (!users[k]) users[k] = v;
    }
    console.log(`[AUTH] Merged users from file. Total: ${Object.keys(users).length}`);
  }
} catch (e) {}

function saveUsersToFile() {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); } catch(e) {}
}
function hashPassword(p) { return crypto.createHash('sha256').update(p).digest('hex'); }

// ============================================================
//  Sessions
// ============================================================
const sessions = {};
const SESSION_EXPIRY = 7 * 24 * 60 * 60 * 1000;

function createSession(username) {
  const t = crypto.randomBytes(32).toString('hex');
  sessions[t] = { username, created: Date.now() };
  return t;
}

function getSession(token) {
  const s = sessions[token];
  if (!s) return null;
  if (Date.now() - s.created > SESSION_EXPIRY) { delete sessions[token]; return null; }
  return s;
}

function getSessionFromReq(req) {
  const cookies = (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, ...v] = c.trim().split('=');
    if (k) acc[k] = v.join('=');
    return acc;
  }, {});
  return cookies.session ? getSession(cookies.session) : null;
}

function userDbPath(username) {
  // Sanitize username to prevent path traversal
  const safe = username.replace(/[^a-zA-Z0-9_]/g, '');
  return path.join(DATA_DIR, safe + '.db');
}

const MIME = {
  '.html':'text/html', '.js':'application/javascript', '.css':'text/css',
  '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png',
  '.ico':'image/x-icon', '.wasm':'application/wasm',
};

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];

  // --- Register ---
  if (url === '/api/register' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(Buffer.concat(chunks).toString());
        if (!username || !password) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false, error: 'Username and password required' }));
        }
        if (username.length < 2 || password.length < 4) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false, error: 'Username (2+) or password (4+) too short' }));
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false, error: 'Username: letters, numbers, underscore only' }));
        }
        if (users[username]) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false, error: 'Username already taken' }));
        }
        users[username] = { hash: hashPassword(password), created: Date.now() };
        saveUsersToFile();
        const token = createSession(username);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_EXPIRY / 1000}`,
        });
        res.end(JSON.stringify({ ok: true, username }));
        // Log the USERS_JSON value so admin can update env var
        console.log(`[AUTH] New user registered: ${username}`);
        console.log(`[AUTH] Current USERS_JSON (update env var to persist):`);
        console.log(JSON.stringify(users));
      } catch (e) {
        res.writeHead(400);
        res.end('Bad request');
      }
    });
    return;
  }

  // --- Login ---
  if (url === '/api/login' && req.method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(Buffer.concat(chunks).toString());
        if (users[username] && users[username].hash === hashPassword(password)) {
          const token = createSession(username);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_EXPIRY / 1000}`,
          });
          res.end(JSON.stringify({ ok: true, username }));
          console.log(`[AUTH] ${username} logged in`);
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Wrong username or password' }));
        }
      } catch (e) {
        res.writeHead(400);
        res.end('Bad request');
      }
    });
    return;
  }

  // --- Logout ---
  if (url === '/api/logout') {
    res.writeHead(302, {
      'Set-Cookie': 'session=; Path=/; HttpOnly; Max-Age=0',
      Location: '/login',
    });
    res.end();
    return;
  }

  // --- Auth check ---
  if (url === '/api/me') {
    const session = getSessionFromReq(req);
    if (session) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, username: session.username }));
    } else {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false }));
    }
    return;
  }

  // --- Sync DB (per user) ---
  if (url === '/api/sync-db') {
    const session = getSessionFromReq(req);
    if (!session) {
      res.writeHead(401);
      return res.end('Unauthorized');
    }
    const dbFile = userDbPath(session.username);

    if (req.method === 'GET') {
      if (fs.existsSync(dbFile)) {
        const data = fs.readFileSync(dbFile);
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': data.length,
        });
        res.end(data);
      } else {
        res.writeHead(204);
        res.end();
      }
      return;
    }

    if (req.method === 'POST') {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        const buf = Buffer.concat(chunks);
        if (buf.length > 0) {
          fs.writeFileSync(dbFile, buf);
          console.log(`[SYNC] ${session.username}: saved ${buf.length} bytes`);
        }
        res.writeHead(200);
        res.end('OK');
      });
      return;
    }
  }

  // --- Public routes ---
  const publicPaths = ['/login', '/register', '/sw.js', '/manifest.json', '/favicon.svg', '/icons/', '/sql-wasm.wasm'];
  const isPublic = publicPaths.some(p => url === p || url.startsWith(p));

  if (!isPublic && !url.startsWith('/api/')) {
    const session = getSessionFromReq(req);
    if (!session) {
      res.writeHead(302, { Location: '/login' });
      return res.end();
    }
  }

  // --- Login / Register page ---
  if (url === '/login' || url === '/register') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(LOGIN_HTML);
  }

  // --- Static files ---
  let filePath = url === '/' ? '/index.html' : url;
  filePath = path.join(DIST, filePath);
  const ext = path.extname(filePath);
  const ct = MIME[ext] || 'application/octet-stream';

  try {
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      res.writeHead(200, { 'Content-Type': ct });
      res.end(fs.readFileSync(filePath));
    } else {
      const idx = path.join(DIST, 'index.html');
      if (fs.existsSync(idx)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(fs.readFileSync(idx));
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    }
  } catch (e) {
    res.writeHead(500);
    res.end('Error');
  }
});

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>HomeExpenses</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a 0%,#1e293b 50%,#334155 100%);color:#e2e8f0}
.card{background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);border:1px solid rgba(99,102,241,0.3);border-radius:24px;padding:48px 36px;width:90%;max-width:400px;text-align:center}
.card h1{font-size:2rem;margin-bottom:8px}.subtitle{color:#94a3b8;margin-bottom:28px;font-size:0.95rem}.logo{font-size:3rem;margin-bottom:16px}
.tabs{display:flex;margin-bottom:24px;border-radius:12px;overflow:hidden;border:1px solid rgba(99,102,241,0.3)}
.tab{flex:1;padding:10px;cursor:pointer;background:transparent;color:#94a3b8;border:none;font-size:0.95rem;font-weight:500;transition:0.2s}
.tab.active{background:rgba(99,102,241,0.2);color:#e2e8f0}
.field{margin-bottom:18px;text-align:left}.field label{display:block;margin-bottom:6px;color:#94a3b8;font-size:0.9rem}
.field input{width:100%;padding:12px 16px;border-radius:12px;border:1px solid rgba(99,102,241,0.3);background:rgba(15,23,42,0.6);color:#e2e8f0;font-size:1rem}
.field input:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,0.2)}
.btn{width:100%;padding:14px;border:none;border-radius:12px;font-size:1.1rem;font-weight:600;cursor:pointer;margin-top:8px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;transition:0.2s}
.btn:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(99,102,241,0.4)}
.error{color:#f87171;margin-top:12px;font-size:0.9rem;min-height:20px}
</style></head><body>
<div class="card"><div class="logo">&#x1F3E0;</div><h1>HomeExpenses</h1><p class="subtitle">Monthly expenses management</p>
<div class="tabs"><button class="tab active" id="tab-login" onclick="showTab('login')">Login</button><button class="tab" id="tab-register" onclick="showTab('register')">Register</button></div>
<form id="form-login" onsubmit="return doLogin(event)">
<div class="field"><label>Username</label><input id="lu" type="text" autocomplete="username" required></div>
<div class="field"><label>Password</label><input id="lp" type="password" autocomplete="current-password" required></div>
<button type="submit" class="btn">Login</button><div class="error" id="le"></div></form>
<form id="form-register" style="display:none" onsubmit="return doRegister(event)">
<div class="field"><label>Username (English)</label><input id="ru" type="text" autocomplete="username" pattern="[a-zA-Z0-9_]+" required minlength="2"></div>
<div class="field"><label>Password</label><input id="rp" type="password" autocomplete="new-password" required minlength="4"></div>
<div class="field"><label>Confirm Password</label><input id="rp2" type="password" autocomplete="new-password" required minlength="4"></div>
<button type="submit" class="btn">Register</button><div class="error" id="re"></div></form></div>
<script>
function showTab(t){document.getElementById('form-login').style.display=t==='login'?'':'none';document.getElementById('form-register').style.display=t==='register'?'':'none';document.getElementById('tab-login').className='tab'+(t==='login'?' active':'');document.getElementById('tab-register').className='tab'+(t==='register'?' active':'');}
if(location.pathname==='/register')showTab('register');
async function doLogin(e){e.preventDefault();var el=document.getElementById('le');el.textContent='';try{var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('lu').value.trim(),password:document.getElementById('lp').value})});var d=await r.json();if(d.ok)window.location.href='/';else el.textContent=d.error||'Error';}catch(x){el.textContent='Connection error';}return false;}
async function doRegister(e){e.preventDefault();var el=document.getElementById('re');el.textContent='';var p1=document.getElementById('rp').value,p2=document.getElementById('rp2').value;if(p1!==p2){el.textContent='Passwords do not match';return false;}try{var r=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('ru').value.trim(),password:p1})});var d=await r.json();if(d.ok)window.location.href='/';else el.textContent=d.error||'Error';}catch(x){el.textContent='Connection error';}return false;}
</script></body></html>`;

server.listen(PORT, () => console.log('HomeExpenses on http://localhost:' + PORT));
