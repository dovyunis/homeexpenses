const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const DIST = path.join(__dirname, 'dist');
const DB_FILE = path.join(__dirname, 'shared-db.bin');

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.wasm': 'application/wasm',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
};

const server = http.createServer((req, res) => {
  // CORS headers for local network
  res.setHeader('Access-Control-Allow-Origin', '*');

  // API: sync database
  if (req.url === '/api/sync-db') {
    if (req.method === 'POST') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const buf = Buffer.concat(chunks);
        fs.writeFileSync(DB_FILE, buf);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
        console.log(`[SYNC] DB saved (${(buf.length / 1024).toFixed(1)} KB)`);
      });
      return;
    }
    if (req.method === 'GET') {
      if (fs.existsSync(DB_FILE)) {
        const data = fs.readFileSync(DB_FILE);
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Cache-Control': 'no-store',
        });
        res.end(data);
      } else {
        res.writeHead(404);
        res.end('No shared DB');
      }
      return;
    }
  }

  // Static file serving
  let filePath = path.join(DIST, req.url === '/' ? 'index.html' : req.url);

  // SPA fallback: if file doesn't exist, serve index.html
  if (!fs.existsSync(filePath)) {
    filePath = path.join(DIST, 'index.html');
  }

  const ext = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';

  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  } catch (e) {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Home Expenses server running on http://0.0.0.0:${PORT}`);
  console.log(`   Local:   http://localhost:${PORT}`);
  // Get local IP
  const nets = require('os').networkInterfaces();
  for (const iface of Object.values(nets)) {
    for (const addr of iface) {
      if (addr.family === 'IPv4' && !addr.internal) {
        console.log(`   Network: http://${addr.address}:${PORT}`);
      }
    }
  }
});
