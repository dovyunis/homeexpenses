import initSqlJs from 'sql.js';

let DB_NAME = 'homeExpensesDB';
const DB_STORE = 'sqliteDb';
let currentUsername = null;

let db = null;

export function getDb() {
  return db;
}

// ============================================================
//  IndexedDB persistence
// ============================================================
function openIDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (e) => e.target.result.createObjectStore(DB_STORE);
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = () => reject(req.error);
  });
}

// Save DB locally to IndexedDB only (no server push)
async function saveDbLocal() {
  if (!db) return;
  const data = db.export();
  const buffer = new Uint8Array(data);
  const idb = await openIDB();
  await new Promise((resolve, reject) => {
    const tx = idb.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).put(buffer, 'db');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveDb() {
  if (!db) return;
  const data = db.export();
  const buffer = new Uint8Array(data);
  const idb = await openIDB();
  await new Promise((resolve, reject) => {
    const tx = idb.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).put(buffer, 'db');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });

  // Also push a copy to the server so other devices can sync
  try {
    const blob = new Blob([buffer], { type: 'application/octet-stream' });
    const res = await fetch('/api/sync-db', {
      method: 'POST',
      body: blob,
    });
    if (res.status === 401) window.location.href = '/login';
  } catch (e) {
    // Server sync is optional — ignore errors
  }
}

async function loadDb() {
  const idb = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = idb.transaction(DB_STORE, 'readonly');
    const req = tx.objectStore(DB_STORE).get('db');
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

// Try to fetch the shared DB from the server (synced from desktop)
async function loadSharedDb() {
  try {
    const res = await fetch('/api/sync-db', { cache: 'no-store', credentials: 'same-origin' });
    if (res.status === 401) { window.location.href = '/login'; return null; }
    if (res.ok) {
      const buf = await res.arrayBuffer();
      if (buf.byteLength > 0) return new Uint8Array(buf);
    }
    console.warn('[loadSharedDb] status:', res.status, 'size:', 0);
  } catch (e) {
    console.error('[loadSharedDb] error:', e);
  }
  return null;
}

// Pull the latest DB from the server and replace local data
export async function syncFromServer() {
  const shared = await loadSharedDb();
  if (!shared) return false;

  const SQL = await initSqlJs({
    locateFile: () => '/sql-wasm.wasm',
  });
  db = new SQL.Database(shared);
  initSchema();

  // Round half values

  const months = (db.exec("SELECT id FROM months")[0]?.values || []);
  for (const [monthId] of months) {
    recalcMonthTotals(monthId);
  }

  // Save locally only — don't push back to server
  await saveDbLocal();
  return true;
}

export async function deleteDb() {
  if (db) {
    db.run("DELETE FROM variable_expenses");
    db.run("DELETE FROM fixed_expenses");
    db.run("DELETE FROM income");
    db.run("DELETE FROM months");
  }
  const idb = await openIDB();
  return new Promise((resolve, reject) => {
    const tx = idb.transaction(DB_STORE, 'readwrite');
    tx.objectStore(DB_STORE).delete('db');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ============================================================
//  Schema
// ============================================================
function initSchema() {
  db.run(`CREATE TABLE IF NOT EXISTS months (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    total_income REAL DEFAULT 0,
    total_expenses REAL DEFAULT 0,
    remaining REAL DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS income (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    amount REAL DEFAULT 0,
    FOREIGN KEY (month_id) REFERENCES months(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS fixed_expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    amount REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    FOREIGN KEY (month_id) REFERENCES months(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS variable_expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    amount REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    FOREIGN KEY (month_id) REFERENCES months(id) ON DELETE CASCADE
  )`);
}

// ============================================================
//  Init
// ============================================================
export async function initDatabase(username) {
  // Scope IndexedDB per user so different users don't see each other's data
  if (username) {
    currentUsername = username;
    DB_NAME = 'homeExpenses_' + username;
  }

  const SQL = await initSqlJs({
    locateFile: () => '/sql-wasm.wasm',
  });

  // Try server first (authoritative per-user DB)
  let serverData = await loadSharedDb();

  if (serverData && serverData.byteLength > 0) {
    // Server has data for this user — use it
    db = new SQL.Database(serverData);
    initSchema();
  } else {
    // No server data — try local IndexedDB
    let saved = await loadDb();
    if (saved) {
      db = new SQL.Database(saved);
      initSchema();
    } else {
      // Brand new user — empty DB
      db = new SQL.Database();
      initSchema();
    }
  }

  // Recalc all month totals
  const months = (db.exec("SELECT id FROM months")[0]?.values || []);
  for (const [monthId] of months) {
    recalcMonthTotals(monthId);
  }

  // Save locally
  await saveDbLocal();
  return db;
}

// ============================================================
//  Queries
// ============================================================
export function getMonths() {
  if (!db) return [];
  return (db.exec("SELECT id, name FROM months ORDER BY id")[0]?.values || [])
    .map(([id, name]) => ({ id, name }));
}

export function getMonthData(monthName) {
  if (!db) return null;
  const row = db.exec("SELECT id, total_income, total_expenses, remaining FROM months WHERE name = ?", [monthName]);
  if (!row[0]) return null;
  const [monthId, totalIncome, totalExpenses, remaining] = row[0].values[0];

  const mapRows = (sql) =>
    (db.exec(sql, [monthId])[0]?.values || []);

  const income = mapRows("SELECT id, name, amount FROM income WHERE month_id = ? ORDER BY id")
    .map(r => ({ id: r[0], name: r[1], amount: r[2] }));
  const fixedExpenses = mapRows("SELECT id, name, amount, notes FROM fixed_expenses WHERE month_id = ? ORDER BY id")
    .map(r => ({ id: r[0], name: r[1], amount: r[2], notes: r[3] }));
  const variableExpenses = mapRows("SELECT id, name, amount, notes FROM variable_expenses WHERE month_id = ? ORDER BY id")
    .map(r => ({ id: r[0], name: r[1], amount: r[2], notes: r[3] }));

  return { monthId, monthName, totalIncome, totalExpenses, remaining, income, fixedExpenses, variableExpenses };
}

export function getAllMonthsSummary() {
  if (!db) return [];
  return (db.exec("SELECT name, total_income, total_expenses, remaining FROM months ORDER BY id")[0]?.values || [])
    .map(r => ({ name: r[0], totalIncome: r[1], totalExpenses: r[2], remaining: r[3] }));
}

export function updateCell(table, id, column, value) {
  if (!db) return;
  db.run(`UPDATE ${table} SET ${column} = ? WHERE id = ?`, [value, id]);
}

export function recalcMonthTotals(monthId) {
  if (!db) return;


  const incomeTotal = db.exec("SELECT COALESCE(SUM(amount),0) FROM income WHERE month_id = ?", [monthId])[0].values[0][0];
  const fixed = db.exec("SELECT COALESCE(SUM(amount),0) FROM fixed_expenses WHERE month_id = ?", [monthId])[0].values[0][0];
  const variable = db.exec("SELECT COALESCE(SUM(amount),0) FROM variable_expenses WHERE month_id = ?", [monthId])[0].values[0][0];
  const totalExpenses = fixed + variable;
  const remaining = incomeTotal - totalExpenses;
  db.run("UPDATE months SET total_income = ?, total_expenses = ?, remaining = ? WHERE id = ?", [incomeTotal, totalExpenses, remaining, monthId]);
}

export function hasData() {
  if (!db) return false;
  const res = db.exec("SELECT COUNT(*) FROM months");
  return res[0]?.values[0][0] > 0;
}

export function insertRow(table, monthId, data) {
  if (!db) return null;
  const cols = Object.keys(data);
  const vals = Object.values(data);
  const placeholders = cols.map(() => '?').join(',');
  db.run(
    `INSERT INTO ${table} (month_id, ${cols.join(',')}) VALUES (?, ${placeholders})`,
    [monthId, ...vals]
  );
  const res = db.exec("SELECT last_insert_rowid()");
  return res[0]?.values[0][0] || null;
}

export function deleteRow(table, id) {
  if (!db) return;
  db.run(`DELETE FROM ${table} WHERE id = ?`, [id]);
}

export function addMonth(name) {
  if (!db) return null;
  db.run("INSERT INTO months (name) VALUES (?)", [name]);
  const res = db.exec("SELECT last_insert_rowid()");
  return res[0]?.values[0][0] || null;
}

export function deleteMonth(monthId) {
  if (!db) return;
  db.run("PRAGMA foreign_keys = ON");
  db.run("DELETE FROM income WHERE month_id = ?", [monthId]);
  db.run("DELETE FROM fixed_expenses WHERE month_id = ?", [monthId]);
  db.run("DELETE FROM variable_expenses WHERE month_id = ?", [monthId]);
  db.run("DELETE FROM months WHERE id = ?", [monthId]);
}

export function duplicateMonth(sourceMonthId, newMonthName) {
  if (!db) return null;
  // Create the new month
  db.run("INSERT INTO months (name) VALUES (?)", [newMonthName]);
  const newId = db.exec("SELECT last_insert_rowid()")[0]?.values[0][0];
  if (!newId) return null;

  // Copy all rows from each table (structure only, amounts zeroed)
  const tables = [
    { name: 'income', cols: 'name, amount' },
    { name: 'fixed_expenses', cols: 'name, amount, notes' },
    { name: 'variable_expenses', cols: 'name, amount, notes' },

  ];

  for (const t of tables) {
    db.run(
      `INSERT INTO ${t.name} (month_id, ${t.cols}) SELECT ?, ${t.cols} FROM ${t.name} WHERE month_id = ?`,
      [newId, sourceMonthId]
    );
  }

  recalcMonthTotals(newId);
  return newId;
}
