import * as XLSX from 'xlsx';
import { getDb } from './db';

// ============================================================
//  Excel → SQLite Import
// ============================================================
function cellVal(ws, col, row) {
  const cell = ws[XLSX.utils.encode_cell({ c: col, r: row - 1 })];
  return cell ? cell.v : null;
}

function findRow(ws, col, text, startRow, endRow) {
  for (let r = startRow; r <= endRow; r++) {
    const v = cellVal(ws, col, r);
    if (v && String(v).trim() === text) return r;
  }
  return null;
}

export function importExcelToDb(_, fileData) {
  const db = getDb();
  const workbook = XLSX.read(fileData, { type: 'binary' });
  let importedCount = 0;

  workbook.SheetNames.forEach((name) => {
    try {
      if (importSheet(db, workbook.Sheets[name], name)) importedCount++;
    } catch (e) {
      console.warn(`Error in sheet "${name}":`, e);
    }
  });

  return importedCount;
}

function importSheet(db, ws, sheetName) {
  const range = XLSX.utils.decode_range(ws['!ref'] || 'A1');
  const maxRow = range.e.r + 1;

  const totalIncome = cellVal(ws, 2, 6);
  const totalExpenses = cellVal(ws, 2, 7);
  const remaining = cellVal(ws, 2, 8);
  if (totalIncome == null && totalExpenses == null) return false;

  db.run("INSERT OR REPLACE INTO months (name, total_income, total_expenses, remaining) VALUES (?, ?, ?, ?)",
    [sheetName, parseFloat(totalIncome) || 0, parseFloat(totalExpenses) || 0, parseFloat(remaining) || 0]);
  const monthId = db.exec("SELECT id FROM months WHERE name = ?", [sheetName])[0].values[0][0];

  ['income', 'fixed_expenses', 'variable_expenses', 'dov_expenses', 'talia_expenses'].forEach(t => {
    db.run(`DELETE FROM ${t} WHERE month_id = ?`, [monthId]);
  });

  // Income
  for (let r = 3; r <= 5; r++) {
    const name = cellVal(ws, 1, r), amount = cellVal(ws, 2, r);
    if (name && amount) db.run("INSERT INTO income (month_id, name, amount) VALUES (?,?,?)", [monthId, name, parseFloat(amount) || 0]);
  }

  // Fixed expenses
  const fixedTotalRow = findRow(ws, 1, 'סה"כ הוצאות קבועות', 10, Math.min(40, maxRow));
  const fixedEnd = fixedTotalRow ? fixedTotalRow - 1 : 25;
  for (let r = 11; r <= fixedEnd; r++) {
    const name = cellVal(ws, 1, r), amount = cellVal(ws, 2, r), notes = cellVal(ws, 3, r) || '';
    if (name && amount != null)
      db.run("INSERT INTO fixed_expenses (month_id, name, amount, notes) VALUES (?,?,?,?)", [monthId, name, parseFloat(amount) || 0, notes]);
  }

  // Variable expenses
  const varHeaderRow = findRow(ws, 1, 'הוצאות משתנות', 20, Math.min(50, maxRow));
  const varStart = varHeaderRow ? varHeaderRow + 1 : 29;
  const varTotalRow = findRow(ws, 1, 'סה"כ הוצאות משתנות', varStart, Math.min(varStart + 15, maxRow));
  const varEnd = varTotalRow ? varTotalRow - 1 : varStart + 5;
  for (let r = varStart; r <= varEnd; r++) {
    const name = cellVal(ws, 1, r), amount = cellVal(ws, 2, r), notes = cellVal(ws, 3, r) || '';
    if (name && amount != null)
      db.run("INSERT INTO variable_expenses (month_id, name, amount, notes) VALUES (?,?,?,?)", [monthId, name, parseFloat(amount) || 0, notes]);
  }

  // Dov expenses
  for (let r = 3; r <= Math.min(50, maxRow); r++) {
    const name = cellVal(ws, 5, r);
    if (!name) continue;
    if (String(name).trim() === 'סה"כ') break;
    const fullAmount = cellVal(ws, 6, r), half = cellVal(ws, 7, r), notes = cellVal(ws, 9, r) || '';
    if (fullAmount != null)
      db.run("INSERT INTO dov_expenses (month_id, name, amount, half, notes) VALUES (?,?,?,?,?)",
        [monthId, name, parseFloat(fullAmount) || 0, parseFloat(half) || 0, notes]);
  }

  // Talia expenses
  let taliaStart = 0;
  for (let r = 10; r <= Math.min(60, maxRow); r++) {
    if (String(cellVal(ws, 5, r) || '').includes('הוצאות - טליה')) { taliaStart = r + 1; break; }
  }
  if (taliaStart) {
    for (let r = taliaStart; r <= Math.min(taliaStart + 40, maxRow); r++) {
      const name = cellVal(ws, 5, r);
      if (!name) continue;
      if (String(name).trim() === 'סה"כ') break;
      const fullAmount = cellVal(ws, 6, r), half = cellVal(ws, 7, r), notes = cellVal(ws, 9, r) || '';
      if (fullAmount != null)
        db.run("INSERT INTO talia_expenses (month_id, name, amount, half, notes) VALUES (?,?,?,?,?)",
          [monthId, name, parseFloat(fullAmount) || 0, parseFloat(half) || 0, notes]);
    }
  }

  return true;
}

// ============================================================
//  SQLite → Excel Export
// ============================================================
export function exportToExcel(getMonths, getMonthData) {
  const wb = XLSX.utils.book_new();
  const months = getMonths();

  months.forEach(({ name }) => {
    const d = getMonthData(name);
    if (!d) return;
    const rows = [];
    rows.push(['סיכום חודש ' + name]);
    rows.push(['הכנסות', d.totalIncome]);
    rows.push(['הוצאות', d.totalExpenses]);
    rows.push(['נשאר', d.remaining]);
    rows.push([]);
    rows.push(['הוצאות קבועות']);
    rows.push(['פריט', 'סכום', 'הערות']);
    d.fixedExpenses.forEach(e => rows.push([e.name, e.amount, e.notes]));
    rows.push([]);
    rows.push(['הוצאות משתנות']);
    rows.push(['פריט', 'סכום', 'הערות']);
    d.variableExpenses.forEach(e => rows.push([e.name, e.amount, e.notes]));
    rows.push([]);
    rows.push(['הוצאות - דב']);
    rows.push(['פריט', 'סכום קנייה', 'מחצית', 'הערות']);
    d.dovExpenses.forEach(e => rows.push([e.name, e.amount, e.half, e.notes]));
    rows.push([]);
    rows.push(['הוצאות - טליה']);
    rows.push(['פריט', 'סכום קנייה', 'מחצית', 'הערות']);
    d.taliaExpenses.forEach(e => rows.push([e.name, e.amount, e.half, e.notes]));

    const ws = XLSX.utils.aoa_to_sheet(rows);
    XLSX.utils.book_append_sheet(wb, ws, name);
  });

  XLSX.writeFile(wb, 'הוצאות_חודשיות_דוח.xlsx');
}
