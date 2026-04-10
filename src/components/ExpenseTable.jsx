import { useState, useMemo } from 'react';
import EditableCell from './EditableCell';
import { fmt } from '../utils';
import './ExpenseTable.css';

export default function ExpenseTable({ title, icon, columns, rows, tableName, monthId, onCellSave, onAddRow, onDeleteRows }) {
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());

  const filtered = useMemo(() => {
    if (!search.trim()) return rows;
    const q = search.trim().toLowerCase();
    return rows.filter((r) =>
      columns.some((c) => {
        const val = r[c.key];
        return val != null && String(val).toLowerCase().includes(q);
      })
    );
  }, [rows, search, columns]);

  const toggleSelect = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === filtered.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filtered.map((r) => r.id)));
    }
  };

  const handleDelete = () => {
    if (selected.size === 0) return;
    onDeleteRows([...selected]);
    setSelected(new Set());
  };

  const handleAdd = () => {
    const defaults = {};
    columns.forEach((c) => {
      if (c.key === 'name') defaults[c.key] = 'חדש';
      else if (c.key === 'notes') defaults[c.key] = '';
      else defaults[c.key] = 0;
    });
    onAddRow(tableName, monthId, defaults);
  };

  const total = rows.reduce((s, r) => {
    const amountCol = columns.find((c) => c.key === 'amount');
    const halfCol = columns.find((c) => c.key === 'half');
    if (halfCol) return s + (r.half || 0);
    if (amountCol) return s + (r.amount || 0);
    return s;
  }, 0);

  // Calculate sums for each numeric column
  const colSums = {};
  columns.forEach((c) => {
    if (c.type === 'number') {
      colSums[c.key] = rows.reduce((s, r) => s + (Number(r[c.key]) || 0), 0);
    }
  });

  return (
    <div className="table-section">
      <div className="table-toolbar">
        <span className="table-title">
          <span>{icon}</span> {title}
          <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-muted)' }}>
            ({rows.length} פריטים · סה״כ {fmt(total)})
          </span>
        </span>
        <div className="table-actions">
          <input
            className="search-input"
            placeholder="🔍 חיפוש..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button className="btn-icon" onClick={handleAdd} title="הוסף שורה">➕ הוסף</button>
          {selected.size > 0 && (
            <button className="btn-icon danger" onClick={handleDelete} title="מחק נבחרים">
              🗑️ מחק ({selected.size})
            </button>
          )}
        </div>
      </div>

      <div className="expense-table-wrapper">
        <table className="expense-table">
          <thead>
            <tr>
              <th style={{ width: 40 }}>
                <input
                  type="checkbox"
                  className="row-select"
                  checked={filtered.length > 0 && selected.size === filtered.length}
                  onChange={toggleAll}
                />
              </th>
              {columns.map((c) => (
                <th key={c.key}>{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={columns.length + 1} className="table-empty">
                  {search ? 'אין תוצאות לחיפוש' : 'אין נתונים'}
                </td>
              </tr>
            ) : (
              filtered.map((row) => (
                <tr key={row.id}>
                  <td>
                    <input
                      type="checkbox"
                      className="row-select"
                      checked={selected.has(row.id)}
                      onChange={() => toggleSelect(row.id)}
                    />
                  </td>
                  {columns.map((c) => (
                    <td key={c.key}>
                      <EditableCell
                        value={row[c.key]}
                        isNumber={c.type === 'number'}
                        formatter={c.type === 'number' ? fmt : undefined}
                        onSave={(val) => onCellSave(tableName, row.id, c.key, val)}
                      />
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
          <tfoot>
            <tr className="table-sum-row">
              <td></td>
              {columns.map((c) => (
                <td key={c.key}>
                  {c.type === 'number' ? (
                    <span className="sum-value">{fmt(colSums[c.key])}</span>
                  ) : c.key === 'name' ? (
                    <span className="sum-label">סה״כ</span>
                  ) : null}
                </td>
              ))}
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  );
}
