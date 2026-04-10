import { useState } from 'react';
import { useTheme } from '../ThemeContext';
import './Sidebar.css';

export default function Sidebar({ months, activeMonth, onSelect, sidebarOpen, onToggle, onAddMonth, onDeleteMonth }) {
  const { dark, toggle } = useTheme();
  const [showAddModal, setShowAddModal] = useState(false);
  const [newMonthName, setNewMonthName] = useState('');
  const [copyFrom, setCopyFrom] = useState('');

  const handleAdd = () => {
    const name = newMonthName.trim();
    if (!name) return;
    if (months.some(m => m.name === name)) {
      alert('חודש עם שם זה כבר קיים');
      return;
    }
    onAddMonth(name, copyFrom || null);
    setNewMonthName('');
    setCopyFrom('');
    setShowAddModal(false);
  };

  return (
    <>
      <button className="hamburger" onClick={onToggle} aria-label="תפריט">
        <span /><span /><span />
      </button>

      {sidebarOpen && <div className="sidebar-overlay" onClick={onToggle} />}

      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <span className="sidebar-logo">📊</span>
          <h2>HomeExpenses</h2>
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-header">
            <h3>חודשים</h3>
            <button
              className="sidebar-add-btn"
              onClick={() => setShowAddModal(true)}
              title="הוסף חודש"
            >
              ➕
            </button>
          </div>
          <ul className="sidebar-months">
            {months.map((m) => (
              <li key={m.id} className="sidebar-month-item">
                <button
                  className={`sidebar-month ${m.name === activeMonth ? 'active' : ''}`}
                  onClick={() => { onSelect(m.name); onToggle(); }}
                >
                  <span className="month-icon">📅</span>
                  {m.name}
                </button>
                <button
                  className="month-delete-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDeleteMonth(m.id, m.name);
                  }}
                  title={`מחק ${m.name}`}
                >
                  ✕
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="sidebar-footer">
          <button className="theme-toggle" onClick={toggle} title={dark ? 'מצב בהיר' : 'מצב כהה'}>
            {dark ? '☀️ מצב בהיר' : '🌙 מצב כהה'}
          </button>
        </div>
      </aside>

      {/* Add Month Modal */}
      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h3>➕ הוסף חודש חדש</h3>
            <div className="modal-field">
              <label>שם החודש</label>
              <input
                type="text"
                value={newMonthName}
                onChange={e => setNewMonthName(e.target.value)}
                placeholder='לדוגמה: ינואר 2026'
                autoFocus
                onKeyDown={e => e.key === 'Enter' && handleAdd()}
              />
            </div>
            <div className="modal-field">
              <label>העתק מבנה מחודש (אופציונלי)</label>
              <select value={copyFrom} onChange={e => setCopyFrom(e.target.value)}>
                <option value="">חודש ריק</option>
                {months.map(m => (
                  <option key={m.id} value={m.name}>{m.name}</option>
                ))}
              </select>
            </div>
            <div className="modal-actions">
              <button className="modal-btn primary" onClick={handleAdd}>הוסף</button>
              <button className="modal-btn" onClick={() => setShowAddModal(false)}>ביטול</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
