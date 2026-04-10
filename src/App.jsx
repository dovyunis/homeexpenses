import { useState, useEffect, useCallback, useRef } from 'react';
import { initDatabase, getMonths, getMonthData, getAllMonthsSummary, updateCell, recalcMonthTotals, saveDb, deleteDb, hasData, insertRow, deleteRow, addMonth, deleteMonth, duplicateMonth, syncFromServer } from './db';
import { importExcelToDb, exportToExcel } from './excel';
import Sidebar from './components/Sidebar';
import SummaryCards from './components/SummaryCards';
import ExpenseTable from './components/ExpenseTable';
import { MonthlyComparisonChart } from './components/Charts';
import Toast from './components/Toast';
import './App.css';

/* Column definitions */
const FIXED_COLS = [
  { key: 'name', label: 'פריט', type: 'text' },
  { key: 'amount', label: 'סכום', type: 'number' },
  { key: 'notes', label: 'הערות', type: 'text' },
];
const PERSON_COLS = [
  { key: 'name', label: 'פריט', type: 'text' },
  { key: 'amount', label: 'סכום קנייה', type: 'number' },
  { key: 'half', label: 'מחצית', type: 'number' },
  { key: 'notes', label: 'הערות', type: 'text' },
];

export default function App() {
  const [loading, setLoading] = useState(true);
  const [months, setMonths] = useState([]);
  const [activeMonth, setActiveMonth] = useState(null);
  const [data, setData] = useState(null);
  const [allMonths, setAllMonths] = useState([]);
  const [prevData, setPrevData] = useState(null);
  const [toasts, setToasts] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const fileInputRef = useRef(null);
  const touchStartX = useRef(null);
  const touchStartY = useRef(null);
  const touchMoveDx = useRef(0);
  const [swipeOffset, setSwipeOffset] = useState(0);
  const [slideClass, setSlideClass] = useState('');

  const toast = useCallback((message, type = 'info') => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  /* Init database */
  useEffect(() => {
    // Fetch current user
    fetch('/api/me').then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setCurrentUser(d.username); })
      .catch(() => {});

    initDatabase().then(() => {
      if (hasData()) {
        refreshMonths();
      }
      setLoading(false);
    }).catch((err) => {
      console.error(err);
      toast('שגיאה בטעינת מסד הנתונים', 'error');
      setLoading(false);
    });
  }, []);

  const refreshMonths = useCallback(() => {
    const m = getMonths();
    setMonths(m);
    setAllMonths(getAllMonthsSummary());
    if (m.length > 0) {
      const current = m[m.length - 1].name;
      setActiveMonth(current);
      loadMonth(current, m);
    }
  }, []);

  const loadMonth = useCallback((name, monthsList) => {
    setActiveMonth(name);
    const d = getMonthData(name);
    setData(d);

    // Get previous month data for trend arrows
    const ml = monthsList || months;
    const idx = ml.findIndex((m) => m.name === name);
    if (idx > 0) {
      const prevName = ml[idx - 1].name;
      const pd = getMonthData(prevName);
      setPrevData(pd ? {
        totalIncome: pd.totalIncome,
        totalExpenses: pd.totalExpenses,
        remaining: pd.remaining,
        taliaHalfSum: (pd.taliaExpenses || []).reduce((s, r) => s + (r.half || 0), 0),
        dovHalfSum: (pd.dovExpenses || []).reduce((s, r) => s + (r.half || 0), 0),
      } : null);
    } else {
      setPrevData(null);
    }
  }, [months]);

  /* Swipe between months on mobile */
  const navigateMonth = useCallback((direction) => {
    if (!activeMonth || months.length <= 1) return false;
    const idx = months.findIndex(m => m.name === activeMonth);
    const newIdx = direction === 'left' ? idx + 1 : idx - 1;
    if (newIdx >= 0 && newIdx < months.length) {
      // Slide animation
      setSlideClass(direction === 'left' ? 'slide-out-left' : 'slide-out-right');
      setTimeout(() => {
        loadMonth(months[newIdx].name);
        setSlideClass(direction === 'left' ? 'slide-in-right' : 'slide-in-left');
        setTimeout(() => setSlideClass(''), 300);
      }, 150);
      return true;
    }
    return false;
  }, [activeMonth, months, loadMonth]);

  const handleTouchStart = useCallback((e) => {
    // Don't capture swipes on scrollable tables
    if (e.target.closest('.expense-table-wrapper')) return;
    touchStartX.current = e.touches[0].clientX;
    touchStartY.current = e.touches[0].clientY;
    touchMoveDx.current = 0;
  }, []);

  const handleTouchMove = useCallback((e) => {
    if (touchStartX.current === null) return;
    const dx = e.touches[0].clientX - touchStartX.current;
    const dy = e.touches[0].clientY - touchStartY.current;
    // If scrolling vertically, cancel swipe
    if (Math.abs(dy) > Math.abs(dx) && Math.abs(dy) > 10) {
      touchStartX.current = null;
      setSwipeOffset(0);
      return;
    }
    touchMoveDx.current = dx;
    // Live drag feedback (capped at ±120px)
    if (Math.abs(dx) > 20) {
      setSwipeOffset(Math.max(-120, Math.min(120, dx * 0.5)));
    }
  }, []);

  const handleTouchEnd = useCallback(() => {
    setSwipeOffset(0);
    if (touchStartX.current === null) return;
    const dx = touchMoveDx.current;
    touchStartX.current = null;
    touchStartY.current = null;
    touchMoveDx.current = 0;
    // Swipe threshold: 80px
    if (Math.abs(dx) > 80) {
      navigateMonth(dx < 0 ? 'left' : 'right');
    }
  }, [navigateMonth]);

  /* File upload */
  const handleFile = useCallback(async (fileData) => {
    setLoading(true);
    try {
      const count = importExcelToDb(null, fileData);
      await saveDb();
      refreshMonths();
      toast(`${count} חודשים יובאו בהצלחה`, 'success');
    } catch (err) {
      console.error(err);
      toast('שגיאה בייבוא הקובץ', 'error');
    }
    setLoading(false);
  }, [refreshMonths, toast]);

  /* Cell editing */
  const handleCellSave = useCallback(async (table, rowId, column, value) => {
    updateCell(table, rowId, column, value);
    if (data?.monthId) {
      // Auto-calc half for person tables when amount changes
      if ((table === 'dov_expenses' || table === 'talia_expenses') && column === 'amount') {
        const halfVal = Math.round(value / 2);
        updateCell(table, rowId, 'half', halfVal);
      }
      recalcMonthTotals(data.monthId);
    }
    await saveDb();
    // Re-fetch data to ensure all computed values (including מזונות) are up to date
    const d = getMonthData(activeMonth);
    setData(d);
    setAllMonths(getAllMonthsSummary());
    toast('נשמר', 'success');
  }, [data, activeMonth, toast]);

  /* Add / Delete rows */
  const handleAddRow = useCallback(async (table, monthId, defaults) => {
    insertRow(table, monthId, defaults);
    recalcMonthTotals(monthId);
    await saveDb();
    loadMonth(activeMonth);
    setAllMonths(getAllMonthsSummary());
    toast('שורה נוספה', 'success');
  }, [activeMonth, loadMonth, toast]);

  const handleDeleteRows = useCallback(async (ids) => {
    // We need the table name — use a closure
    return (tableName) => {
      ids.forEach((id) => deleteRow(tableName, id));
      if (data?.monthId) recalcMonthTotals(data.monthId);
      saveDb().then(() => {
        loadMonth(activeMonth);
        setAllMonths(getAllMonthsSummary());
        toast(`${ids.length} שורות נמחקו`, 'success');
      });
    };
  }, [data, activeMonth, loadMonth, toast]);

  /* Export */
  const handleExport = useCallback(() => {
    exportToExcel(getMonths, getMonthData);
    toast('הקובץ יוצא בהצלחה', 'success');
  }, [toast]);

  /* Reset */
  const handleReset = useCallback(async () => {
    if (!confirm('האם אתה בטוח שברצונך למחוק את כל הנתונים?')) return;
    await deleteDb();
    setMonths([]);
    setActiveMonth(null);
    setData(null);
    setAllMonths([]);
    setPrevData(null);
    toast('הנתונים נמחקו', 'info');
  }, [toast]);

  /* Sync from server */
  const handleSync = useCallback(async () => {
    setLoading(true);
    try {
      const ok = await syncFromServer();
      if (ok) {
        refreshMonths();
        toast('הנתונים סונכרנו בהצלחה', 'success');
      } else {
        toast('אין נתונים בשרת לסנכרון', 'error');
      }
    } catch (err) {
      console.error(err);
      toast('שגיאה בסנכרון', 'error');
    }
    setLoading(false);
  }, [refreshMonths, toast]);

  /* Logout */
  const handleLogout = useCallback(() => {
    window.location.href = '/api/logout';
  }, []);

  /* Add month */
  const handleAddMonth = useCallback(async (monthName, copyFrom) => {
    if (copyFrom) {
      // Duplicate from existing month
      const sourceMonth = months.find(m => m.name === copyFrom);
      if (sourceMonth) {
        duplicateMonth(sourceMonth.id, monthName);
      } else {
        addMonth(monthName);
      }
    } else {
      addMonth(monthName);
    }
    await saveDb();
    const m = getMonths();
    setMonths(m);
    setAllMonths(getAllMonthsSummary());
    setActiveMonth(monthName);
    loadMonth(monthName, m);
    toast(`חודש "${monthName}" נוסף`, 'success');
  }, [months, loadMonth, toast]);

  /* Delete month */
  const handleDeleteMonth = useCallback(async (monthId, monthName) => {
    if (!confirm(`האם אתה בטוח שברצונך למחוק את "${monthName}"?`)) return;
    deleteMonth(monthId);
    await saveDb();
    const m = getMonths();
    setMonths(m);
    setAllMonths(getAllMonthsSummary());
    if (m.length > 0) {
      const newActive = m[m.length - 1].name;
      setActiveMonth(newActive);
      loadMonth(newActive, m);
    } else {
      setActiveMonth(null);
      setData(null);
      setPrevData(null);
    }
    toast(`חודש "${monthName}" נמחק`, 'success');
  }, [loadMonth, toast]);

  /* Render */
  const showDashboard = months.length > 0 && data;

  return (
    <div className="app-layout">
      {loading && (
        <div className="loading-overlay">
          <div className="spinner" />
          <p>טוען...</p>
        </div>
      )}

      {!loading && (
        <Sidebar
          months={months}
          activeMonth={activeMonth}
          onSelect={(name) => loadMonth(name)}
          sidebarOpen={sidebarOpen}
          onToggle={() => setSidebarOpen((v) => !v)}
          onAddMonth={handleAddMonth}
          onDeleteMonth={handleDeleteMonth}
        />
      )}

      <main
        className="main-content"
        style={!showDashboard ? { marginRight: 0 } : undefined}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        {!showDashboard ? (
          <div className="welcome-screen">
            <div className="welcome-content">
              <div className="welcome-icon">🏠</div>
              <h1>Welcome to HomeExpenses</h1>
              <p>Start managing your monthly expenses</p>
              <div className="welcome-steps">
                <div className="welcome-step">
                  <span className="step-number">1</span>
                  <span>Open the sidebar menu</span>
                </div>
                <div className="welcome-step">
                  <span className="step-number">2</span>
                  <span>Press ➕ to add a new month</span>
                </div>
                <div className="welcome-step">
                  <span className="step-number">3</span>
                  <span>Start tracking your expenses</span>
                </div>
              </div>
              <button className="welcome-btn" onClick={() => setSidebarOpen(true)}>
                📋 Open Sidebar
              </button>
            </div>
          </div>
        ) : (
          <div
            className={`swipe-container ${slideClass}`}
            style={swipeOffset ? { transform: `translateX(${swipeOffset}px)`, transition: 'none' } : undefined}
          >
            {/* Top bar */}
            <div className="top-bar">
              <div className="month-nav-header">
                <button
                  className="month-nav-arrow"
                  onClick={() => navigateMonth('right')}
                  disabled={months.findIndex(m => m.name === activeMonth) <= 0}
                >
                  ◀
                </button>
                <h1>📊 {activeMonth}</h1>
                <button
                  className="month-nav-arrow"
                  onClick={() => navigateMonth('left')}
                  disabled={months.findIndex(m => m.name === activeMonth) >= months.length - 1}
                >
                  ▶
                </button>
              </div>
              <div className="top-actions">
                <button className="action-btn primary" onClick={handleSync}>🔄 סנכרון</button>
                {currentUser && (
                  <button className="action-btn logout-btn" onClick={handleLogout} title="התנתק">
                    👤 {currentUser} | יציאה
                  </button>
                )}
              </div>
            </div>

            {/* Summary cards with trends */}
            <SummaryCards
              totalIncome={data.totalIncome}
              totalExpenses={data.totalExpenses}
              remaining={data.remaining}
              prevData={prevData}
              mezonot={Math.round(1860 + (data.taliaExpenses || []).reduce((s, r) => s + (r.half || 0), 0) - (data.dovExpenses || []).reduce((s, r) => s + (r.half || 0), 0))}
              prevMezonot={prevData ? Math.round(1860 + (prevData.taliaHalfSum || 0) - (prevData.dovHalfSum || 0)) : null}
              dovHalfSum={(data.dovExpenses || []).reduce((s, r) => s + (r.half || 0), 0)}
              taliaHalfSum={(data.taliaExpenses || []).reduce((s, r) => s + (r.half || 0), 0)}
            />

            {/* Tables */}
            <ExpenseTable
              title="הוצאות משתנות"
              icon="�"
              columns={FIXED_COLS}
              rows={data.variableExpenses}
              tableName="variable_expenses"
              monthId={data.monthId}
              onCellSave={handleCellSave}
              onAddRow={handleAddRow}
              onDeleteRows={(ids) => {
                ids.forEach((id) => deleteRow('variable_expenses', id));
                if (data.monthId) recalcMonthTotals(data.monthId);
                saveDb().then(() => {
                  loadMonth(activeMonth);
                  setAllMonths(getAllMonthsSummary());
                  toast(`${ids.length} שורות נמחקו`, 'success');
                });
              }}
            />

            <ExpenseTable
              title="הוצאות - דב"
              icon="👤"
              columns={PERSON_COLS}
              rows={data.dovExpenses}
              tableName="dov_expenses"
              monthId={data.monthId}
              onCellSave={handleCellSave}
              onAddRow={handleAddRow}
              onDeleteRows={(ids) => {
                ids.forEach((id) => deleteRow('dov_expenses', id));
                if (data.monthId) recalcMonthTotals(data.monthId);
                saveDb().then(() => {
                  loadMonth(activeMonth);
                  setAllMonths(getAllMonthsSummary());
                  toast(`${ids.length} שורות נמחקו`, 'success');
                });
              }}
            />

            <ExpenseTable
              title="הוצאות - טליה"
              icon="�"
              columns={PERSON_COLS}
              rows={data.taliaExpenses}
              tableName="talia_expenses"
              monthId={data.monthId}
              onCellSave={handleCellSave}
              onAddRow={handleAddRow}
              onDeleteRows={(ids) => {
                ids.forEach((id) => deleteRow('talia_expenses', id));
                if (data.monthId) recalcMonthTotals(data.monthId);
                saveDb().then(() => {
                  loadMonth(activeMonth);
                  setAllMonths(getAllMonthsSummary());
                  toast(`${ids.length} שורות נמחקו`, 'success');
                });
              }}
            />

            <ExpenseTable
              title="הוצאות קבועות"
              icon="🏠"
              columns={FIXED_COLS}
              rows={data.fixedExpenses}
              tableName="fixed_expenses"
              monthId={data.monthId}
              onCellSave={handleCellSave}
              onAddRow={handleAddRow}
              onDeleteRows={(ids) => {
                ids.forEach((id) => deleteRow('fixed_expenses', id));
                if (data.monthId) recalcMonthTotals(data.monthId);
                saveDb().then(() => {
                  loadMonth(activeMonth);
                  setAllMonths(getAllMonthsSummary());
                  toast(`${ids.length} שורות נמחקו`, 'success');
                });
              }}
            />

            <ExpenseTable
              title="הכנסות"
              icon="�"
              columns={[
                { key: 'name', label: 'מקור', type: 'text' },
                { key: 'amount', label: 'סכום', type: 'number' },
              ]}
              rows={data.income}
              tableName="income"
              monthId={data.monthId}
              onCellSave={handleCellSave}
              onAddRow={handleAddRow}
              onDeleteRows={(ids) => {
                ids.forEach((id) => deleteRow('income', id));
                if (data.monthId) recalcMonthTotals(data.monthId);
                saveDb().then(() => {
                  loadMonth(activeMonth);
                  setAllMonths(getAllMonthsSummary());
                  toast(`${ids.length} שורות נמחקו`, 'success');
                });
              }}
            />

            {/* Charts */}
            <div className="charts-grid">
              <MonthlyComparisonChart allMonths={allMonths} />
            </div>
          </div>
        )}
      </main>

      {/* Toasts */}
      <div className="toast-wrapper">
        {toasts.map((t) => (
          <Toast key={t.id} message={t.message} type={t.type} onClose={() => removeToast(t.id)} />
        ))}
      </div>
    </div>
  );
}
