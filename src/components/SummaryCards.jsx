import { fmt } from '../utils';
import './SummaryCards.css';

export default function SummaryCards({ totalIncome, totalExpenses, remaining, prevData, mezonot, prevMezonot, dovHalfSum, taliaHalfSum }) {
  const renderTrend = (current, previous, invertColor = false) => {
    if (previous == null || previous === 0) return <span className="card-trend neutral">—</span>;
    const diff = current - previous;
    const pct = Math.round((diff / previous) * 100);
    const isUp = diff > 0;
    // For expenses: going up is bad (red), going down is good (green)
    // For income/remaining: going up is good (green), going down is bad (red)
    let cls;
    if (invertColor) {
      cls = isUp ? 'down' : 'up'; // invert for expenses
    } else {
      cls = isUp ? 'up' : 'down';
    }
    if (diff === 0) cls = 'neutral';
    return (
      <span className={`card-trend ${cls}`}>
        {isUp ? '▲' : '▼'} {Math.abs(pct)}%
      </span>
    );
  };

  return (
    <div className="summary-cards">
      <div className="summary-card">
        <div className="card-header">
          <span className="card-label">הכנסות</span>
          <div className="card-icon income">💰</div>
        </div>
        <div className="card-value">{fmt(totalIncome)}</div>
        {renderTrend(totalIncome, prevData?.totalIncome)}
      </div>

      <div className="summary-card">
        <div className="card-header">
          <span className="card-label">הוצאות</span>
          <div className="card-icon expense">💳</div>
        </div>
        <div className="card-value">{fmt(totalExpenses)}</div>
        {renderTrend(totalExpenses, prevData?.totalExpenses, true)}
      </div>

      <div className="summary-card">
        <div className="card-header">
          <span className="card-label">נשאר</span>
          <div className="card-icon remain">🏦</div>
        </div>
        <div className="card-value">{fmt(remaining)}</div>
        {renderTrend(remaining, prevData?.remaining)}
      </div>

      <div className="summary-card">
        <div className="card-header">
          <span className="card-label">מזונות</span>
          <div className="card-icon mezonot">👨‍👧‍👦</div>
        </div>
        <div className="card-value">{fmt(mezonot)}</div>
        <div className="card-breakdown">
          1,860 + {fmt(taliaHalfSum)} − {fmt(dovHalfSum)}
        </div>
        {renderTrend(mezonot, prevMezonot, true)}
      </div>
    </div>
  );
}
