import './MonthTabs.css';

export default function MonthTabs({ months, activeMonth, onSelect }) {
  return (
    <nav className="month-tabs">
      {months.map((m) => (
        <button
          key={m.id}
          className={`month-tab ${m.name === activeMonth ? 'active' : ''}`}
          onClick={() => onSelect(m.name)}
        >
          {m.name}
        </button>
      ))}
    </nav>
  );
}
