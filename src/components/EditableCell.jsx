import { useState, useRef, useEffect } from 'react';

export default function EditableCell({ value, isNumber, onSave, formatter }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  const inputRef = useRef(null);

  useEffect(() => {
    if (editing && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [editing]);

  const handleStart = () => {
    setDraft(value ?? '');
    setEditing(true);
  };

  const handleSave = () => {
    setEditing(false);
    const finalVal = isNumber ? Number(draft) || 0 : draft;
    if (finalVal !== value) {
      onSave(finalVal);
    }
  };

  const handleKey = (e) => {
    if (e.key === 'Enter') handleSave();
    if (e.key === 'Escape') setEditing(false);
  };

  if (editing) {
    return (
      <input
        ref={inputRef}
        className="editable-input"
        type={isNumber ? 'number' : 'text'}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={handleSave}
        onKeyDown={handleKey}
      />
    );
  }

  const display = formatter ? formatter(value) : (value ?? '');

  return (
    <span className="editable-cell" onClick={handleStart} title="לחץ לעריכה">
      {display || <span style={{ opacity: 0.3 }}>—</span>}
    </span>
  );
}
