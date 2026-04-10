import { useRef, useState } from 'react';
import './UploadArea.css';

export default function UploadArea({ onFile }) {
  const inputRef = useRef(null);
  const [dragover, setDragover] = useState(false);

  const handleFiles = (files) => {
    const file = files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => onFile(e.target.result);
    reader.readAsBinaryString(file);
  };

  return (
    <div className="upload-area">
      <div
        className={`upload-card ${dragover ? 'dragover' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragover(true); }}
        onDragLeave={() => setDragover(false)}
        onDrop={(e) => { e.preventDefault(); setDragover(false); handleFiles(e.dataTransfer.files); }}
      >
        <span className="upload-icon">📁</span>
        <p className="upload-title">העלאת קובץ אקסל</p>
        <p className="upload-subtitle">גרור קובץ לכאן או לחץ לבחירה</p>
        <button className="upload-btn" type="button">📤 בחירת קובץ</button>
        <p className="upload-hint">נתמכים קבצי .xlsx / .xls</p>
        <input
          ref={inputRef}
          type="file"
          accept=".xlsx,.xls"
          hidden
          onChange={(e) => handleFiles(e.target.files)}
        />
      </div>
    </div>
  );
}
