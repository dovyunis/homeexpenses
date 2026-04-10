import { useEffect, useState } from 'react';
import './Toast.css';

export default function Toast({ message, type = 'info', onClose }) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(onClose, 300);
    }, 3000);
    return () => clearTimeout(timer);
  }, [onClose]);

  if (!visible) return null;

  const icons = { success: '✅', error: '❌', info: 'ℹ️' };

  return (
    <div className={`toast ${type}`}>
      <span className="toast-icon">{icons[type]}</span>
      <span>{message}</span>
    </div>
  );
}
