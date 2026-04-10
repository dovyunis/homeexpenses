import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ThemeProvider } from './ThemeContext';
import App from './App';
import './index.css';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </StrictMode>
);

// Unregister old service workers and register fresh one
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    // Unregister all old service workers first
    const regs = await navigator.serviceWorker.getRegistrations();
    for (const reg of regs) {
      await reg.unregister();
    }
    // Clear all caches
    const keys = await caches.keys();
    for (const key of keys) {
      await caches.delete(key);
    }
    // Register fresh service worker
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  });
}
