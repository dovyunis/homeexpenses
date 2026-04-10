export function fmt(n) {
  return '₪' + (n || 0).toLocaleString('he-IL', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
}

export function generateColors(count) {
  const base = [
    '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#e67e22', '#34495e',
    '#d35400', '#c0392b', '#16a085', '#8e44ad', '#2c3e50', '#f1c40f', '#7f8c8d',
    '#00bcd4', '#ff5722', '#795548', '#607d8b', '#4caf50', '#ff9800', '#673ab7',
    '#009688', '#cddc39', '#ffc107', '#03a9f4', '#e91e63', '#9e9e9e',
  ];
  return Array.from({ length: count }, (_, i) => base[i % base.length]);
}
