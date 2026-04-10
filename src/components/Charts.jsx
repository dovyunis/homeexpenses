import { useMemo } from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import ChartDataLabels from 'chartjs-plugin-datalabels';
import { useTheme } from '../ThemeContext';
import { generateColors } from '../utils';
import './Charts.css';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ChartDataLabels);

export function FixedExpensesChart({ data }) {
  const { dark } = useTheme();

  const chartData = useMemo(() => {
    if (!data) return null;
    const labels = data.map((r) => r.name);
    const values = data.map((r) => r.amount);
    const colors = generateColors(labels.length);
    return {
      labels,
      datasets: [{
        label: 'סכום',
        data: values,
        backgroundColor: colors.map((c) => c + 'cc'),
        borderColor: colors,
        borderWidth: 1,
        borderRadius: 6,
      }],
    };
  }, [data]);

  if (!chartData) return null;

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      datalabels: {
        anchor: 'end',
        align: 'top',
        color: dark ? '#ccc' : '#333',
        font: { size: 10, weight: 600 },
        formatter: (v) => '₪' + v.toLocaleString(),
      },
    },
    scales: {
      x: {
        ticks: { color: dark ? '#aaa' : '#555', font: { size: 10 } },
        grid: { display: false },
      },
      y: {
        ticks: { color: dark ? '#aaa' : '#555', callback: (v) => '₪' + v.toLocaleString() },
        grid: { color: dark ? '#2d2f3e' : '#eee' },
      },
    },
  };

  return (
    <div className="chart-card">
      <h3>📊 הוצאות קבועות</h3>
      <div className="chart-canvas-wrapper">
        <Bar data={chartData} options={options} />
      </div>
    </div>
  );
}

export function MonthlyComparisonChart({ allMonths }) {
  const { dark } = useTheme();

  const chartData = useMemo(() => {
    if (!allMonths?.length) return null;
    const labels = allMonths.map((m) => m.name);
    return {
      labels,
      datasets: [
        {
          label: 'הכנסות',
          data: allMonths.map((m) => m.totalIncome),
          backgroundColor: (dark ? '#34d399' : '#10b981') + 'aa',
          borderColor: dark ? '#34d399' : '#10b981',
          borderWidth: 1,
          borderRadius: 6,
        },
        {
          label: 'הוצאות',
          data: allMonths.map((m) => m.totalExpenses),
          backgroundColor: (dark ? '#f87171' : '#ef4444') + 'aa',
          borderColor: dark ? '#f87171' : '#ef4444',
          borderWidth: 1,
          borderRadius: 6,
        },
      ],
    };
  }, [allMonths, dark]);

  if (!chartData) return null;

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
        labels: { color: dark ? '#ccc' : '#333', font: { size: 12 }, usePointStyle: true, pointStyle: 'rectRounded' },
      },
      datalabels: { display: false },
    },
    scales: {
      x: {
        ticks: { color: dark ? '#aaa' : '#555', font: { size: 11 } },
        grid: { display: false },
      },
      y: {
        ticks: { color: dark ? '#aaa' : '#555', callback: (v) => '₪' + v.toLocaleString() },
        grid: { color: dark ? '#2d2f3e' : '#eee' },
      },
    },
  };

  return (
    <div className="chart-card">
      <h3>📈 השוואה חודשית</h3>
      <div className="chart-canvas-wrapper">
        <Bar data={chartData} options={options} />
      </div>
    </div>
  );
}
