/**
 * SURVEILGUARD AI — Chart.js Visualization Controllers
 * Connects to real API data. Shows loading, empty, and error states.
 */

let chartInstances = {};

function destroyChart(chartId) {
  if (chartInstances[chartId]) {
    chartInstances[chartId].destroy();
    chartInstances[chartId] = null;
  }
}

const ChartTheme = {
  text: '#64748b',
  textLight: '#1e293b',
  grid: 'rgba(0, 0, 0, 0.06)',
  fontFamily: "'Inter', sans-serif",
};

// ─── Empty State helpers ───────────────────────────────────────────────────────

function showChartEmpty(wrapperId, icon, message) {
  const wrapper = document.getElementById(wrapperId);
  if (!wrapper) return;
  wrapper.innerHTML = `
    <div style="height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:20px;text-align:center;">
      <i class="${icon}" style="font-size:28px;color:#94a3b8;"></i>
      <p style="font-size:12px;color:var(--text-dim);margin:0;max-width:180px;">${message}</p>
    </div>`;
}

function showChartLoading(wrapperId) {
  const wrapper = document.getElementById(wrapperId);
  if (!wrapper) return;
  wrapper.innerHTML = `
    <div style="height:100%;display:flex;align-items:center;justify-content:center;gap:8px;">
      <i class="fas fa-spinner fa-spin" style="color:var(--primary-blue);font-size:20px;"></i>
      <span style="font-size:12px;color:var(--text-dim);">Loading chart data...</span>
    </div>`;
}

function restoreCanvas(wrapperId, canvasId) {
  const wrapper = document.getElementById(wrapperId);
  if (!wrapper) return null;
  // Remove placeholder content and restore canvas
  wrapper.innerHTML = `<canvas id="${canvasId}"></canvas>`;
  return document.getElementById(canvasId);
}

// ─── 1. Normal vs Suspicious Ratio ────────────────────────────────────────────

function renderStatusDonutChart(chartData, wrapperId) {
  wrapperId = wrapperId || 'chartWrapperStatus';
  const canvas = restoreCanvas(wrapperId, 'statusDonutChart');
  if (!canvas) return;
  destroyChart('statusDonut');

  const hasData = chartData && chartData.values && chartData.values.some(v => v > 0);

  if (!hasData) {
    showChartEmpty(wrapperId, 'fas fa-chart-pie', 'No events recorded yet. Start a detection session to populate this chart.');
    return;
  }

  chartInstances['statusDonut'] = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: chartData.labels,
      datasets: [{
        data: chartData.values,
        backgroundColor: ['#22c55e', '#ef4444'],
        borderColor: '#ffffff',
        borderWidth: 3,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: ChartTheme.textLight,
            font: { family: ChartTheme.fontFamily, size: 12, weight: '600' },
            padding: 14
          }
        },
        tooltip: {
          backgroundColor: '#1e293b',
          titleColor: '#fff',
          bodyColor: '#e2e8f0',
          borderColor: '#475569',
          borderWidth: 1,
          padding: 10,
          cornerRadius: 6,
          callbacks: {
            label: function(ctx) {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct = total > 0 ? Math.round(ctx.raw / total * 100) : 0;
              return ` ${ctx.label}: ${ctx.raw} (${pct}%)`;
            }
          }
        }
      },
      cutout: '70%'
    }
  });
}

// ─── 2. 24-Hour Activity Distribution ─────────────────────────────────────────

function renderHourlyBarChart(chartData, wrapperId) {
  wrapperId = wrapperId || 'chartWrapperHourly';
  const canvas = restoreCanvas(wrapperId, 'hourlyBarChart');
  if (!canvas) return;
  destroyChart('hourlyBar');

  const hasData = chartData && chartData.values && chartData.values.some(v => v > 0);

  if (!hasData) {
    showChartEmpty(wrapperId, 'fas fa-clock', 'No activity recorded yet. Detection events will appear here by hour of day (UTC).');
    return;
  }

  chartInstances['hourlyBar'] = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: chartData.labels,
      datasets: [{
        label: 'Events',
        data: chartData.values,
        backgroundColor: 'rgba(59, 130, 246, 0.7)',
        hoverBackgroundColor: '#3b82f6',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: ChartTheme.grid },
          ticks: {
            color: ChartTheme.text,
            font: { family: ChartTheme.fontFamily, size: 9 },
            maxRotation: 45,
            callback: function(val, idx) {
              // Only show every 4th label to avoid crowding on 24 bars
              return idx % 4 === 0 ? this.getLabelForValue(val) : '';
            }
          }
        },
        y: {
          beginAtZero: true,
          grid: { color: ChartTheme.grid },
          ticks: {
            color: ChartTheme.text,
            font: { family: ChartTheme.fontFamily, size: 10 },
            precision: 0
          }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1e293b',
          titleColor: '#fff',
          bodyColor: '#e2e8f0',
          borderColor: '#475569',
          borderWidth: 1,
          padding: 10,
          cornerRadius: 6
        }
      }
    }
  });
}

// ─── 3. Events by Camera Source ───────────────────────────────────────────────

function renderCameraBarChart(chartData, wrapperId) {
  wrapperId = wrapperId || 'chartWrapperCamera';
  const canvas = restoreCanvas(wrapperId, 'cameraBarChart');
  if (!canvas) return;
  destroyChart('cameraBar');

  const hasData = chartData && chartData.values && chartData.values.some(v => v > 0);

  if (!hasData) {
    showChartEmpty(wrapperId, 'fas fa-camera', 'No camera events recorded yet. Events will be grouped by camera source here.');
    return;
  }

  const COLORS = [
    'rgba(59,130,246,0.75)', 'rgba(139,92,246,0.75)',
    'rgba(239,68,68,0.75)', 'rgba(245,158,11,0.75)',
    'rgba(34,197,94,0.75)', 'rgba(20,184,166,0.75)'
  ];

  chartInstances['cameraBar'] = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: chartData.labels,
      datasets: [{
        label: 'Events',
        data: chartData.values,
        backgroundColor: chartData.labels.map((_, i) => COLORS[i % COLORS.length]),
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: ChartTheme.grid },
          ticks: {
            color: ChartTheme.textLight,
            font: { family: ChartTheme.fontFamily, size: 10, weight: '600' },
            maxRotation: 35
          }
        },
        y: {
          beginAtZero: true,
          grid: { color: ChartTheme.grid },
          ticks: {
            color: ChartTheme.text,
            font: { family: ChartTheme.fontFamily, size: 10 },
            precision: 0
          }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1e293b',
          titleColor: '#fff',
          bodyColor: '#e2e8f0',
          borderColor: '#475569',
          borderWidth: 1,
          padding: 10,
          cornerRadius: 6
        }
      }
    }
  });
}

// ─── 4. Suspicious Incidents by Location ──────────────────────────────────────

function renderLocationRadarChart(chartData, wrapperId) {
  wrapperId = wrapperId || 'chartWrapperLocation';
  const canvas = restoreCanvas(wrapperId, 'locationRadarChart');
  if (!canvas) return;
  destroyChart('locationRadar');

  const hasData = chartData && chartData.values && chartData.values.some(v => v > 0);

  if (!hasData) {
    showChartEmpty(wrapperId, 'fas fa-compass', 'No suspicious incidents recorded yet. When threats are detected, their locations will appear here.');
    return;
  }

  const COLORS_BG = [
    'rgba(239,68,68,0.6)', 'rgba(245,158,11,0.6)',
    'rgba(139,92,246,0.6)', 'rgba(59,130,246,0.6)',
    'rgba(34,197,94,0.6)', 'rgba(20,184,166,0.6)'
  ];

  chartInstances['locationRadar'] = new Chart(canvas, {
    type: 'polarArea',
    data: {
      labels: chartData.labels,
      datasets: [{
        data: chartData.values,
        backgroundColor: chartData.labels.map((_, i) => COLORS_BG[i % COLORS_BG.length]),
        borderColor: '#ffffff',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          grid: { color: ChartTheme.grid },
          ticks: { backdropColor: 'transparent', color: ChartTheme.text, font: { size: 9 }, precision: 0 }
        }
      },
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: ChartTheme.textLight,
            font: { family: ChartTheme.fontFamily, size: 10, weight: '500' },
            padding: 8,
            boxWidth: 12
          }
        },
        tooltip: {
          backgroundColor: '#1e293b',
          titleColor: '#fff',
          bodyColor: '#e2e8f0',
          borderColor: '#475569',
          borderWidth: 1,
          padding: 10,
          cornerRadius: 6
        }
      }
    }
  });
}

// ─── ChartsManager — called from app.js ───────────────────────────────────────

window.ChartsManager = {
  /**
   * Set loading states on all 4 chart wrappers.
   */
  showLoading() {
    ['chartWrapperStatus', 'chartWrapperHourly', 'chartWrapperCamera', 'chartWrapperLocation']
      .forEach(id => showChartLoading(id));
  },

  /**
   * Renders all 4 charts from the API response.
   * Expects:
   *   data.status_distribution    -> { labels, values }
   *   data.events_by_hour         -> { labels, values }
   *   data.events_by_camera       -> { labels, values }
   *   data.suspicious_by_location -> { labels, values }
   */
  renderCharts(data) {
    if (!data) {
      ['chartWrapperStatus', 'chartWrapperHourly', 'chartWrapperCamera', 'chartWrapperLocation']
        .forEach(id => showChartEmpty(id, 'fas fa-exclamation-triangle', 'Chart data unavailable.'));
      return;
    }

    try { renderStatusDonutChart(data.status_distribution, 'chartWrapperStatus'); }
    catch(e) { console.warn('Status chart error:', e); showChartEmpty('chartWrapperStatus', 'fas fa-chart-pie', 'Chart failed to render.'); }

    try { renderHourlyBarChart(data.events_by_hour, 'chartWrapperHourly'); }
    catch(e) { console.warn('Hourly chart error:', e); showChartEmpty('chartWrapperHourly', 'fas fa-clock', 'Chart failed to render.'); }

    try { renderCameraBarChart(data.events_by_camera, 'chartWrapperCamera'); }
    catch(e) { console.warn('Camera chart error:', e); showChartEmpty('chartWrapperCamera', 'fas fa-camera', 'Chart failed to render.'); }

    try { renderLocationRadarChart(data.suspicious_by_location, 'chartWrapperLocation'); }
    catch(e) { console.warn('Location chart error:', e); showChartEmpty('chartWrapperLocation', 'fas fa-compass', 'Chart failed to render.'); }
  }
};
