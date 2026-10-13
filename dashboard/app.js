/**
 * X-NIDS Security Operations Center Dashboard
 * Real-time reactive telemetry, simulation runner, and SHAP explainability inspector.
 */

// Application State
const state = {
  currentPage: 1,
  pageSize: 25,
  totalFlows: 0,
  statusFilter: 'all',
  searchQuery: '',
  threshold: 0.50,
  categoryChart: null,
  isSimulating: false,
  selectedFlowId: null
};

// Attack Category Color Mapping
const CATEGORY_COLORS = {
  'Normal': '#10b981',
  'Exploits': '#ef4444',
  'DoS': '#f97316',
  'Reconnaissance': '#3b82f6',
  'Generic': '#8b5cf6',
  'Fuzzers': '#ec4899',
  'Analysis': '#eab308',
  'Backdoor': '#14b8a6',
  'Worms': '#a855f7'
};

// DOM Elements
const kpiTotalFlows = document.getElementById('kpiTotalFlows');
const kpiThreats = document.getElementById('kpiThreats');
const kpiThreatRatio = document.getElementById('kpiThreatRatio');
const kpiBenignCount = document.getElementById('kpiBenignCount');
const kpiThroughput = document.getElementById('kpiThroughput');
const kpiLatency = document.getElementById('kpiLatency');
const flowsTableBody = document.getElementById('flowsTableBody');
const pageInfo = document.getElementById('pageInfo');
const prevPageBtn = document.getElementById('prevPageBtn');
const nextPageBtn = document.getElementById('nextPageBtn');
const flowSearch = document.getElementById('flowSearch');
const filterBtns = document.querySelectorAll('.filter-btn');
const runSimBtn = document.getElementById('runSimBtn');
const btnIcon = document.getElementById('btnIcon');
const btnText = document.getElementById('btnText');
const thresholdSlider = document.getElementById('thresholdSlider');
const thresholdValue = document.getElementById('thresholdValue');
const shapPlotImg = document.getElementById('shapPlotImg');
const lastRunTime = document.getElementById('lastRunTime');

// Drawer Elements
const shapDrawer = document.getElementById('shapDrawer');
const closeDrawerBtn = document.getElementById('closeDrawerBtn');
const drawerFlowTitle = document.getElementById('drawerFlowTitle');
const drawerFlowSubtitle = document.getElementById('drawerFlowSubtitle');
const drawerVerdict = document.getElementById('drawerVerdict');
const drawerConfidence = document.getElementById('drawerConfidence');
const drawerDriversList = document.getElementById('drawerDriversList');
const drawerRecommendation = document.getElementById('drawerRecommendation');
const drawerRawMetrics = document.getElementById('drawerRawMetrics');

// Modal Elements
const plotModal = document.getElementById('plotModal');
const expandPlotBtn = document.getElementById('expandPlotBtn');
const closePlotModalBtn = document.getElementById('closePlotModalBtn');
const plotThumbnailContainer = document.getElementById('plotThumbnailContainer');

// -----------------------------------------------------------------------------
// Core Initialization
// -----------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  fetchMetrics();
  fetchFlows();
  fetchShapAlerts();
});

function initEventListeners() {
  // Threshold Slider
  thresholdSlider.addEventListener('input', (e) => {
    state.threshold = parseFloat(e.target.value);
    thresholdValue.textContent = state.threshold.toFixed(2);
    state.currentPage = 1;
    fetchFlows();
  });

  // Search input debounce
  let searchTimeout = null;
  flowSearch.addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      state.searchQuery = e.target.value.trim();
      state.currentPage = 1;
      fetchFlows();
    }, 250);
  });

  // Status Filter Pills
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => {
        b.classList.remove('bg-blue-600', 'text-white');
        b.classList.add('text-slate-400');
      });
      btn.classList.add('bg-blue-600', 'text-white');
      btn.classList.remove('text-slate-400');
      
      state.statusFilter = btn.dataset.status;
      state.currentPage = 1;
      fetchFlows();
    });
  });

  // Pagination
  prevPageBtn.addEventListener('click', () => {
    if (state.currentPage > 1) {
      state.currentPage--;
      fetchFlows();
    }
  });

  nextPageBtn.addEventListener('click', () => {
    const maxPage = Math.ceil(state.totalFlows / state.pageSize);
    if (state.currentPage < maxPage) {
      state.currentPage++;
      fetchFlows();
    }
  });

  // Run Simulation Button
  runSimBtn.addEventListener('click', triggerSimulation);

  // Drawer Close
  closeDrawerBtn.addEventListener('click', closeDrawer);
  shapDrawer.addEventListener('click', (e) => {
    if (e.target === shapDrawer) closeDrawer();
  });

  // Modal Plot Zoom
  expandPlotBtn.addEventListener('click', () => plotModal.classList.remove('hidden'));
  plotThumbnailContainer.addEventListener('click', () => plotModal.classList.remove('hidden'));
  closePlotModalBtn.addEventListener('click', () => plotModal.classList.add('hidden'));
  plotModal.addEventListener('click', (e) => {
    if (e.target === plotModal) plotModal.classList.add('hidden');
  });
}

// -----------------------------------------------------------------------------
// API Calls & Data Rendering
// -----------------------------------------------------------------------------

async function fetchMetrics() {
  try {
    const res = await fetch('/api/metrics');
    const data = await res.json();
    
    kpiTotalFlows.textContent = Number(data.total_flows || 0).toLocaleString();
    kpiThreats.textContent = Number(data.threat_count || 0).toLocaleString();
    kpiThreatRatio.textContent = `${data.threat_ratio_pct || 0}% Ratio`;
    kpiBenignCount.textContent = `${Number(data.benign_count || 0).toLocaleString()} Legitimate flows OK`;
    kpiThroughput.textContent = (data.throughput_us || 0).toFixed(1);
    kpiLatency.textContent = `Total Latency: ${(data.latency_ms || 0).toFixed(1)} ms`;
    
    renderCategoryChart(data.category_breakdown || {}, data.benign_count || 0);
  } catch (err) {
    console.error('Failed to fetch metrics:', err);
  }
}

async function fetchFlows() {
  try {
    const offset = (state.currentPage - 1) * state.pageSize;
    const url = `/api/flows?status=${state.statusFilter}&search=${encodeURIComponent(state.searchQuery)}&threshold=${state.threshold}&limit=${state.pageSize}&offset=${offset}`;
    
    const res = await fetch(url);
    const data = await res.json();
    
    state.totalFlows = data.total;
    renderFlowsTable(data.flows);
    renderPagination(data.total, offset, data.limit);
  } catch (err) {
    console.error('Failed to fetch flows:', err);
    flowsTableBody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-rose-400">Failed to load flows telemetry</td></tr>`;
  }
}

async function fetchShapAlerts() {
  try {
    const res = await fetch('/api/shap-alerts');
    const data = await res.json();
    if (data.plots && data.plots.length > 0) {
      const plotUrl = `${data.plots[0]}?t=${Date.now()}`;
      shapPlotImg.src = plotUrl;
      document.getElementById('modalPlotImg').src = plotUrl;
      shapPlotImg.style.display = 'block';
      document.getElementById('plotPlaceholder').style.display = 'none';
    }
  } catch (err) {
    console.error('Failed to fetch SHAP alerts:', err);
  }
}

// -----------------------------------------------------------------------------
// Interactive Trigger Simulation
// -----------------------------------------------------------------------------

async function triggerSimulation() {
  if (state.isSimulating) return;
  state.isSimulating = true;
  
  // UI Loading State
  btnIcon.classList.add('animate-radar');
  btnText.textContent = 'Simulating Traffic & AI...';
  runSimBtn.classList.add('opacity-80', 'cursor-not-allowed');
  
  try {
    const res = await fetch('/api/run-simulation', { method: 'POST' });
    const result = await res.json();
    
    if (result.success) {
      lastRunTime.textContent = 'Just now';
      await fetchMetrics();
      await fetchFlows();
      await fetchShapAlerts();
    } else {
      alert(`Simulation Error: ${result.error || 'Unknown failure'}`);
    }
  } catch (err) {
    console.error('Simulation execution failed:', err);
    alert('Failed to connect to simulation server.');
  } finally {
    state.isSimulating = false;
    btnIcon.classList.remove('animate-radar');
    btnText.textContent = 'Trigger Simulation & AI';
    runSimBtn.classList.remove('opacity-80', 'cursor-not-allowed');
  }
}

// -----------------------------------------------------------------------------
// Table & Component Renderers
// -----------------------------------------------------------------------------

function renderFlowsTable(flows) {
  if (!flows || flows.length === 0) {
    flowsTableBody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center py-8 text-slate-500">
          No matching flows found with current filters
        </td>
      </tr>`;
    return;
  }

  flowsTableBody.innerHTML = flows.map(f => {
    const isMal = f.is_malicious;
    const badgeClass = isMal ? 'badge-threat' : 'badge-normal';
    const statusText = isMal ? 'THREAT' : 'NORMAL';
    const catColor = CATEGORY_COLORS[f.predicted_class] || '#94a3b8';
    
    return `
      <tr class="table-row-hover" onclick="openShapDrawer(${f.flow_id})">
        <td class="py-3 px-4">
          <span class="badge ${badgeClass}">${statusText}</span>
        </td>
        <td class="py-3 px-4 font-mono font-medium text-slate-200">
          <span class="text-blue-400">${f.src_ip}</span>:<span class="text-slate-400">${f.src_port}</span>
          <span class="text-slate-500 mx-1">→</span>
          <span class="text-cyan-400">${f.dst_ip}</span>:<span class="text-slate-400">${f.dst_port}</span>
        </td>
        <td class="py-3 px-4 text-slate-400 font-bold">${f.proto}</td>
        <td class="py-3 px-4 text-slate-300 font-mono">${f.dur}s</td>
        <td class="py-3 px-4 text-slate-300 font-mono">
          ${f.spkts} pkts (${f.sbytes} B)
        </td>
        <td class="py-3 px-4">
          <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold" style="color: ${catColor}; background: ${catColor}15; border: 1px solid ${catColor}30;">
            ${f.predicted_class}
          </span>
        </td>
        <td class="py-3 px-4 font-mono">
          <div class="flex items-center gap-2">
            <span class="${isMal ? 'text-rose-400 font-bold' : 'text-emerald-400'}">${f.confidence}%</span>
            <div class="w-12 bg-slate-800 h-1 rounded-full overflow-hidden">
              <div class="h-full ${isMal ? 'bg-rose-500' : 'bg-emerald-500'}" style="width: ${f.confidence}%"></div>
            </div>
          </div>
        </td>
        <td class="py-3 px-4 text-right">
          <button class="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition-colors text-xs font-medium"
                  onclick="event.stopPropagation(); openShapDrawer(${f.flow_id})">
            Explain SHAP
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderPagination(total, offset, limit) {
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + limit, total);
  pageInfo.textContent = `Showing ${start} to ${end} of ${total} flows`;
  
  prevPageBtn.disabled = state.currentPage <= 1;
  nextPageBtn.disabled = end >= total;
}

function renderCategoryChart(threatCategories, benignCount) {
  const ctx = document.getElementById('categoryChart').getContext('2d');
  
  const labels = ['Normal (Benign)', ...Object.keys(threatCategories)];
  const dataValues = [benignCount, ...Object.values(threatCategories)];
  const backgroundColors = [
    '#10b981',
    ...Object.keys(threatCategories).map(k => CATEGORY_COLORS[k] || '#ef4444')
  ];

  if (state.categoryChart) {
    state.categoryChart.destroy();
  }

  state.categoryChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: dataValues,
        backgroundColor: backgroundColors,
        borderWidth: 1,
        borderColor: '#0f172a'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f172a',
          titleFont: { family: 'Outfit', size: 13 },
          bodyFont: { family: 'JetBrains Mono', size: 12 },
          borderColor: 'rgba(255,255,255,0.1)',
          borderWidth: 1,
          padding: 10
        }
      },
      cutout: '72%'
    }
  });

  // Render Legend
  const legendContainer = document.getElementById('chartLegend');
  legendContainer.innerHTML = labels.map((lbl, idx) => `
    <div class="flex items-center gap-1.5 font-mono">
      <span class="w-2.5 h-2.5 rounded-full" style="background-color: ${backgroundColors[idx]}"></span>
      <span class="text-slate-300 truncate">${lbl}:</span>
      <span class="text-white font-bold ml-auto">${dataValues[idx]}</span>
    </div>
  `).join('');
}

// -----------------------------------------------------------------------------
// Deep Flow SHAP Explainability Inspector
// -----------------------------------------------------------------------------

async function openShapDrawer(flowId) {
  state.selectedFlowId = flowId;
  shapDrawer.classList.add('active');
  
  drawerDriversList.innerHTML = `<div class="text-center py-6 text-slate-500">Calculating SHAP TreeExplainer attributions...</div>`;
  drawerRawMetrics.innerHTML = ``;
  
  try {
    const res = await fetch(`/api/explain-flow/${flowId}`);
    const data = await res.json();
    
    if (data.error) {
      drawerDriversList.innerHTML = `<div class="text-rose-400 p-4">${data.error}</div>`;
      return;
    }

    const flow = data.flow;
    const isMal = flow.is_malicious;
    
    drawerFlowTitle.textContent = `Flow #${flow.flow_id} Attribution`;
    drawerFlowSubtitle.textContent = `${flow.src_ip}:${flow.src_port} → ${flow.dst_ip}:${flow.dst_port} (${flow.proto})`;
    
    drawerVerdict.textContent = data.class_name.toUpperCase();
    drawerVerdict.className = `text-lg font-heading font-extrabold ${isMal ? 'text-rose-400' : 'text-emerald-400'}`;
    
    drawerConfidence.textContent = `${data.confidence}%`;
    
    // Feature Drivers Visualization
    drawerDriversList.innerHTML = data.drivers.map(d => {
      const isPushMal = d.impact > 0;
      const barColor = isPushMal ? 'bg-rose-500' : 'bg-emerald-500';
      const textColor = isPushMal ? 'text-rose-400' : 'text-emerald-400';
      const sign = d.impact > 0 ? '+' : '';
      const absImpact = Math.min(Math.abs(d.impact) * 80, 100); // Scale bar for UI
      
      return `
        <div class="bg-slate-900/60 p-3 rounded-xl border border-white/5 space-y-1.5">
          <div class="flex justify-between items-center text-xs">
            <span class="font-mono font-medium text-slate-200">${d.feature}</span>
            <div class="flex items-center gap-2 font-mono">
              <span class="text-slate-400">val=${d.value}</span>
              <span class="${textColor} font-bold">${sign}${d.impact.toFixed(4)}</span>
            </div>
          </div>
          <div class="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div class="${barColor} h-full rounded-full transition-all duration-500" style="width: ${absImpact}%"></div>
          </div>
        </div>
      `;
    }).join('');

    // Recommendation logic
    if (isMal) {
      drawerRecommendation.textContent = `Threat classified as [${data.class_name}] with ${data.confidence}% ensemble probability. Primary indicators include anomalous feature values in ${data.drivers[0].feature} (${data.drivers[0].value}) contributing ${data.drivers[0].impact.toFixed(3)} to malice score. SOC action: Isolate host ${flow.src_ip} and block ingress TCP/UDP port ${flow.dst_port}.`;
    } else {
      drawerRecommendation.textContent = `Flow conforms to standard baseline enterprise traffic profile. Handshake timing, byte symmetry, and session payload size align with normal network operations. No remediation required.`;
    }

    // Raw Metrics
    drawerRawMetrics.innerHTML = Object.entries(flow).map(([k, v]) => `
      <div class="truncate">
        <span class="text-slate-500">${k}:</span> <strong class="text-slate-300">${v}</strong>
      </div>
    `).join('');

  } catch (err) {
    console.error('Failed to explain flow:', err);
    drawerDriversList.innerHTML = `<div class="text-rose-400 p-4">Error computing SHAP values.</div>`;
  }
}

function closeDrawer() {
  shapDrawer.classList.remove('active');
}
