/**
 * PhishGraph Frontend Controller
 * Enterprise-grade client architecture for Graph ML & Fuzzy Logic Security Research
 */

// Global DOM helper access
window.$ = id => document.getElementById(id);
window.$$ = sel => document.querySelectorAll(sel);
const $ = window.$;
const $$ = window.$$;

const State = {
  activeSection: 'scanner',
  currentSingleResult: null,
  batchResults: [],
  batchFiltered: [],
  fuzzyPlaygroundData: null,
  trainingInterval: null,
  historyPage: 1,
  graphTransforms: {
    'graph-viewport': 1,
    'result-graph-viewport': 1
  }
};

// ============================================================================
// DRAWER / MODAL SAFETY CONTROLS
// ============================================================================
function openDrawer() {
  const d = document.getElementById('detail-drawer');
  if (d) {
    d.hidden = false;
    d.classList.add('is-open');
    d.style.setProperty('display', 'flex', 'important');
    d.style.setProperty('pointer-events', 'auto', 'important');
  }
}

function closeDrawer() {
  const d = document.getElementById('detail-drawer');
  if (d) {
    d.hidden = true;
    d.classList.remove('is-open');
    d.style.setProperty('display', 'none', 'important');
    d.style.setProperty('pointer-events', 'none', 'important');
  }
}
window.openDrawer = openDrawer;
window.closeDrawer = closeDrawer;

// Force closed on initial script evaluation
try { closeDrawer(); } catch (e) {}

// ============================================================================
// API CLIENT UTILITY
// ============================================================================
async function api(path, options = {}) {
  const headers = { ...options.headers };
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, { ...options, headers });
  
  const cType = response.headers.get('content-type') || '';
  if (cType.includes('application/pdf') || cType.includes('text/csv')) {
    if (!response.ok) throw new Error('File download failed');
    return response.blob();
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `HTTP error ${response.status}`);
  }
  return data;
}

// Download helper
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
}

// ============================================================================
// NAVIGATION & THEME CONTROLS
// ============================================================================
function openMobileNav() {
  const sb = $('sidebar');
  const bd = $('sidebar-backdrop');
  if (sb) sb.classList.add('mobile-open');
  if (bd) bd.classList.add('is-active');
  document.body.classList.add('mobile-nav-locked');
}

function closeMobileNav() {
  const sb = $('sidebar');
  const bd = $('sidebar-backdrop');
  if (sb) sb.classList.remove('mobile-open');
  if (bd) bd.classList.remove('is-active');
  document.body.classList.remove('mobile-nav-locked');
}

window.openMobileNav = openMobileNav;
window.closeMobileNav = closeMobileNav;

function initNavigation() {
  $$('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const sectionId = link.dataset.section;
      switchSection(sectionId);
    });
  });

  const brandLink = document.querySelector('.brand');
  if (brandLink) {
    brandLink.addEventListener('click', e => {
      e.preventDefault();
      switchSection('scanner');
    });
  }

  const quickDemoBtn = $('quick-demo-btn');
  if (quickDemoBtn) {
    quickDemoBtn.addEventListener('click', () => switchSection('guided-demo'));
  }

  // Theme Toggle
  const savedTheme = localStorage.getItem('phishgraph_theme') || 'dark';
  setTheme(savedTheme);

  const themeToggle = $('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      setTheme(next);
    });
  }

  // Desktop & Mobile Sidebar toggle
  const sidebarToggle = $('sidebar-toggle');
  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', () => {
      if (window.innerWidth <= 900) {
        closeMobileNav();
      } else {
        $('sidebar').classList.toggle('collapsed');
      }
    });
  }

  // Mobile Hamburger Toggle
  const mobileNavToggle = $('mobile-nav-toggle');
  if (mobileNavToggle) {
    mobileNavToggle.addEventListener('click', () => {
      const sb = $('sidebar');
      if (sb && sb.classList.contains('mobile-open')) {
        closeMobileNav();
      } else {
        openMobileNav();
      }
    });
  }

  // Mobile Backdrop Click
  const backdrop = $('sidebar-backdrop');
  if (backdrop) {
    backdrop.addEventListener('click', closeMobileNav);
  }
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const icon = $('theme-icon');
  if (icon) icon.textContent = theme === 'dark' ? '☀️' : '🌙';
  localStorage.setItem('phishgraph_theme', theme);
  if (State.fuzzyPlaygroundData) drawFuzzyCanvas();
}

function switchSection(sectionId) {
  State.activeSection = sectionId;
  $$('.nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.section === sectionId);
  });
  $$('.app-section').forEach(s => {
    s.classList.toggle('active', s.id === sectionId);
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // On mobile screens, automatically close the sidebar drawer
  closeMobileNav();

  // Section-specific hooks
  if (sectionId === 'history') loadHistory();
  if (sectionId === 'evaluation') loadMetrics();
  if (sectionId === 'playground') updatePlaygroundSimulation();
  if (sectionId === 'training') { loadTrainingStatus(); loadExperiments(); loadDatasetsDropdown(); }
  if (sectionId === 'datasets') loadDatasetsTable();
  if (sectionId === 'graph-view') loadSpectralMetrics();
}

// ============================================================================
// SECTION 01: SINGLE & BATCH URL SCANNER
// ============================================================================
async function executeScan(urlToScan, switchTab = true, isInitialLoad = false) {
  if (!urlToScan || !urlToScan.trim()) return;
  const url = urlToScan.trim();
  $('url').value = url;

  if (switchTab) {
    switchSection('scanner');
    $('tab-single-btn').click();
  }

  $('scan-error').hidden = true;
  const submitBtn = $('submit');
  const btnText = submitBtn ? submitBtn.querySelector('.btn-text') : null;

  if (!isInitialLoad && submitBtn) {
    submitBtn.disabled = true;
    if (btnText) btnText.textContent = 'Analyzing…';
  }

  try {
    const res = await api('/api/predict', { method: 'POST', body: { url } });
    renderSingleResult(res);
  } catch (err) {
    $('scan-error').textContent = err.message;
    $('scan-error').hidden = false;
    $('result').hidden = true;
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      if (btnText) btnText.textContent = 'Analyze URL ↗';
    }
  }
}
window.executeScan = executeScan;

function initScanner() {
  // Tab Switching
  $('tab-single-btn').addEventListener('click', () => {
    $('tab-single-btn').classList.add('active');
    $('tab-batch-btn').classList.remove('active');
    $('pane-single').classList.add('active');
    $('pane-batch').classList.remove('active');
  });

  $('tab-batch-btn').addEventListener('click', () => {
    $('tab-batch-btn').classList.add('active');
    $('tab-single-btn').classList.remove('active');
    $('pane-batch').classList.add('active');
    $('pane-single').classList.remove('active');
  });

  // Quick Preset Buttons
  $$('[data-example]').forEach(btn => {
    btn.addEventListener('click', () => {
      executeScan(btn.dataset.example, true, false);
    });
  });

  // Single Scan Form Submit
  $('scan-form').addEventListener('submit', e => {
    e.preventDefault();
    executeScan($('url').value, true, false);
  });

  // Export current single result
  $('download-current-json').addEventListener('click', () => {
    if (!State.currentSingleResult) return;
    const blob = new Blob([JSON.stringify(State.currentSingleResult, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `phishgraph-${State.currentSingleResult.host}.json`);
  });

  $('download-current-pdf').addEventListener('click', async () => {
    if (!State.currentSingleResult) return;
    try {
      const blob = await api('/api/export/current/pdf', {
        method: 'POST',
        body: State.currentSingleResult
      });
      downloadBlob(blob, `phishgraph-report-${State.currentSingleResult.host}.pdf`);
    } catch (e) {
      alert('PDF generation error: ' + e.message);
    }
  });

  // Batch Triage
  initBatchScanner();
}

function renderSingleResult(res) {
  State.currentSingleResult = res;
  $('result').hidden = false;

  // Composite Score & Verdict
  $('score').textContent = res.risk_score.toFixed(1);
  $('host').textContent = res.host;
  
  const badge = $('verdict-badge');
  badge.textContent = res.verdict;
  badge.className = 'badge ' + (
    res.verdict === 'High risk' ? 'badge-high' :
    res.verdict === 'Review needed' ? 'badge-review' : 'badge-low'
  );

  $('notice').textContent = res.notice;
  $('limited-support-banner').hidden = !res.limited_support;

  // Tri-evidence meters
  $('graph-value').textContent = res.graph_score.toFixed(1) + '%';
  $('graph-bar').style.width = Math.min(100, Math.max(0, res.graph_score)) + '%';

  $('lexical-value').textContent = res.lexical_score.toFixed(1) + '%';
  $('lexical-bar').style.width = Math.min(100, Math.max(0, res.lexical_score)) + '%';

  // Signals
  const signalsUl = $('signals-list');
  signalsUl.innerHTML = '';
  if (res.signals && res.signals.length) {
    res.signals.forEach(s => {
      const li = document.createElement('li');
      li.innerHTML = `<span>- ${escapeHtml(s.signal)}</span> <strong class="fine">+${s.weight}</strong>`;
      signalsUl.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.innerHTML = `<span class="muted">No selected lexical warning signals flagged.</span>`;
    signalsUl.appendChild(li);
  }

  // Draw Interactive Graph on both views (Scanner embedded & dedicated explorer)
  drawSvgGraph('interactive-graph', res, 'graph-viewport');
  drawSvgGraph('result-graph', res, 'result-graph-viewport');
  inspectGraphNode(res.graph_view.nodes[0], res);

  // Populate result-neighbors list
  const nList = $('result-neighbors');
  if (nList && res.neighbors) {
    nList.innerHTML = '';
    res.neighbors.forEach((n, idx) => {
      const p = document.createElement('div');
      p.className = 'neighbor-item fine mt-1';
      p.innerHTML = `<strong>N${idx+1}</strong> · ${escapeHtml(n.host)} · Sim: <strong class="text-cyan">${n.similarity}</strong> · <span class="badge ${n.seed_label === 1 ? 'badge-high' : (n.seed_label === 0 ? 'badge-low' : '')}">${escapeHtml(n.seed_status)}</span>`;
      nList.appendChild(p);
    });
  }

  // Populate result-rules
  const rRules = $('result-rules');
  if (rRules && res.rules) {
    rRules.innerHTML = '';
    res.rules.forEach(r => {
      const div = document.createElement('div');
      div.className = 'rule-item card mb-2';
      div.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>IF ${escapeHtml(r.rule)}</strong>
          <span class="badge ${r.consequent >= 0.65 ? 'badge-high' : (r.consequent >= 0.35 ? 'badge-review' : 'badge-low')}">
            z_k = ${(r.consequent * 100).toFixed(0)}/100
          </span>
        </div>
        <div class="fine mt-1">
          Activation w_i: <strong>${(r.activation * 100).toFixed(1)}%</strong> |
          Contribution: <strong>${(r.weighted_consequent * 100).toFixed(2)}</strong>
        </div>
      `;
      rRules.appendChild(div);
    });
  }

  // Populate result-features-tbody
  const rFeatures = $('result-features-tbody');
  if (rFeatures && res.feature_breakdown) {
    rFeatures.innerHTML = '';
    Object.entries(res.feature_breakdown).forEach(([key, info]) => {
      const tr = document.createElement('tr');
      const formattedVal = typeof info.value === 'number' ? (Number.isInteger(info.value) ? info.value : info.value.toFixed(4)) : info.value;
      tr.innerHTML = `
        <td><strong>${escapeHtml(info.title)}</strong></td>
        <td><strong class="font-mono text-cyan">${formattedVal}</strong></td>
        <td class="fine">${escapeHtml(info.rationale || info.desc)}</td>
      `;
      rFeatures.appendChild(tr);
    });
  }

  // Populate full Explainability section features & rules
  renderExplainabilityDetails(res);
}

// BATCH TRIAGE LOGIC
function initBatchScanner() {
  const dropZone = $('batch-drop-zone');
  const fileInput = $('batch-file-input');
  const browseBtn = $('batch-browse-btn');

  if (browseBtn) {
    browseBtn.addEventListener('click', e => {
      e.stopPropagation();
      fileInput.click();
    });
  }

  if (dropZone) {
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      if (e.dataTransfer.files?.length) handleBatchFile(e.dataTransfer.files[0]);
    });
  }

  fileInput.addEventListener('change', () => {
    if (fileInput.files?.length) handleBatchFile(fileInput.files[0]);
  });

  $('batch-clear-btn').addEventListener('click', () => {
    $('batch-textarea').value = '';
    $('batch-results-container').hidden = true;
    $('batch-error').hidden = true;
    State.batchResults = [];
  });

  $('batch-submit-btn').addEventListener('click', async () => {
    const raw = $('batch-textarea').value;
    const urls = raw.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (!urls.length) {
      showBatchError('Please paste at least one URL or upload a CSV file.');
      return;
    }

    $('batch-error').hidden = true;
    $('batch-submit-btn').disabled = true;
    $('batch-submit-btn').textContent = `Triageing ${urls.length} URLs…`;

    try {
      const out = await api('/api/predict/batch', {
        method: 'POST',
        body: { urls, save_history: true }
      });
      renderBatchResults(out);
    } catch (e) {
      showBatchError(e.message);
    } finally {
      $('batch-submit-btn').disabled = false;
      $('batch-submit-btn').textContent = 'Start Batch Triage 🚀';
    }
  });

  // Batch Filter & Search
  $('batch-search').addEventListener('input', applyBatchFilters);
  $('batch-risk-filter').addEventListener('change', applyBatchFilters);

  // Batch Exports
  $('batch-export-csv').addEventListener('click', async () => {
    if (!State.batchResults.length) return;
    try {
      const blob = await api('/api/export/batch/csv', {
        method: 'POST',
        body: { items: State.batchFiltered }
      });
      downloadBlob(blob, 'phishgraph_batch_analysis.csv');
    } catch (e) { alert(e.message); }
  });

  $('batch-export-pdf').addEventListener('click', async () => {
    if (!State.batchResults.length) return;
    try {
      const blob = await api('/api/export/batch/pdf', {
        method: 'POST',
        body: { items: State.batchFiltered, summary: {} }
      });
      downloadBlob(blob, 'phishgraph_batch_report.pdf');
    } catch (e) { alert(e.message); }
  });

  $('batch-export-json').addEventListener('click', () => {
    if (!State.batchResults.length) return;
    const blob = new Blob([JSON.stringify(State.batchFiltered, null, 2)], { type: 'application/json' });
    downloadBlob(blob, 'phishgraph_batch_analysis.json');
  });
}

function handleBatchFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    const text = e.target.result;
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const cleanUrls = [];
    for (const line of lines) {
      const clean = line.split(',')[0].replace(/^["']|["']$/g, '').trim();
      if (clean && !clean.toLowerCase().startsWith('url')) {
        cleanUrls.push(clean);
      }
    }
    $('batch-textarea').value = cleanUrls.slice(0, 200).join('\n');
    $('batch-error').hidden = true;
  };
  reader.readAsText(file);
}

function showBatchError(msg) {
  $('batch-error').textContent = msg;
  $('batch-error').hidden = false;
}

function renderBatchResults(out) {
  State.batchResults = out.items || [];
  State.batchFiltered = [...State.batchResults];
  $('batch-results-container').hidden = false;

  // Stats
  const total = State.batchResults.length;
  const nHigh = State.batchResults.filter(i => i.verdict === 'High risk').length;
  const nReview = State.batchResults.filter(i => i.verdict === 'Review needed').length;
  const nLow = State.batchResults.filter(i => i.verdict === 'Low risk').length;

  $('stat-batch-total').textContent = total;
  $('stat-batch-high').textContent = nHigh;
  $('stat-batch-review').textContent = nReview;
  $('stat-batch-low').textContent = nLow;
  $('batch-count-analyzed').textContent = total;

  // Errors Box
  const errBox = $('batch-errors-box');
  const errList = $('batch-errors-list');
  errList.innerHTML = '';
  if (out.errors && out.errors.length) {
    errBox.hidden = false;
    out.errors.slice(0, 5).forEach(err => {
      const li = document.createElement('li');
      li.textContent = `Row ${err.row}: ${err.input} (${err.error})`;
      errList.appendChild(li);
    });
  } else {
    errBox.hidden = true;
  }

  applyBatchFilters();
}

function applyBatchFilters() {
  const query = $('batch-search').value.trim().toLowerCase();
  const verdict = $('batch-risk-filter').value;

  State.batchFiltered = State.batchResults.filter(item => {
    const matchesQ = !query || item.host.toLowerCase().includes(query);
    const matchesV = verdict === 'all' || item.verdict === verdict;
    return matchesQ && matchesV;
  });

  const tbody = $('batch-tbody');
  tbody.innerHTML = '';

  if (!State.batchFiltered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted text-center">No matching URLs found.</td></tr>';
    return;
  }

  State.batchFiltered.forEach(item => {
    const tr = document.createElement('tr');
    const badgeClass = item.verdict === 'High risk' ? 'badge-high' :
                       (item.verdict === 'Review needed' ? 'badge-review' : 'badge-low');
    const topSig = item.signals?.length ? item.signals[0].signal : 'None';

    tr.innerHTML = `
      <td><strong>${escapeHtml(item.host)}</strong></td>
      <td><span class="font-mono">${item.risk_score.toFixed(1)}</span>/100</td>
      <td><span class="badge ${badgeClass}">${escapeHtml(item.verdict)}</span></td>
      <td>${item.graph_score.toFixed(1)}%</td>
      <td>${item.lexical_score.toFixed(1)}%</td>
      <td class="fine">${escapeHtml(topSig)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ============================================================================
// SECTION 02: INTERACTIVE GRAPH EXPLORER
// ============================================================================
function initGraphExplorer() {
  const zoomIn = $('graph-zoom-in');
  const zoomOut = $('graph-zoom-out');
  const zoomReset = $('graph-zoom-reset');

  if (zoomIn) zoomIn.addEventListener('click', () => updateGraphZoom(1.2, 'graph-viewport'));
  if (zoomOut) zoomOut.addEventListener('click', () => updateGraphZoom(0.8, 'graph-viewport'));
  if (zoomReset) zoomReset.addEventListener('click', () => resetGraphZoom('graph-viewport'));

  const rZoomIn = $('result-zoom-in');
  const rZoomOut = $('result-zoom-out');
  const rZoomReset = $('result-zoom-reset');

  if (rZoomIn) rZoomIn.addEventListener('click', () => updateGraphZoom(1.2, 'result-graph-viewport'));
  if (rZoomOut) rZoomOut.addEventListener('click', () => updateGraphZoom(0.8, 'result-graph-viewport'));
  if (rZoomReset) rZoomReset.addEventListener('click', () => resetGraphZoom('result-graph-viewport'));
}

function drawSvgGraph(svgElementId, res, viewportId) {
  const svg = $(svgElementId);
  if (!svg) return;
  svg.innerHTML = '';

  const gView = res?.graph_view;
  if (!gView || !gView.nodes) return;

  const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  g.id = viewportId;
  svg.appendChild(g);

  // Draw Edges
  gView.edges.forEach(edge => {
    const targetNode = gView.nodes.find(n => n.id === edge.target);
    if (!targetNode) return;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', 240);
    line.setAttribute('y1', 160);
    line.setAttribute('x2', targetNode.x);
    line.setAttribute('y2', targetNode.y);
    line.setAttribute('stroke-width', Math.max(1, edge.similarity * 5));
    line.setAttribute('stroke-opacity', Math.max(0.3, edge.similarity));
    g.appendChild(line);
  });

  // Draw Nodes
  gView.nodes.forEach(node => {
    const isQuery = node.id === 'query';
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', node.x);
    circle.setAttribute('cy', node.y);
    circle.setAttribute('r', isQuery ? 26 : 18);

    let fillColor = '#0ea5e9'; // query
    if (!isQuery) {
      if (node.type === 'seed_phish') fillColor = '#ef4444';
      else if (node.type === 'seed_benign') fillColor = '#10b981';
      else fillColor = '#64748b';
    }
    circle.setAttribute('fill', fillColor);
    circle.setAttribute('stroke', '#ffffff');
    circle.setAttribute('stroke-width', '1.5');
    circle.setAttribute('stroke-opacity', '0.6');

    // Node interaction
    circle.addEventListener('click', () => inspectGraphNode(node, res));
    circle.addEventListener('mouseenter', () => inspectGraphNode(node, res));

    g.appendChild(circle);

    // Text Label
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', node.x);
    text.setAttribute('y', node.y + (isQuery ? 4 : 3));
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('font-size', isQuery ? '10px' : '8.5px');
    text.setAttribute('font-weight', '700');
    text.setAttribute('fill', '#ffffff');
    text.textContent = isQuery ? 'Query' : node.label.slice(0, 9);
    g.appendChild(text);
  });
}

function inspectGraphNode(node, fullRes) {
  const hostEl = $('inspector-host');
  if (hostEl) hostEl.textContent = node.label;
  const isQuery = node.id === 'query';
  const typeEl = $('inspector-type');
  if (typeEl) typeEl.textContent = isQuery ? 'TARGET QUERY NODE' : 'NEIGHBORHOOD TRAINING NODE';

  const body = $('inspector-body');
  if (!body) return;
  if (isQuery) {
    body.innerHTML = `
      <div class="inspector-detail-grid">
        <div><strong>Verdict:</strong> ${escapeHtml(node.verdict)}</div>
        <div><strong>Risk Index:</strong> ${node.risk_score}/100</div>
        <div><strong>Feature Neighbors:</strong> 6 nearest training hosts displayed</div>
        <div><strong>Total Training Nodes:</strong> ${fullRes?.graph_view?.total_training_nodes || 363}</div>
      </div>
    `;
  } else {
    body.innerHTML = `
      <div class="inspector-detail-grid">
        <div><strong>RBF Manifold Similarity:</strong> ${node.similarity}</div>
        <div><strong>Feature Distance (||x - x_q||):</strong> ${node.distance}</div>
        <div><strong>Semi-Supervised Status:</strong> <span class="badge ${node.seed_label === 1 ? 'badge-high' : (node.seed_label === 0 ? 'badge-low' : '')}">${escapeHtml(node.status)}</span></div>
        <div><strong>Propagated Graph Score:</strong> ${(node.spread_score * 100).toFixed(1)}%</div>
      </div>
    `;
  }
}

function updateGraphZoom(delta, viewportId = 'graph-viewport') {
  State.graphTransforms[viewportId] = Math.min(3, Math.max(0.4, (State.graphTransforms[viewportId] || 1) * delta));
  const g = $(viewportId);
  if (g) {
    g.setAttribute('transform', `translate(260, 160) scale(${State.graphTransforms[viewportId]}) translate(-260, -160)`);
  }
}

function resetGraphZoom(viewportId = 'graph-viewport') {
  State.graphTransforms[viewportId] = 1;
  const g = $(viewportId);
  if (g) g.setAttribute('transform', 'scale(1)');
}

// ============================================================================
// SECTION 03: DETAILED EXPLAINABILITY & RULES
// ============================================================================
function renderExplainabilityDetails(res) {
  const tbody = $('features-tbody');
  if (tbody && res.feature_breakdown) {
    tbody.innerHTML = '';
    Object.entries(res.feature_breakdown).forEach(([key, info]) => {
      const tr = document.createElement('tr');
      const formattedVal = typeof info.value === 'number' ? (Number.isInteger(info.value) ? info.value : info.value.toFixed(4)) : info.value;
      tr.innerHTML = `
        <td><strong>${escapeHtml(info.title)}</strong><br><span class="fine font-mono">${escapeHtml(key)}</span></td>
        <td><strong class="font-mono text-cyan">${formattedVal}</strong></td>
        <td>
          <div>${escapeHtml(info.desc)}</div>
          <div class="fine text-muted mt-1"><em>Rationale:</em> ${escapeHtml(info.rationale)}</div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  const rulesList = $('explainability-rules-list');
  if (rulesList && res.rules) {
    rulesList.innerHTML = '';
    res.rules.forEach(r => {
      const div = document.createElement('div');
      div.className = 'rule-item card mb-2';
      div.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>IF ${escapeHtml(r.rule)}</strong>
          <span class="badge ${r.consequent >= 0.65 ? 'badge-high' : (r.consequent >= 0.35 ? 'badge-review' : 'badge-low')}">
            z_k = ${(r.consequent * 100).toFixed(0)}/100
          </span>
        </div>
        <div class="fine mt-1">
          Activation w_i: <strong>${(r.activation * 100).toFixed(1)}%</strong> | 
          Contribution: <strong>${(r.weighted_consequent * 100).toFixed(2)}</strong>
        </div>
      `;
      rulesList.appendChild(div);
    });
  }
}

// ============================================================================
// SECTION 04: FUZZY LOGIC PLAYGROUND
// ============================================================================
async function initFuzzyPlayground() {
  if (!State.fuzzyPlaygroundData) {
    try {
      State.fuzzyPlaygroundData = await api('/api/fuzzy/playground');
      drawFuzzyCanvas();
    } catch (e) { console.error('Playground init error:', e); }
  }

  const pGraph = $('play-graph');
  const pLex = $('play-lexical');

  if (pGraph) pGraph.addEventListener('input', updatePlaygroundSimulation);
  if (pLex) pLex.addEventListener('input', updatePlaygroundSimulation);

  const zDay = $('sim-zero-day');
  const imp = $('sim-impersonation');
  const blat = $('sim-blatant');
  const ben = $('sim-benign');

  if (zDay) zDay.addEventListener('click', () => setPlaygroundInputs(0.92, 0.10));
  if (imp) imp.addEventListener('click', () => setPlaygroundInputs(0.15, 0.88));
  if (blat) blat.addEventListener('click', () => setPlaygroundInputs(0.85, 0.90));
  if (ben) ben.addEventListener('click', () => setPlaygroundInputs(0.08, 0.05));

  updatePlaygroundSimulation();
}

function setPlaygroundInputs(g, l) {
  $('play-graph').value = g;
  $('play-lexical').value = l;
  updatePlaygroundSimulation();
}

async function updatePlaygroundSimulation() {
  const gEl = $('play-graph');
  const lEl = $('play-lexical');
  if (!gEl || !lEl) return;

  const g = parseFloat(gEl.value);
  const l = parseFloat(lEl.value);

  const gVal = $('play-graph-val');
  const lVal = $('play-lexical-val');
  if (gVal) gVal.textContent = (g * 100).toFixed(1) + '%';
  if (lVal) lVal.textContent = (l * 100).toFixed(1) + '%';

  try {
    const sim = await api(`/api/fuzzy/simulate?graph=${g}&lexical=${l}`);
    const scoreEl = $('play-composite-score');
    if (scoreEl) scoreEl.textContent = sim.risk_score.toFixed(1);
    
    const badge = $('play-composite-verdict');
    if (badge) {
      badge.textContent = sim.verdict;
      badge.className = 'badge ' + (
        sim.verdict === 'High risk' ? 'badge-high' :
        sim.verdict === 'Review needed' ? 'badge-review' : 'badge-low'
      );
    }

    const mathBox = $('play-math-breakdown');
    if (mathBox && sim.rules) {
      const totalW = sim.rules.reduce((sum, r) => sum + r.activation, 0);
      const weightedSum = sim.rules.reduce((sum, r) => sum + r.weighted_consequent, 0);
      mathBox.innerHTML = `
        Weighted Sum = <strong>${(weightedSum * 100).toFixed(2)}</strong> ÷ Weights = <strong>${totalW.toFixed(3)}</strong> → Output = <strong>${sim.risk_score.toFixed(2)} / 100</strong>
      `;
    }

    renderPlaygroundRuleMatrix(sim.rules || []);
    drawFuzzyCanvas(g, l);
  } catch (e) { console.error(e); }
}

function renderPlaygroundRuleMatrix(activeRules) {
  const container = $('play-rule-matrix');
  if (!container) return;
  container.innerHTML = '';
  const matrix = State.fuzzyPlaygroundData?.consequents_matrix || [[0.05, 0.25, 0.55], [0.30, 0.50, 0.75], [0.65, 0.85, 0.95]];
  const levels = ['Low', 'Med', 'High'];

  for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 3; j++) {
      const c = matrix[i][j];
      const match = activeRules.find(r => r.graph_level.toLowerCase() === levels[i].toLowerCase() &&
                                          r.lexical_level.toLowerCase() === levels[j].toLowerCase());
      const cell = document.createElement('div');
      cell.className = 'rule-matrix-cell' + (match ? ' active-rule' : '');
      cell.innerHTML = `
        <strong>G:${levels[i]} & L:${levels[j]}</strong>
        <div>z = ${(c * 100).toFixed(0)}</div>
        ${match ? `<div class="fine text-cyan mt-1">w = ${(match.activation * 100).toFixed(0)}%</div>` : ''}
      `;
      container.appendChild(cell);
    }
  }
}

function drawFuzzyCanvas(markerG = 0.5, markerL = 0.5) {
  const canvas = $('fuzzy-curves-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const pad = 24;
  const plotW = w - pad * 2;
  const plotH = h - pad * 2;

  // Grid
  ctx.strokeStyle = '#283548';
  ctx.lineWidth = 1;
  ctx.strokeRect(pad, pad, plotW, plotH);

  // Triangle curves: Low (green), Medium (amber), High (red)
  const drawCurve = (color, fn) => {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    for (let px = 0; px <= plotW; px++) {
      const x = px / plotW;
      const y = fn(x);
      const py = pad + plotH - y * plotH;
      if (px === 0) ctx.moveTo(pad + px, py);
      else ctx.lineTo(pad + px, py);
    }
    ctx.stroke();
  };

  drawCurve('#10b981', x => Math.max(0, 1 - 2 * x));
  drawCurve('#f59e0b', x => Math.max(0, 1 - Math.abs(2 * x - 1)));
  drawCurve('#ef4444', x => Math.max(0, 2 * x - 1));

  // Input markers
  const drawMarker = (val, color, label) => {
    const mx = pad + val * plotW;
    ctx.strokeStyle = color;
    ctx.setLineDash([4, 3]);
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(mx, pad);
    ctx.lineTo(mx, pad + plotH);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = color;
    ctx.font = '10px monospace';
    ctx.fillText(`${label}: ${val.toFixed(2)}`, mx + 4, pad + 14);
  };

  drawMarker(markerG, '#38bdf8', 'Graph');
  drawMarker(markerL, '#a855f7', 'Lexical');
}

// ============================================================================
// SECTION 05: MODEL EVALUATION & COMPARISON
// ============================================================================
async function loadMetrics() {
  try {
    const report = await api('/api/metrics');
    const titleEl = $('eval-dataset-title');
    if (titleEl) titleEl.textContent = `Benchmark Metrics (${report.dataset})`;
    const badgeEl = $('eval-synthetic-badge');
    if (badgeEl) badgeEl.hidden = !report.synthetic_demo;
    const noteEl = $('eval-methodology-note');
    if (noteEl) {
      noteEl.textContent = `
        ${report.synthetic_demo ? 'SYNTHETIC DEMO DATASET — NOT indicative of real-world accuracy. ' : ''}
        Evaluated on ${report.test_rows} held-out test URLs (${report.train_rows} training nodes, ${report.labeled_train_rows} visible labels).
        Holdout split isolates exact hostnames. Threshold = 0.50.
      `;
    }

    // Metrics Table
    const tbody = $('eval-metrics-tbody');
    if (tbody) {
      tbody.innerHTML = '';
      const models = report.models || {};
      const modelDisplayNames = {
        logistic_baseline: 'Logistic Regression (Baseline)',
        graph_ml: 'Graph ML (LabelSpreading RBF)',
        graph_plus_fuzzy: 'Graph ML + Sugeno Fuzzy Logic'
      };

      Object.entries(models).forEach(([key, m]) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${modelDisplayNames[key] || key}</strong></td>
          <td><strong class="text-cyan">${(m.accuracy * 100).toFixed(1)}%</strong></td>
          <td>${(m.precision * 100).toFixed(1)}%</td>
          <td>${(m.recall * 100).toFixed(1)}%</td>
          <td>${(m.f1 * 100).toFixed(1)}%</td>
          <td>${(m.roc_auc * 100).toFixed(1)}%</td>
        `;
        tbody.appendChild(tr);
      });
    }

    // Confusion Matrices
    const confGrid = $('confusion-matrices-container');
    if (confGrid) {
      confGrid.innerHTML = '';
      const models = report.models || {};
      const modelDisplayNames = {
        logistic_baseline: 'Logistic Regression',
        graph_ml: 'Graph ML (LabelSpreading)',
        graph_plus_fuzzy: 'Graph ML + Sugeno Fuzzy'
      };

      Object.entries(models).forEach(([key, m]) => {
        const cm = m.confusion_matrix || [[0, 0], [0, 0]];
        const card = document.createElement('div');
        card.className = 'matrix-card';
        card.innerHTML = `
          <h4>${modelDisplayNames[key] || key}</h4>
          <div class="matrix-2x2">
            <div class="matrix-cell">
              <div class="matrix-cell-val text-cyan">${cm[0][0]}</div>
              <div class="matrix-cell-lbl">True Benign (TN)</div>
            </div>
            <div class="matrix-cell">
              <div class="matrix-cell-val" style="color:var(--risk-high)">${cm[0][1]}</div>
              <div class="matrix-cell-lbl">False Phish (FP)</div>
            </div>
            <div class="matrix-cell">
              <div class="matrix-cell-val" style="color:var(--risk-high)">${cm[1][0]}</div>
              <div class="matrix-cell-lbl">False Benign (FN)</div>
            </div>
            <div class="matrix-cell">
              <div class="matrix-cell-val text-cyan">${cm[1][1]}</div>
              <div class="matrix-cell-lbl">True Phish (TP)</div>
            </div>
          </div>
        `;
        confGrid.appendChild(card);
      });
    }
  } catch (e) {
    console.error('Failed to load metrics:', e);
  }
}

// ============================================================================
// SECTION 06: TRAINING STUDIO & EXPERIMENTS
// ============================================================================
function initTraining() {
  const form = $('training-form');
  if (form) {
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const dataset_id = $('train-dataset-select').value;
      const gamma = parseFloat($('train-gamma').value);
      const alpha = parseFloat($('train-alpha').value);
      const unlabel_ratio = parseFloat($('train-unlabel').value);
      const seed = parseInt($('train-seed').value);
      const version = $('train-version').value.trim() || undefined;

      try {
        await api('/api/training/start', {
          method: 'POST',
          body: { dataset_id, gamma, alpha, unlabel_ratio, seed, version }
        });
        startTrainingPoller();
      } catch (err) {
        alert('Training launch error: ' + err.message);
      }
    });
  }
}

function startTrainingPoller() {
  if (State.trainingInterval) clearInterval(State.trainingInterval);
  State.trainingInterval = setInterval(loadTrainingStatus, 1500);
  loadTrainingStatus();
}

async function loadTrainingStatus() {
  try {
    const job = await api('/api/training/status');
    const badge = $('training-badge');
    const badgeText = $('training-badge-text');

    if (job.status === 'running') {
      if (badge) badge.className = 'training-pill pill-running';
      if (badgeText) badgeText.textContent = `Training… (${job.duration}s)`;
      const durEl = $('train-duration-badge');
      if (durEl) durEl.textContent = `${job.duration}s`;
      const btn = $('train-start-btn');
      if (btn) btn.disabled = true;
    } else {
      if (badge) badge.className = 'training-pill pill-idle';
      if (badgeText) badgeText.textContent = job.status === 'completed' ? 'Trainer Idle (Ready)' : 'Trainer Idle';
      const btn = $('train-start-btn');
      if (btn) btn.disabled = false;
      if (State.trainingInterval && job.status !== 'running') {
        clearInterval(State.trainingInterval);
        State.trainingInterval = null;
        loadExperiments();
      }
    }

    if (job.logs && job.logs.length) {
      const stream = $('train-log-stream');
      if (stream) {
        stream.textContent = job.logs.join('\n');
        stream.scrollTop = stream.scrollHeight;
      }
    }
  } catch (e) { console.error(e); }
}

async function loadExperiments() {
  try {
    const experiments = await api('/api/experiments');
    const tbody = $('experiments-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!experiments.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted text-center">No experiments recorded yet.</td></tr>';
      return;
    }

    experiments.forEach(exp => {
      const tr = document.createElement('tr');
      const acc = exp.metrics?.graph_plus_fuzzy?.accuracy;
      const accStr = acc !== undefined ? `${(acc * 100).toFixed(1)}%` : '—';

      tr.innerHTML = `
        <td><strong class="font-mono">${escapeHtml(exp.id)}</strong></td>
        <td><span class="pill pill-idle">${escapeHtml(exp.version)}</span></td>
        <td>${escapeHtml(exp.dataset)}</td>
        <td>${exp.duration_seconds}s</td>
        <td><strong class="text-cyan">${accStr}</strong></td>
        <td><span class="badge ${exp.status === 'completed' ? 'badge-low' : 'badge-high'}">${exp.status}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" data-exp-id="${escapeHtml(exp.id)}">
            Activate
          </button>
        </td>
      `;
      tr.querySelector('button').addEventListener('click', () => {
        window.activateModelExperiment(exp.id);
      });
      tbody.appendChild(tr);
    });
  } catch (e) { console.error(e); }
}

window.activateModelExperiment = async function(expId) {
  try {
    const res = await api('/api/experiments/activate', {
      method: 'POST',
      body: { experiment_id: expId }
    });
    alert(`Model activated successfully: ${res.version}`);
    initHealthCheck();
  } catch (e) {
    alert('Model activation failed: ' + e.message);
  }
};

async function loadDatasetsDropdown() {
  try {
    const datasets = await api('/api/datasets');
    const select = $('train-dataset-select');
    if (!select) return;
    select.innerHTML = '';
    datasets.forEach(ds => {
      const opt = document.createElement('option');
      opt.value = ds.id;
      opt.textContent = `${ds.filename} (${ds.unique_valid_urls} URLs, ${ds.is_synthetic ? 'Synthetic' : 'User Upload'})`;
      select.appendChild(opt);
    });
  } catch (e) { console.error(e); }
}

// ============================================================================
// SECTION 07: DATASET MANAGEMENT
// ============================================================================
function initDatasetManager() {
  const form = $('dataset-upload-form');
  const fileInput = $('dataset-file-input');
  const browseBtn = $('dataset-browse-btn');
  const dropZone = $('dataset-drop-zone');

  if (browseBtn) {
    browseBtn.addEventListener('click', e => {
      e.stopPropagation();
      fileInput.click();
    });
  }

  if (dropZone) {
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      if (e.dataTransfer.files?.length) {
        fileInput.files = e.dataTransfer.files;
        $('dataset-chosen-name').textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size/1024).toFixed(1)} KB)`;
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length) {
        $('dataset-chosen-name').textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size/1024).toFixed(1)} KB)`;
      }
    });
  }

  if (form) {
    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (!fileInput.files.length) {
        $('dataset-upload-error').textContent = 'Please choose a CSV file first.';
        $('dataset-upload-error').hidden = false;
        return;
      }

      $('dataset-upload-error').hidden = true;
      $('dataset-upload-success').hidden = true;
      $('dataset-upload-btn').disabled = true;
      $('dataset-upload-btn').textContent = 'Validating on server…';

      const formData = new FormData(form);
      try {
        const res = await fetch('/api/datasets/upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Upload validation failed');

        $('dataset-upload-success').textContent = `Dataset validated & saved! ${data.unique_valid_urls} unique URLs (${data.class_distribution.benign_count} benign, ${data.class_distribution.phishing_count} phish).`;
        $('dataset-upload-success').hidden = false;
        form.reset();
        $('dataset-chosen-name').textContent = '';
        loadDatasetsTable();
        loadDatasetsDropdown();
      } catch (err) {
        $('dataset-upload-error').textContent = err.message;
        $('dataset-upload-error').hidden = false;
      } finally {
        $('dataset-upload-btn').disabled = false;
        $('dataset-upload-btn').textContent = 'Validate & Register Dataset 📥';
      }
    });
  }
}

async function loadDatasetsTable() {
  try {
    const list = await api('/api/datasets');
    const tbody = $('datasets-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    list.forEach(ds => {
      const tr = document.createElement('tr');
      const ratio = ds.class_distribution?.phishing_ratio ? `${(ds.class_distribution.phishing_ratio * 100).toFixed(0)}% phish` : '50%';
      tr.innerHTML = `
        <td><strong>${escapeHtml(ds.filename)}</strong></td>
        <td>${ds.unique_valid_urls}</td>
        <td>${ratio}</td>
        <td class="fine">${escapeHtml(ds.source_note || '—')}</td>
        <td class="fine font-mono">${(ds.sha256 || '').slice(0, 10)}…</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) { console.error(e); }
}

// ============================================================================
// SECTION 08: SEARCHABLE ANALYSIS HISTORY
// ============================================================================
function initHistory() {
  const sInput = $('history-search-input');
  const vSelect = $('history-verdict-select');
  const tSelect = $('history-type-select');
  const prevBtn = $('history-prev-page');
  const nextBtn = $('history-next-page');
  const clearBtn = $('clear-history-btn');

  if (sInput) sInput.addEventListener('input', () => { State.historyPage = 1; loadHistory(); });
  if (vSelect) vSelect.addEventListener('change', () => { State.historyPage = 1; loadHistory(); });
  if (tSelect) tSelect.addEventListener('change', () => { State.historyPage = 1; loadHistory(); });

  if (prevBtn) prevBtn.addEventListener('click', () => {
    if (State.historyPage > 1) { State.historyPage--; loadHistory(); }
  });
  if (nextBtn) nextBtn.addEventListener('click', () => {
    State.historyPage++;
    loadHistory();
  });

  if (clearBtn) clearBtn.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to clear all analysis history?')) return;
    try {
      await api('/api/history', { method: 'DELETE', body: {} });
      loadHistory();
    } catch (e) { alert(e.message); }
  });

  // Drawer Close Handlers
  const closeBtn = $('drawer-close-btn');
  const closeBottomBtn = $('drawer-close-bottom-btn');
  const drawerBackdrop = $('detail-drawer');

  if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
  if (closeBottomBtn) closeBottomBtn.addEventListener('click', closeDrawer);
  if (drawerBackdrop) {
    drawerBackdrop.addEventListener('click', e => {
      if (e.target === drawerBackdrop) closeDrawer();
    });
  }

  // Keyboard shortcut: Escape to close drawer and mobile navigation
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeDrawer();
      closeMobileNav();
    }
  });
}

async function loadHistory() {
  const sInput = $('history-search-input');
  const vSelect = $('history-verdict-select');
  const tSelect = $('history-type-select');

  const q = sInput ? sInput.value.trim() : '';
  const verdict = vSelect ? vSelect.value : 'all';
  const scan_type = tSelect ? tSelect.value : 'all';

  try {
    const data = await api(`/api/history?page=${State.historyPage}&per_page=15&q=${encodeURIComponent(q)}&verdict=${encodeURIComponent(verdict)}&scan_type=${encodeURIComponent(scan_type)}`);
    const tbody = $('history-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const items = data.items || [];
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="muted text-center">No analysis history found.</td></tr>';
      $('history-pagination-info').textContent = 'Showing 0-0 of 0';
      $('history-prev-page').disabled = true;
      $('history-next-page').disabled = true;
      return;
    }

    $('history-pagination-info').textContent = `Showing ${(data.page-1)*data.per_page + 1}-${Math.min(data.page*data.per_page, data.total)} of ${data.total}`;
    $('history-prev-page').disabled = data.page <= 1;
    $('history-next-page').disabled = data.page >= data.total_pages;

    items.forEach(row => {
      const tr = document.createElement('tr');
      const badgeClass = row.verdict === 'High risk' ? 'badge-high' :
                         (row.verdict === 'Review needed' ? 'badge-review' : 'badge-low');
      tr.innerHTML = `
        <td><strong>${escapeHtml(row.host)}</strong></td>
        <td><span class="font-mono">${row.risk.toFixed(1)}</span>/100</td>
        <td><span class="badge ${badgeClass}">${escapeHtml(row.verdict)}</span></td>
        <td>${row.graph_score?.toFixed(1) || 0}%</td>
        <td>${row.lexical_score?.toFixed(1) || 0}%</td>
        <td><span class="pill pill-idle">${escapeHtml(row.model_version || 'v1-demo')}</span></td>
        <td class="fine">${escapeHtml(row.created)}</td>
        <td style="white-space:nowrap;">
          <button class="btn btn-ghost btn-sm btn-inspect" data-id="${row.id}">Details</button>
          <a href="/report/single/${row.id}" target="_blank" class="btn btn-ghost btn-sm">Report ↗</a>
          <button class="btn btn-ghost btn-sm text-danger btn-del" data-id="${row.id}">✕</button>
        </td>
      `;
      tr.querySelector('.btn-inspect').addEventListener('click', () => window.openScanDrawer(row.id));
      tr.querySelector('.btn-del').addEventListener('click', () => window.deleteHistoryItem(row.id));
      tbody.appendChild(tr);
    });
  } catch (e) { console.error('Failed to load history:', e); }
}

window.openScanDrawer = async function(scanId) {
  try {
    const item = await api(`/api/history/${scanId}`);
    if (!item) throw new Error('Scan record not found');

    const hostEl = $('drawer-host');
    if (hostEl) hostEl.textContent = item.host || 'Analysis Record';

    const body = $('drawer-body');
    if (!body) return;

    const riskVal = typeof item.risk === 'number' ? item.risk : (parseFloat(item.risk) || 0);
    const graphVal = typeof item.graph_score === 'number' ? item.graph_score : (parseFloat(item.graph_score) || 0);
    const lexicalVal = typeof item.lexical_score === 'number' ? item.lexical_score : (parseFloat(item.lexical_score) || 0);
    const verdict = item.verdict || (riskVal >= 65 ? 'High risk' : (riskVal >= 35 ? 'Review needed' : 'Low risk'));

    const badgeClass = verdict === 'High risk' ? 'badge-high' :
                       (verdict === 'Review needed' ? 'badge-review' : 'badge-low');

    const signals = Array.isArray(item.signals) ? item.signals : [];

    body.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span class="eyebrow">RISK VERDICT</span>
          <div style="margin-top:4px;"><span class="badge ${badgeClass}">${escapeHtml(verdict)}</span></div>
        </div>
        <div style="text-align:right;">
          <span class="eyebrow">SCORE</span>
          <div class="score-number" style="font-size:32px;">${riskVal.toFixed(1)}</div>
        </div>
      </div>

      <div class="card mt-3">
        <h4>Scores Breakdown</h4>
        <div class="mt-2">Graph ML: <strong>${graphVal.toFixed(1)}%</strong></div>
        <div class="mt-1">Lexical Risk: <strong>${lexicalVal.toFixed(1)}%</strong></div>
        <div class="mt-1 fine text-muted">Model: ${escapeHtml(item.model_version || 'v1-demo')} | Type: ${escapeHtml(item.scan_type || 'single')}</div>
      </div>

      <div class="card mt-3">
        <h4>Extracted Signals (${signals.length})</h4>
        <ul style="padding-left:18px; margin-top:8px;">
          ${signals.map(s => {
            const sigName = typeof s === 'object' && s.signal ? s.signal : String(s);
            const sigWeight = typeof s === 'object' && s.weight !== undefined ? ` (+${s.weight})` : '';
            return `<li>${escapeHtml(sigName)}${sigWeight}</li>`;
          }).join('') || '<li class="muted">No security warnings triggered</li>'}
        </ul>
      </div>
    `;

    const pdfBtn = $('drawer-pdf-btn');
    if (pdfBtn) {
      pdfBtn.onclick = async () => {
        try {
          const blob = await api(`/api/export/single/pdf/${scanId}`);
          downloadBlob(blob, `phishgraph_scan_${item.host || 'record'}.pdf`);
        } catch (err) {
          alert('Could not download PDF report: ' + err.message);
        }
      };
    }

    openDrawer();
  } catch (e) {
    console.error('Failed to load scan record:', e);
    alert('Unable to load scan record: ' + e.message);
  }
};

window.deleteHistoryItem = async function(scanId) {
  if (!confirm('Delete this historical scan record?')) return;
  try {
    await api(`/api/history/${scanId}`, { method: 'DELETE', body: {} });
    loadHistory();
  } catch (e) { alert(e.message); }
};

// ============================================================================
// SECTION 09: GUIDED DEMO & VIVA NOTES
// ============================================================================
async function loadDemoContent() {
  try {
    const data = await api('/api/demo/samples');
    
    // Curated exemplars
    const grid = $('demo-exemplars-grid');
    if (grid) {
      grid.innerHTML = '';
      data.samples.forEach(s => {
        const card = document.createElement('div');
        card.className = 'exemplar-card';
        const badgeClass = s.category === 'High risk' ? 'badge-high' :
                           (s.category === 'Review needed' ? 'badge-review' : 'badge-low');
        card.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="badge ${badgeClass}">${s.category}</span>
            <span class="fine">${s.expected_band}</span>
          </div>
          <h4 style="margin:8px 0 4px;">${escapeHtml(s.title)}</h4>
          <p class="fine">${escapeHtml(s.description)}</p>
          <div class="host-pill mt-2 font-mono">${escapeHtml(s.url)}</div>
          <button class="btn btn-primary btn-sm btn-block mt-3">Test This Scenario ↗</button>
        `;
        card.querySelector('button').addEventListener('click', e => {
          e.stopPropagation();
          executeScan(s.url, true, false);
        });
        card.addEventListener('click', () => {
          executeScan(s.url, true, false);
        });
        grid.appendChild(card);
      });
    }

    // Viva Glossary
    const gloss = $('demo-glossary-list');
    if (gloss) {
      gloss.innerHTML = '';
      data.glossary.forEach(g => {
        const item = document.createElement('div');
        item.className = 'glossary-item';
        item.innerHTML = `
          <strong>${escapeHtml(g.term)}</strong>
          <p class="fine mt-1">${escapeHtml(g.definition)}</p>
        `;
        gloss.appendChild(item);
      });
    }
  } catch (e) { console.error(e); }
}

// ============================================================================
// FEATURE UPGRADE 01: SPECTRAL GRAPH & HOMOPHILY ANALYTICS
// ============================================================================
async function loadSpectralMetrics() {
  try {
    const data = await api('/api/graph/spectral');
    const hEl = $('spectral-homophily');
    const cEl = $('spectral-clustering');
    const dEl = $('spectral-degree');
    const tEl = $('spectral-trace');
    const expText = $('spectral-explanation-text');

    if (hEl) hEl.textContent = `${data.homophily_index}%`;
    if (cEl) cEl.textContent = data.average_clustering_coefficient;
    if (dEl) dEl.textContent = data.mean_degree;
    if (tEl) tEl.textContent = data.spectral_laplacian_trace;
    if (expText) expText.textContent = data.theoretical_takeaway || data.homophily_evaluation;
  } catch (e) {
    console.error('Failed to load spectral graph metrics:', e);
  }
}

function initSpectralAnalytics() {
  const btn = $('btn-refresh-spectral');
  if (btn) btn.addEventListener('click', loadSpectralMetrics);
}

// ============================================================================
// FEATURE UPGRADE 02: ADAPTIVE FUZZY PROFILE TUNER
// ============================================================================
function initFuzzyProfileTuner() {
  const presetSel = $('fuzzy-preset-select');
  const saveBtn = $('btn-save-fuzzy-profile');

  const presets = {
    balanced: [[0.05, 0.25, 0.55], [0.30, 0.50, 0.75], [0.65, 0.85, 0.95]],
    aggressive: [[0.10, 0.40, 0.70], [0.45, 0.70, 0.90], [0.80, 0.95, 0.99]],
    conservative: [[0.02, 0.15, 0.45], [0.15, 0.40, 0.65], [0.50, 0.75, 0.90]]
  };

  const populateInputs = matrix => {
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        const input = $(`rule-${i}-${j}`);
        if (input) input.value = matrix[i][j];
      }
    }
  };

  if (presetSel) {
    presetSel.addEventListener('change', () => {
      const p = presets[presetSel.value];
      if (p) populateInputs(p);
    });
  }

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const matrix = [];
      for (let i = 0; i < 3; i++) {
        const row = [];
        for (let j = 0; j < 3; j++) {
          row.push(parseFloat($(`rule-${i}-${j}`)?.value || 0.5));
        }
        matrix.push(row);
      }

      try {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving…';
        const res = await api('/api/fuzzy/profile', {
          method: 'POST',
          body: { matrix, profile_name: presetSel ? presetSel.value : 'custom' }
        });
        const msg = $('fuzzy-profile-msg');
        if (msg) {
          msg.textContent = `Fuzzy profile '${res.profile?.active_profile}' applied successfully!`;
          msg.hidden = false;
          setTimeout(() => { msg.hidden = true; }, 4000);
        }
        updatePlaygroundSimulation();
      } catch (err) {
        alert('Failed to save fuzzy profile: ' + err.message);
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Apply Custom Rule Profile';
      }
    });
  }
}

// ============================================================================
// FEATURE UPGRADE 03: ADVERSARIAL EVASION LAB
// ============================================================================
async function runAdversarialSimulation() {
  const input = $('adv-url-input');
  if (!input) return;
  const url = input.value.trim();
  if (!url) return;

  const btn = $('btn-run-adv');
  if (btn) { btn.disabled = true; btn.textContent = 'Testing Mutations…'; }

  try {
    const res = await api('/api/adversarial/simulate', {
      method: 'POST',
      body: { url }
    });

    $('adv-results-container').hidden = false;
    $('adv-resilience-score').textContent = res.resilience_score;
    $('adv-baseline-risk').textContent = `${res.baseline_risk.toFixed(1)}/100`;
    $('adv-mean-shift').textContent = `±${res.mean_absolute_shift}`;
    $('adv-caught-ratio').textContent = res.evasion_caught_ratio;

    const badge = $('adv-resilience-badge');
    if (badge) {
      badge.textContent = res.defense_rating;
      badge.className = 'badge ' + (
        res.resilience_score >= 80 ? 'badge-low' :
        (res.resilience_score >= 55 ? 'badge-review' : 'badge-high')
      );
    }

    const tbody = $('adv-simulations-tbody');
    if (tbody) {
      tbody.innerHTML = '';
      res.simulations.forEach(sim => {
        const tr = document.createElement('tr');
        const shiftColor = sim.delta_shift > 0 ? 'var(--risk-high)' : (sim.delta_shift < 0 ? 'var(--risk-low)' : 'var(--text-main)');
        const statusBadgeClass = sim.caught ? 'badge-low' : 'badge-high';

        tr.innerHTML = `
          <td><strong>${escapeHtml(sim.tactic_name)}</strong><br><span class="fine font-mono">${escapeHtml(sim.tactic_id)}</span></td>
          <td><span class="fine">${escapeHtml(sim.category)}</span></td>
          <td><div class="font-mono fine" style="max-width:280px; word-break:break-all;">${escapeHtml(sim.mutated_url)}</div></td>
          <td><strong class="font-mono">${sim.mutated_risk.toFixed(1)}</strong>/100</td>
          <td><strong style="color:${shiftColor}">${sim.delta_shift > 0 ? '+' : ''}${sim.delta_shift}</strong></td>
          <td><span class="badge ${statusBadgeClass}">${escapeHtml(sim.resilience_status)}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    alert('Adversarial simulation error: ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Evasion Tests ⚔️'; }
  }
}

function initAdversarialLab() {
  const btn = $('btn-run-adv');
  if (btn) btn.addEventListener('click', runAdversarialSimulation);
}

// ============================================================================
// FEATURE UPGRADE 04: BRAND IMPERSONATION & HOMOGRAPH RADAR
// ============================================================================
async function runBrandRadarAnalysis(overrideUrl) {
  const input = $('brand-url-input');
  const targetUrl = overrideUrl || (input ? input.value.trim() : '');
  if (!targetUrl) return;
  if (input) input.value = targetUrl;

  const btn = $('btn-run-brand');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning Radar…'; }

  try {
    const [brandRes, homoRes] = await Promise.all([
      api('/api/brand/analyze', { method: 'POST', body: { url: targetUrl } }),
      api('/api/homograph/analyze', { method: 'POST', body: { url: targetUrl } })
    ]);

    $('brand-results-container').hidden = false;

    // Brand card
    const bTitle = $('brand-target-title');
    const bBadge = $('brand-severity-badge');
    const bBody = $('brand-card-body');

    if (brandRes.is_impersonating) {
      if (bTitle) bTitle.textContent = `Target: ${brandRes.top_brand}`;
      if (bBadge) {
        bBadge.textContent = brandRes.risk_rating;
        bBadge.className = 'badge ' + (brandRes.risk_rating === 'Critical' ? 'badge-high' : 'badge-review');
      }
      if (bBody) {
        bBody.innerHTML = `
          <div class="meter-head">
            <span>Impersonation Similarity:</span>
            <strong class="text-cyan">${brandRes.impersonation_score}%</strong>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill fill-graph" style="width:${brandRes.impersonation_score}%"></div></div>
          
          <div class="card mt-3" style="background:var(--bg-base);">
            <div><strong>Official Domain:</strong> <span class="font-mono text-cyan">${escapeHtml(brandRes.official_domain)}</span></div>
            <div class="mt-1"><strong>Industry Category:</strong> ${escapeHtml(brandRes.top_category)}</div>
            <div class="fine mt-2 text-muted">${escapeHtml(brandRes.matches[0]?.explanation || '')}</div>
          </div>
        `;
      }
    } else {
      if (bTitle) bTitle.textContent = 'No Brand Impersonation';
      if (bBadge) { bBadge.textContent = 'Neutral'; bBadge.className = 'badge badge-low'; }
      if (bBody) {
        bBody.innerHTML = `<p class="fine text-muted">No unauthorized tokens or typosquats matching top 20 monitored global financial/tech institutions were detected.</p>`;
      }
    }

    // Homograph card
    const hBadge = $('homograph-severity-badge');
    const hBody = $('homograph-card-body');

    if (hBadge) {
      hBadge.textContent = homoRes.threat_level;
      hBadge.className = 'badge ' + (
        homoRes.has_homoglyphs ? 'badge-high' :
        (homoRes.is_punycode ? 'badge-review' : 'badge-low')
      );
    }

    if (hBody) {
      if (homoRes.has_homoglyphs) {
        hBody.innerHTML = `
          <div>Canonical Latin Target: <strong class="font-mono text-cyan">${escapeHtml(homoRes.canonical_latin_target)}</strong></div>
          <div class="mt-1 fine text-muted">${escapeHtml(homoRes.summary)}</div>
          
          <div class="table-scroll mt-3">
            <table class="data-table">
              <thead><tr><th>Char</th><th>Code Point</th><th>Script</th><th>Confusable With</th></tr></thead>
              <tbody>
                ${homoRes.flagged_characters.map(c => `
                  <tr>
                    <td><strong class="font-mono text-cyan">${escapeHtml(c.char)}</strong></td>
                    <td class="font-mono fine">${escapeHtml(c.code_point)}</td>
                    <td>${escapeHtml(c.script)}</td>
                    <td><strong>${escapeHtml(c.confusable_with)}</strong> (Latin)</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `;
      } else {
        hBody.innerHTML = `
          <div class="fine">Scripts Detected: <strong>${escapeHtml(homoRes.scripts_observed.join(', '))}</strong></div>
          <div class="fine mt-1">Punycode Encoding: <strong>${homoRes.is_punycode ? 'Yes (' + escapeHtml(homoRes.original_host) + ')' : 'No (Standard ASCII)'}</strong></div>
          <div class="callout callout-info mt-3"><p class="fine">${escapeHtml(homoRes.summary)}</p></div>
        `;
      }
    }

  } catch (err) {
    alert('Brand radar error: ' + err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan Brand Threats 🎯'; }
  }
}

function initBrandRadar() {
  const btn = $('btn-run-brand');
  if (btn) btn.addEventListener('click', () => runBrandRadarAnalysis());

  $$('[data-brand-preset]').forEach(btnPreset => {
    btnPreset.addEventListener('click', () => {
      runBrandRadarAnalysis(btnPreset.dataset.brandPreset);
    });
  });
}

// ============================================================================
// FEATURE UPGRADE 05: CAMPAIGN CLUSTERING
// ============================================================================
async function runCampaignClustering() {
  const btn = $('btn-run-clustering');
  if (btn) { btn.disabled = true; btn.textContent = 'Clustering Graphs…'; }

  try {
    const res = await api('/api/campaigns/cluster', { method: 'POST', body: {} });
    $('campaigns-results-container').hidden = false;
    $('stat-campaign-count').textContent = res.cluster_count;
    $('stat-campaign-clustered').textContent = res.total_items;

    const grid = $('campaigns-grid');
    if (grid) {
      grid.innerHTML = '';
      if (!res.clusters.length) {
        grid.innerHTML = '<p class="muted">No campaign families detected in current batch.</p>';
        return;
      }
      res.clusters.forEach(c => {
        const card = document.createElement('div');
        card.className = 'exemplar-card';
        card.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="badge ${c.average_risk >= 65 ? 'badge-high' : 'badge-review'}">${escapeHtml(c.cluster_id)}</span>
            <span class="fine">Avg Risk: ${c.average_risk}/100</span>
          </div>
          <h4 style="margin:8px 0 4px;">Top Host: ${escapeHtml(c.representative_host)}</h4>
          <p class="fine">Threat Density: <strong>${escapeHtml(c.threat_density)}</strong> | Dominant TLD: <strong>.${escapeHtml(c.dominant_tld)}</strong></p>
          <div class="fine text-muted mt-2">Kit Member Count: <strong>${c.size} related domains</strong></div>
        `;
        grid.appendChild(card);
      });
    }
  } catch (e) {
    alert('Campaign clustering error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Discover Threat Families 🔍'; }
  }
}

function initCampaignClustering() {
  const btn = $('btn-run-clustering');
  if (btn) btn.addEventListener('click', runCampaignClustering);
}

// ============================================================================
// FEATURE UPGRADE 06: SOC ALERT TRIAGE & THREAT INTEL
// ============================================================================
async function loadSocQueue() {
  try {
    const queue = await api('/api/soc/triage?status=all');
    const tbody = $('soc-triage-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!queue.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted text-center">No alerts in triage queue. Run some scans first.</td></tr>';
      return;
    }

    queue.forEach(item => {
      const tr = document.createElement('tr');
      const badgeClass = item.verdict === 'High risk' ? 'badge-high' :
                         (item.verdict === 'Review needed' ? 'badge-review' : 'badge-low');
      const currentStatus = item.triage_status || 'Unreviewed';

      tr.innerHTML = `
        <td><strong>${escapeHtml(item.host)}</strong></td>
        <td><span class="font-mono">${item.risk.toFixed(1)}</span>/100</td>
        <td><span class="badge ${badgeClass}">${escapeHtml(item.verdict)}</span></td>
        <td>
          <select class="select-sm soc-status-select" data-id="${item.id}">
            <option value="Unreviewed" ${currentStatus==='Unreviewed'?'selected':''}>Unreviewed</option>
            <option value="Confirmed Phishing" ${currentStatus==='Confirmed Phishing'?'selected':''}>Confirmed Phishing</option>
            <option value="False Positive" ${currentStatus==='False Positive'?'selected':''}>False Positive</option>
            <option value="Escalated" ${currentStatus==='Escalated'?'selected':''}>Escalated to CIRT</option>
            <option value="Blocked" ${currentStatus==='Blocked'?'selected':''}>Blocked on Firewall</option>
          </select>
        </td>
        <td><input type="text" class="input-sm soc-notes-input" style="width:140px;" placeholder="Analyst notes…" value="${escapeHtml(item.triage_notes || '')}" data-id="${item.id}"></td>
        <td>
          <button class="btn btn-secondary btn-sm btn-view-pack" data-id="${item.id}">Playbook 📁</button>
        </td>
      `;

      tr.querySelector('.soc-status-select').addEventListener('change', async e => {
        const notes = tr.querySelector('.soc-notes-input').value;
        await api('/api/soc/triage', {
          method: 'POST',
          body: { scan_id: item.id, status: e.target.value, notes }
        });
      });

      tr.querySelector('.btn-view-pack').addEventListener('click', () => viewSocPack(item.id));
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Failed to load SOC queue:', e);
  }
}

async function viewSocPack(scanId) {
  try {
    const pack = await api(`/api/soc/pack/${scanId}`);
    $('soc-pack-card').hidden = false;
    $('soc-pack-host').textContent = pack.host;
    $('soc-pack-priority').textContent = pack.priority;
    $('soc-pack-priority').className = 'badge ' + (
      pack.verdict === 'High risk' ? 'badge-high' :
      (pack.verdict === 'Review needed' ? 'badge-review' : 'badge-low')
    );

    // MITRE grid
    const mitreGrid = $('soc-mitre-grid');
    if (mitreGrid) {
      mitreGrid.innerHTML = '';
      pack.mitre_mappings.forEach(m => {
        const div = document.createElement('div');
        div.className = 'method-step-card';
        div.innerHTML = `
          <span class="step-badge">${escapeHtml(m.technique_id)} · ${escapeHtml(m.tactic)}</span>
          <h4>${escapeHtml(m.name)}</h4>
          <p class="fine mt-1">${escapeHtml(m.mitigation)}</p>
        `;
        mitreGrid.appendChild(div);
      });
    }

    // Rules
    $('soc-rule-suricata').textContent = pack.firewall_rules.suricata;
    $('soc-rule-iptables').textContent = pack.firewall_rules.iptables;
    $('soc-rule-cisco').textContent = pack.firewall_rules.cisco;

    $('soc-pack-card').scrollIntoView({ behavior: 'smooth' });
  } catch (err) {
    alert('Failed to load SOC pack: ' + err.message);
  }
}

function initSocThreatIntel() {
  const exportStixBtn = $('btn-export-stix');
  const exportIocBtn = $('btn-export-openioc');
  const dispatchWebhookBtn = $('btn-dispatch-webhook');

  if (exportStixBtn) {
    exportStixBtn.addEventListener('click', async () => {
      try {
        const blob = await api('/api/export/stix', { method: 'POST', body: {} });
        downloadBlob(blob, 'phishgraph_stix21_feed.json');
      } catch (e) { alert(e.message); }
    });
  }

  if (exportIocBtn) {
    exportIocBtn.addEventListener('click', async () => {
      try {
        const blob = await api('/api/export/openioc', { method: 'POST', body: {} });
        downloadBlob(blob, 'phishgraph_ioc_blocklist.ioc');
      } catch (e) { alert(e.message); }
    });
  }

  if (dispatchWebhookBtn) {
    dispatchWebhookBtn.addEventListener('click', async () => {
      try {
        dispatchWebhookBtn.disabled = true;
        dispatchWebhookBtn.textContent = 'Signing & Dispatching…';
        const res = await api('/api/api-console/simulate-webhook', { method: 'POST', body: {} });
        $('webhook-response-box').hidden = false;
        $('webhook-json-output').textContent = JSON.stringify(res, null, 2);
      } catch (e) {
        alert('Webhook error: ' + e.message);
      } finally {
        dispatchWebhookBtn.disabled = false;
        dispatchWebhookBtn.textContent = 'Dispatch Simulated Webhook 🚀';
      }
    });
  }
}

// ============================================================================
// GLOBAL HEALTH CHECK & INIT
// ============================================================================
async function initHealthCheck() {
  try {
    const health = await api('/api/health');
    const nameEl = $('sidebar-model-name');
    if (nameEl) nameEl.textContent = health.model_version || 'LabelSpreading';
    const indEl = $('demo-indicator');
    if (indEl) {
      indEl.textContent = health.demo ? 'SYNTHETIC DEMO MODEL' : 'PRODUCTION LABELED';
      indEl.className = 'pill ' + (health.demo ? 'pill-warning' : 'badge-low');
    }
  } catch (e) {
    console.error('Health check failed:', e);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Document Ready Bootstrap
document.addEventListener('DOMContentLoaded', () => {
  closeDrawer();
  initNavigation();
  initScanner();
  initGraphExplorer();
  initFuzzyPlayground();
  initTraining();
  initDatasetManager();
  initHistory();
  initHealthCheck();
  loadMetrics();
  initSpectralAnalytics();
  initFuzzyProfileTuner();
  initAdversarialLab();
  initBrandRadar();
  initCampaignClustering();
  initSocThreatIntel();

  // Execute silent scan of demo URL on startup so dashboard opens fully populated
  executeScan('https://cedar12.test/catalog/item/12', false, true);
});
