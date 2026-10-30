/**
 * AegisFlow Main Application Frontend Logic
 */

let currentTab = 'overview';
let leafletMap = null;
let leafletFlowLayer = null;
let ws = null;

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  initClock();
  initWebSocket();
  loadOverview();
  pollAttackStatus();
  registerPWA();

  // Auto-refresh data every 10 seconds
  setInterval(() => {
    refreshCurrentTab();
  }, 10000);
});

function registerPWA() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/static/sw.js').catch(() => {});
  }
}

function toggleMobileSidebar() {
  const sidebar = document.getElementById('app-sidebar');
  if (sidebar) {
    sidebar.classList.toggle('-translate-x-full');
  }
}

function initClock() {
  const clockEl = document.getElementById('live-clock');
  setInterval(() => {
    const now = new Date();
    clockEl.innerText = now.toUTCString().split(' ')[4] + ' UTC';
  }, 1000);
}

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/live`;
  try {
    ws = new WebSocket(wsUrl);
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'KPI_TICK') {
          updateKpis(msg.data);
        } else if (msg.type === 'ATTACK_TICK') {
          updateAttackStatusUI(msg.data);
        }
      } catch (e) { }
    };
    ws.onclose = () => {
      setTimeout(initWebSocket, 5000);
    };
  } catch (e) { }
}

function switchTab(tabId) {
  currentTab = tabId;

  // Update nav buttons
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.className = "nav-btn w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium transition text-slate-400 hover:text-white hover:bg-slate-800/60";
  });
  const activeBtn = document.getElementById(`nav-${tabId}`);
  if (activeBtn) {
    activeBtn.className = "nav-btn w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium transition text-white bg-cyan-600/20 border border-cyan-500/30";
  }

  // Hide all tabs, show selected
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
  const activePane = document.getElementById(`tab-${tabId}`);
  if (activePane) activePane.classList.remove('hidden');

  // Close mobile sidebar on tab selection
  const sidebar = document.getElementById('app-sidebar');
  if (sidebar && !sidebar.classList.contains('-translate-x-full')) {
    sidebar.classList.add('-translate-x-full');
  }

  // Trigger tab-specific loaders and resize charts
  setTimeout(() => {
    if (tabId === 'overview') loadOverview();
    else if (tabId === 'upstreams') { loadUpstreamData(); loadMultiParameterFlows('IP_TO_IP'); }
    else if (tabId === 'pattern') loadPatternStudio();
    else if (tabId === 'top-talkers') loadTopTalkers();
    else if (tabId === 'peering') loadPeering();
    else if (tabId === 'interfaces') loadInterfaces();
    else if (tabId === 'geomap') loadGeoMap();
    else if (tabId === 'security') loadSecurity();
    else if (tabId === 'qos') loadQoS();
    else if (tabId === 'capacity') loadCapacityForecast();
    else if (tabId === 'billing') loadBilling();
    else if (tabId === 'reports') loadReports();
    else if (tabId === 'devices') loadDevicesList();
    else if (tabId === 'explorer') queryRawFlows();

    window.dispatchEvent(new Event('resize'));
  }, 50);
}

function refreshCurrentTab() {
  switchTab(currentTab);
}

// ================= LOADERS =================

async function loadOverview() {
  try {
    const [kpiRes, tsRes, appsRes] = await Promise.all([
      fetch('/api/v1/overview?minutes=60'),
      fetch('/api/v1/throughput-timeseries?minutes=60'),
      fetch('/api/v1/applications?limit=6&minutes=60')
    ]);

    const kpi = await kpiRes.json();
    const timeseries = await tsRes.json();
    const apps = await appsRes.json();

    updateKpis(kpi);
    updateThroughputChart(timeseries);
    updateAppPieChart(apps);

    // Direction breakdown synthetic/cached
    updateDirectionPieChart([
      { name: 'North-South Outbound', value: 55 },
      { name: 'North-South Inbound', value: 25 },
      { name: 'East-West Internal', value: 15 },
      { name: 'External Transit', value: 5 }
    ]);
  } catch (e) {
    console.error('Failed to load overview:', e);
  }
}

function updateKpis(kpi) {
  if (!kpi) return;
  const gbps = (kpi.avg_gbps || 0).toFixed(2);
  document.getElementById('kpi-mbps').innerText = `${gbps} Gbps`;
  document.getElementById('kpi-pps').innerText = `${Math.round((kpi.avg_pps || 0) / 1000)} kpps`;
  document.getElementById('kpi-flows').innerText = (kpi.total_flows || 0).toLocaleString();
  document.getElementById('kpi-devices').innerText = (kpi.active_devices || 1000).toLocaleString();
}

async function loadTopTalkers() {
  try {
    const [srcRes, dstRes, convRes] = await Promise.all([
      fetch('/api/v1/top-talkers/sources?limit=8&minutes=60'),
      fetch('/api/v1/top-talkers/destinations?limit=8&minutes=60'),
      fetch('/api/v1/conversations?limit=12&minutes=60')
    ]);

    const sources = await srcRes.json();
    const destinations = await dstRes.json();
    const convs = await convRes.json();

    // Render Sources
    const srcTbody = document.getElementById('table-top-sources');
    srcTbody.innerHTML = sources.map(s => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2 text-cyan-400 font-semibold">${s.src_ip}</td>
        <td class="py-2 text-slate-300">${s.src_country} · ${s.src_as_name || 'AS'}</td>
        <td class="py-2 text-slate-400">${s.src_cloud}</td>
        <td class="py-2 text-right text-emerald-400 font-bold">${s.mbps} Mbps</td>
        <td class="py-2 text-right text-slate-400">${formatBytes(s.bytes)}</td>
      </tr>
    `).join('') || '<tr><td colspan="5" class="py-3 text-center text-slate-500">No data</td></tr>';

    // Render Destinations
    const dstTbody = document.getElementById('table-top-destinations');
    dstTbody.innerHTML = destinations.map(d => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2 text-blue-400 font-semibold">${d.dst_ip}</td>
        <td class="py-2 text-slate-300">${d.dst_country} · ${d.dst_as_name || 'AS'}</td>
        <td class="py-2 text-slate-400">${d.dst_cloud}</td>
        <td class="py-2 text-right text-emerald-400 font-bold">${d.mbps} Mbps</td>
        <td class="py-2 text-right text-slate-400">${formatBytes(d.bytes)}</td>
      </tr>
    `).join('') || '<tr><td colspan="5" class="py-3 text-center text-slate-500">No data</td></tr>';

    // Render Conversations
    const convTbody = document.getElementById('table-conversations');
    convTbody.innerHTML = convs.map(c => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2 text-cyan-400">${c.src_ip} <span class="text-slate-500">(${c.src_country})</span></td>
        <td class="py-2 text-blue-400">${c.dst_ip} <span class="text-slate-500">(${c.dst_country})</span></td>
        <td class="py-2 text-slate-200"><span class="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[11px]">${c.application}</span></td>
        <td class="py-2 text-slate-400">${c.protocol === 6 ? 'TCP' : (c.protocol === 17 ? 'UDP' : 'ICMP')} / ${c.dst_port}</td>
        <td class="py-2"><span class="text-[10px] px-1.5 py-0.5 rounded ${c.flow_direction.includes('East-West') ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-400'}">${c.flow_direction}</span></td>
        <td class="py-2 text-right text-emerald-400 font-semibold">${c.mbps} Mbps</td>
        <td class="py-2 text-right text-slate-400">${(c.packets || 0).toLocaleString()}</td>
      </tr>
    `).join('') || '<tr><td colspan="7" class="py-3 text-center text-slate-500">No data</td></tr>';

  } catch (e) {
    console.error('Failed to load top talkers:', e);
  }
}

async function loadPeering() {
  try {
    const [matrixRes, summaryRes] = await Promise.all([
      fetch('/api/v1/peering/matrix?limit=15&minutes=60'),
      fetch('/api/v1/peering/summary?minutes=60')
    ]);

    const matrix = await matrixRes.json();
    const summary = await summaryRes.json();

    updatePeeringRatioChart(summary.categories || []);

    const tbody = document.getElementById('table-asn-matrix');
    tbody.innerHTML = matrix.map(m => {
      const isCandidate = m.peering_candidate;
      return `
        <tr class="hover:bg-slate-800/40 font-mono">
          <td class="py-2.5 text-slate-300">AS${m.src_as} <span class="text-slate-500">(${m.src_as_name})</span></td>
          <td class="py-2.5 text-cyan-400 font-semibold">AS${m.dst_as} <span class="text-slate-400">(${m.dst_as_name})</span></td>
          <td class="py-2.5"><span class="px-2 py-0.5 rounded text-[10px] ${m.dst_as_category.includes('Peering') ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'}">${m.dst_as_category}</span></td>
          <td class="py-2.5 text-right font-semibold">${m.mbps} Mbps</td>
          <td class="py-2.5 text-right text-slate-300">$${(m.monthly_transit_cost_usd || 0).toLocaleString()} /mo</td>
          <td class="py-2.5 text-center">
            ${isCandidate ? `
              <span class="px-2 py-1 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[11px] font-semibold">
                <i class="fa-solid fa-handshake mr-1"></i> Peer via IXP
              </span>
            ` : `
              <span class="text-slate-500 text-[11px]">Transit Required</span>
            `}
          </td>
        </tr>
      `;
    }).join('') || '<tr><td colspan="6" class="py-4 text-center text-slate-500">No ASN traffic recorded</td></tr>';

  } catch (e) {
    console.error('Failed to load peering:', e);
  }
}

async function loadInterfaces() {
  try {
    const [utilRes, siteRes] = await Promise.all([
      fetch('/api/v1/interfaces/utilization?limit=30&minutes=15'),
      fetch('/api/v1/site-to-site?minutes=60')
    ]);

    const utils = await utilRes.json();
    const sites = await siteRes.json();

    updateSiteToSiteChart(sites);

    const tbody = document.getElementById('table-interface-util');
    tbody.innerHTML = utils.map(u => {
      const pct = u.utilization_pct;
      const isSaturated = u.status === 'SATURATED';
      const isWarning = u.status === 'WARNING';
      const barColor = isSaturated ? 'bg-red-500' : (isWarning ? 'bg-amber-500' : 'bg-cyan-500');
      const badgeClass = isSaturated ? 'bg-red-500/20 text-red-400 border-red-500/30' : (isWarning ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30');

      return `
        <tr class="hover:bg-slate-800/40">
          <td class="py-2.5 font-semibold text-slate-200">${u.device_name}</td>
          <td class="py-2.5"><span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300">${u.vendor}</span></td>
          <td class="py-2.5 text-slate-400">${u.site}</td>
          <td class="py-2.5 text-cyan-400">${u.if_name}</td>
          <td class="py-2.5 text-slate-400 text-[11px] truncate max-w-xs">${u.if_alias}</td>
          <td class="py-2.5 font-bold text-slate-300">${u.speed_readable}</td>
          <td class="py-2.5 text-right font-semibold">${u.current_in_mbps} Mbps</td>
          <td class="py-2.5">
            <div class="flex items-center space-x-2">
              <div class="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden">
                <div class="${barColor} h-2 rounded-full transition-all" style="width: ${Math.min(100, pct)}%"></div>
              </div>
              <span class="text-[11px] font-bold w-12 text-right">${pct}%</span>
            </div>
          </td>
          <td class="py-2.5 text-center">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">${u.status}</span>
          </td>
        </tr>
      `;
    }).join('') || '<tr><td colspan="9" class="py-4 text-center text-slate-500">No interface flows</td></tr>';

  } catch (e) {
    console.error('Failed to load interfaces:', e);
  }
}

async function loadGeoMap() {
  if (!leafletMap) {
    leafletMap = L.map('leaflet-map').setView([25, 10], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
      subdomains: 'abcd',
      maxZoom: 19
    }).addTo(leafletMap);
    leafletFlowLayer = L.layerGroup().addTo(leafletMap);
  }

  try {
    const res = await fetch('/api/v1/geomap?minutes=30');
    const flows = await res.json();
    leafletFlowLayer.clearLayers();

    flows.forEach(f => {
      if (f.src_lat && f.src_lon && f.dst_lat && f.dst_lon) {
        // Source Marker
        L.circleMarker([f.src_lat, f.src_lon], {
          radius: 5,
          color: '#06b6d4',
          fillColor: '#06b6d4',
          fillOpacity: 0.8
        }).bindPopup(`<b>${f.src_city}, ${f.src_country}</b><br/>Transmitted: ${formatBytes(f.bytes)}`).addTo(leafletFlowLayer);

        // Destination Marker
        L.circleMarker([f.dst_lat, f.dst_lon], {
          radius: 6,
          color: '#3b82f6',
          fillColor: '#3b82f6',
          fillOpacity: 0.8
        }).bindPopup(`<b>${f.dst_city}, ${f.dst_country}</b>`).addTo(leafletFlowLayer);

        // Flow Line Arc
        L.polyline([[f.src_lat, f.src_lon], [f.dst_lat, f.dst_lon]], {
          color: '#06b6d4',
          weight: 1.5,
          opacity: 0.5,
          dashArray: '5, 8'
        }).addTo(leafletFlowLayer);
      }
    });

    leafletMap.invalidateSize();
  } catch (e) {
    console.error('Failed to load geomap:', e);
  }
}

async function loadSecurity() {
  try {
    const [ddosRes, anomRes] = await Promise.all([
      fetch('/api/v1/security/ddos?window_minutes=15'),
      fetch('/api/v1/security/anomalies?window_minutes=15')
    ]);

    const attacks = await ddosRes.json();
    const anomalies = await anomRes.json();

    document.getElementById('sec-ddos-count').innerText = attacks.length;
    const lateralCount = anomalies.filter(a => a.category.includes('Lateral')).length;
    const scanCount = anomalies.filter(a => a.category.includes('Scan')).length;
    document.getElementById('sec-lateral-count').innerText = lateralCount;
    document.getElementById('sec-scan-count').innerText = scanCount;

    // Active Attack Cards
    const cardsEl = document.getElementById('ddos-attack-cards');
    if (attacks.length === 0) {
      cardsEl.innerHTML = `
        <div class="p-6 text-center text-slate-500 font-mono text-xs rounded-lg border border-slate-800 bg-slate-900/30">
          <i class="fa-solid fa-circle-check text-emerald-400 text-lg mb-2"></i>
          <div>NO VOLUMETRIC ATTACKS DETECTED</div>
          <div class="text-[11px] text-slate-600 mt-1">Normal baseline traffic thresholds intact</div>
        </div>
      `;
    } else {
      cardsEl.innerHTML = attacks.map(att => `
        <div class="p-4 rounded-xl border border-red-500/40 bg-red-950/20 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div class="space-y-1">
            <div class="flex items-center space-x-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/30 text-red-400 border border-red-500/50">${att.severity}</span>
              <span class="text-sm font-bold text-white">${att.attack_type}</span>
              <span class="text-xs text-slate-400">Target: <strong class="text-cyan-400 font-mono">${att.target_ip}</strong></span>
            </div>
            <p class="text-xs text-slate-300 font-mono">${att.description}</p>
            <div class="text-[11px] text-slate-400">
              Metric: <strong class="text-red-400">${att.metric_value} ${att.unit}</strong> (Threshold: ${att.threshold} ${att.unit})
            </div>
          </div>
          <div class="flex flex-col sm:flex-row items-start sm:items-center gap-2">
            <button onclick="deployMitigation('${att.alert_id}', 'BGP_FLOWSPEC')" class="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs flex items-center space-x-1.5 shadow-lg shadow-red-600/30 transition">
              <i class="fa-solid fa-shield"></i>
              <span>Deploy BGP Flowspec</span>
            </button>
            <button onclick="deployMitigation('${att.alert_id}', 'RTBH')" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition">
              <span>Trigger RTBH Blackhole</span>
            </button>
          </div>
        </div>
        ${att.bgp_flowspec_rule ? `
          <div class="bg-black/40 border border-slate-800 p-3 rounded-lg text-[11px] font-mono text-emerald-400 overflow-x-auto">
            <div class="text-slate-500 text-[10px] mb-1">// Generated RFC 5575 BGP Flowspec Filter:</div>
            <pre>${att.bgp_flowspec_rule}</pre>
          </div>
        ` : ''}
      `).join('');
    }

    // Anomalies Table
    const tbody = document.getElementById('table-security-anomalies');
    tbody.innerHTML = anomalies.map(a => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2.5 text-slate-400">${new Date(a.timestamp * 1000).toLocaleTimeString()}</td>
        <td class="py-2.5 text-slate-200"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700">${a.category}</span></td>
        <td class="py-2.5"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${a.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' : 'bg-red-500/20 text-red-400'}">${a.severity}</span></td>
        <td class="py-2.5 text-cyan-400 font-semibold">${a.source_ip}</td>
        <td class="py-2.5 text-blue-400 font-semibold">${a.target_ip}</td>
        <td class="py-2.5 text-slate-300 text-[11px]">${a.description}</td>
        <td class="py-2.5 text-center"><span class="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-bold">DETECTED</span></td>
      </tr>
    `).join('') || '<tr><td colspan="7" class="py-4 text-center text-slate-500">No anomalies detected</td></tr>';

  } catch (e) {
    console.error('Failed to load security:', e);
  }
}

async function deployMitigation(alertId, action) {
  try {
    const res = await fetch(`/api/v1/security/mitigate?alert_id=${alertId}&action=${action}`, { method: 'POST' });
    const data = await res.json();
    showToast(data.message, 'success');
    refreshCurrentTab();
  } catch (e) {
    showToast('Mitigation dispatch failed', 'error');
  }
}

// ================= CYBER THREAT & DDOS ATTACK SIMULATOR =================

let currentAttackStatus = { active: false };

async function pollAttackStatus() {
  try {
    const res = await fetch('/api/v1/simulate/attack/status');
    const data = await res.json();
    updateAttackStatusUI(data);
  } catch (e) { }
}

function updateAttackStatusUI(status) {
  currentAttackStatus = status || { active: false };
  const isActive = !!currentAttackStatus.active;

  // 1. Top Header button
  const btnHeaderStart = document.getElementById('btn-header-attack');
  const btnHeaderStop = document.getElementById('btn-header-stop-attack');
  if (btnHeaderStart && btnHeaderStop) {
    if (isActive) {
      btnHeaderStart.classList.add('hidden');
      btnHeaderStop.classList.remove('hidden');
      btnHeaderStop.innerHTML = `<i class="fa-solid fa-circle-stop mr-1.5 animate-pulse"></i><span>Stop Attack (${Number(currentAttackStatus.current_mbps || 0).toLocaleString()} Mbps)</span>`;
    } else {
      btnHeaderStart.classList.remove('hidden');
      btnHeaderStop.classList.add('hidden');
    }
  }

  // 2. Security Tab Console Controls
  const badgeSecStatus = document.getElementById('sec-attack-badge');
  const btnStart = document.getElementById('btn-sec-start-attack');
  const btnStop = document.getElementById('btn-sec-stop-attack');
  const liveBanner = document.getElementById('sec-attack-live-banner');

  if (badgeSecStatus) {
    if (isActive) {
      badgeSecStatus.className = "px-2.5 py-1 rounded bg-red-600/30 text-red-400 border border-red-500/50 text-xs font-mono font-bold flex items-center space-x-1.5 animate-pulse";
      badgeSecStatus.innerHTML = `<span class="w-2 h-2 rounded-full bg-red-500"></span><span>● ATTACK ACTIVE: ${currentAttackStatus.target_ip} (${currentAttackStatus.protocol})</span>`;
    } else {
      badgeSecStatus.className = "px-2.5 py-1 rounded bg-slate-800 text-slate-400 text-xs font-mono font-bold";
      badgeSecStatus.innerText = "● SYSTEM IDLE";
    }
  }

  if (btnStart) {
    btnStart.disabled = isActive;
    if (isActive) {
      btnStart.className = "px-4 py-2 rounded-lg bg-slate-800 text-slate-500 cursor-not-allowed text-xs font-bold flex items-center space-x-1.5";
    } else {
      btnStart.className = "px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs flex items-center space-x-1.5 shadow-lg shadow-red-600/30 transition cursor-pointer";
    }
  }

  if (btnStop) {
    btnStop.disabled = !isActive;
    if (isActive) {
      btnStop.className = "px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs flex items-center space-x-1.5 shadow-lg shadow-amber-600/30 transition cursor-pointer";
    } else {
      btnStop.className = "px-4 py-2 rounded-lg bg-slate-800 text-slate-600 cursor-not-allowed text-xs font-bold flex items-center space-x-1.5 border border-slate-700/50";
    }
  }

  // 3. Live metrics banner
  if (liveBanner) {
    if (isActive) {
      liveBanner.classList.remove('hidden');
      const elTarget = document.getElementById('live-atk-target');
      if (elTarget) elTarget.innerText = currentAttackStatus.target_ip;
      const elProto = document.getElementById('live-atk-proto');
      if (elProto) elProto.innerText = `${currentAttackStatus.protocol} (Port ${currentAttackStatus.target_port})`;
      const elRate = document.getElementById('live-atk-rate');
      if (elRate) elRate.innerText = `${Number(currentAttackStatus.current_mbps || 0).toLocaleString()} Mbps`;
      const elPps = document.getElementById('live-atk-pps');
      if (elPps) elPps.innerText = `${(currentAttackStatus.current_pps || 0).toLocaleString()} PPS`;
      const elPkts = document.getElementById('live-atk-pkts');
      if (elPkts) elPkts.innerText = `${(currentAttackStatus.total_packets || 0).toLocaleString()}`;
      const elTime = document.getElementById('live-atk-time');
      if (elTime) elTime.innerText = formatAttackTimer(currentAttackStatus.elapsed_seconds || 0);
    } else {
      liveBanner.classList.add('hidden');
    }
  }

  // 4. Modal controls (if open)
  const modalBtnStart = document.getElementById('btn-modal-start-attack');
  const modalBtnStop = document.getElementById('btn-modal-stop-attack');
  if (modalBtnStart && modalBtnStop) {
    modalBtnStart.disabled = isActive;
    modalBtnStop.disabled = !isActive;
    if (isActive) {
      modalBtnStart.className = "px-4 py-2 rounded-lg bg-slate-800 text-slate-500 cursor-not-allowed text-xs font-bold";
      modalBtnStop.className = "px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs shadow-lg transition";
    } else {
      modalBtnStart.className = "px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow-lg shadow-red-600/30 transition";
      modalBtnStop.className = "px-4 py-2 rounded-lg bg-slate-800 text-slate-600 cursor-not-allowed text-xs font-bold";
    }
  }
}

function formatAttackTimer(sec) {
  const m = Math.floor(sec / 60).toString().padStart(2, '0');
  const s = Math.floor(sec % 60).toString().padStart(2, '0');
  return `${m}:${s}`;
}

function setAttackTarget(ip, label) {
  const input = document.getElementById('atk-target-ip');
  if (input) input.value = ip;
  const modalInput = document.getElementById('modal-atk-target-ip');
  if (modalInput) modalInput.value = ip;
  showToast(`Selected target victim: ${ip} (${label})`, 'info');
}

function onAttackProtocolChange(proto) {
  const portInput = document.getElementById('atk-target-port');
  const modalPortInput = document.getElementById('modal-atk-target-port');
  let defaultPort = 443;
  if (proto === 'UDP_DNS') defaultPort = 53;
  else if (proto === 'UDP_NTP') defaultPort = 123;
  else if (proto === 'HTTP') defaultPort = 80;
  else if (proto === 'LATERAL') defaultPort = 445;
  else if (proto === 'ICMP') defaultPort = 0;

  if (portInput) portInput.value = defaultPort;
  if (modalPortInput) modalPortInput.value = defaultPort;
}

async function startSimulatedAttack(fromModal = false) {
  const targetIp = (fromModal ? document.getElementById('modal-atk-target-ip')?.value : document.getElementById('atk-target-ip')?.value) || '10.0.1.50';
  const protocol = (fromModal ? document.getElementById('modal-atk-protocol')?.value : document.getElementById('atk-protocol')?.value) || 'TCP_SYN';
  const targetPort = (fromModal ? document.getElementById('modal-atk-target-port')?.value : document.getElementById('atk-target-port')?.value) || 443;
  const intensity = (fromModal ? document.getElementById('modal-atk-intensity')?.value : document.getElementById('atk-intensity')?.value) || 'high';

  try {
    const res = await fetch('/api/v1/simulate/attack/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_ip: targetIp,
        protocol: protocol,
        target_port: parseInt(targetPort),
        intensity: intensity
      })
    });
    const data = await res.json();
    updateAttackStatusUI(data.campaign);
    showToast(data.message, 'warning');
    if (fromModal) closeAttackConsoleModal();
    switchTab('security');
  } catch (e) {
    showToast('Failed to start attack campaign', 'error');
  }
}

async function stopSimulatedAttack() {
  try {
    const res = await fetch('/api/v1/simulate/attack/stop', { method: 'POST' });
    const data = await res.json();
    updateAttackStatusUI(data.campaign);
    showToast(data.message, 'success');
    if (currentTab === 'security') {
      setTimeout(loadSecurity, 600);
    }
  } catch (e) {
    showToast('Failed to stop attack campaign', 'error');
  }
}

function openAttackConsoleModal() {
  const modal = document.getElementById('modal-attack-console');
  if (modal) modal.classList.remove('hidden');
}

function closeAttackConsoleModal() {
  const modal = document.getElementById('modal-attack-console');
  if (modal) modal.classList.add('hidden');
}

// Legacy alias
function triggerSimulatedAttack() {
  openAttackConsoleModal();
}

async function loadQoS() {
  try {
    const [breakdownRes, complianceRes] = await Promise.all([
      fetch('/api/v1/qos/breakdown?minutes=60'),
      fetch('/api/v1/qos/compliance?minutes=60')
    ]);

    const breakdown = await breakdownRes.json();
    const compliance = await complianceRes.json();

    updateQosChart(breakdown);

    const badge = document.getElementById('badge-qos-status');
    if (compliance.compliant) {
      badge.className = "px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-xs font-semibold border border-emerald-500/20";
      badge.innerText = "All CBQoS Policies Compliant";
    } else {
      badge.className = "px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 text-xs font-semibold border border-amber-500/30";
      badge.innerText = "Voice/BGP Tagging Violations Detected";
    }

    const tbody = document.getElementById('table-qos-breakdown');
    tbody.innerHTML = breakdown.map(q => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2.5 text-cyan-400 font-semibold">${q.dscp_name} (DSCP ${q.dscp})</td>
        <td class="py-2.5 text-slate-300">${q.qos_class}</td>
        <td class="py-2.5 text-slate-400">${q.dscp === 46 ? 'Mission Critical Voice (EF)' : (q.dscp === 34 ? 'Interactive Video (AF41)' : 'General Traffic')}</td>
        <td class="py-2.5 text-right font-bold text-slate-200">${q.mbps} Mbps</td>
        <td class="py-2.5 text-right text-emerald-400 font-semibold">${q.percentage}%</td>
      </tr>
    `).join('') || '<tr><td colspan="5" class="py-4 text-center text-slate-500">No QoS data</td></tr>';

  } catch (e) {
    console.error('Failed to load QoS:', e);
  }
}

async function loadCapacityForecast() {
  const devSelect = document.getElementById('select-capacity-device');
  const devId = devSelect ? devSelect.value : 'dev-0001';

  try {
    const res = await fetch(`/api/v1/capacity/forecast?device_id=${devId}&in_ifindex=1`);
    const forecast = await res.json();

    document.getElementById('cap-speed').innerText = `${forecast.speed_mbps / 1000} Gbps`;
    document.getElementById('cap-current-peak').innerText = `${(forecast.current_peak_mbps / 1000).toFixed(2)} Gbps`;
    document.getElementById('cap-days-85').innerText = `${forecast.estimated_days_to_85_pct} Days`;
    document.getElementById('cap-exhaust-date').innerText = forecast.exhaustion_forecast_date;

    updateCapacityChart(forecast);
  } catch (e) {
    console.error('Failed to load capacity:', e);
  }
}

async function loadBilling() {
  try {
    const [p95Res, cbRes] = await Promise.all([
      fetch('/api/v1/billing/p95?days=30'),
      fetch('/api/v1/billing/chargebacks?days=30')
    ]);

    const p95 = await p95Res.json();
    const chargebacks = await cbRes.json();

    document.getElementById('bill-p95').innerText = `${(p95.p95_mbps / 1000).toFixed(2)} Gbps`;
    document.getElementById('bill-total-tb').innerText = `${p95.total_transfer_tb} TB`;
    document.getElementById('bill-invoice-usd').innerText = `$${(p95.estimated_invoice_usd || 0).toLocaleString()}`;

    const tbody = document.getElementById('table-chargebacks');
    tbody.innerHTML = chargebacks.map(cb => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2.5 text-cyan-400 font-semibold">${cb.tenant_or_group}</td>
        <td class="py-2.5 text-right text-slate-300 font-bold">${cb.transfer_tb} TB</td>
        <td class="py-2.5 text-right text-slate-400">$${cb.rate_per_tb_usd} / TB</td>
        <td class="py-2.5 text-right text-emerald-400 font-bold">$${(cb.chargeback_cost_usd || 0).toLocaleString()}</td>
      </tr>
    `).join('') || '<tr><td colspan="4" class="py-4 text-center text-slate-500">No chargebacks</td></tr>';

  } catch (e) {
    console.error('Failed to load billing:', e);
  }
}

async function loadDevicesList() {
  const vendorFilter = document.getElementById('filter-device-vendor').value;
  try {
    const url = `/api/v1/devices?limit=150${vendorFilter ? '&vendor=' + vendorFilter : ''}`;
    const res = await fetch(url);
    const data = await res.json();

    const tbody = document.getElementById('table-devices-list');
    tbody.innerHTML = data.devices.map(d => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2 text-cyan-400">${d.device_id}</td>
        <td class="py-2 font-semibold text-slate-200">${d.hostname}</td>
        <td class="py-2 text-slate-300">${d.ip}</td>
        <td class="py-2"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${getVendorBadgeClass(d.vendor)}">${d.vendor}</span></td>
        <td class="py-2 text-slate-400">${d.model}</td>
        <td class="py-2 text-slate-300">${d.role}</td>
        <td class="py-2 text-slate-400">${d.site}</td>
        <td class="py-2 text-slate-300 font-semibold">${d.flow_protocol}</td>
        <td class="py-2 text-slate-400">1 : ${d.sampling_rate}</td>
        <td class="py-2 text-center"><span class="w-2 h-2 inline-block rounded-full bg-emerald-500 mr-1"></span> ONLINE</td>
      </tr>
    `).join('') || '<tr><td colspan="10" class="py-4 text-center text-slate-500">No devices found</td></tr>';

  } catch (e) {
    console.error('Failed to load devices:', e);
  }
}

function getVendorBadgeClass(vendor) {
  if (vendor === 'Auto-Discovered') return 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold';
  if (vendor === 'Cisco') return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
  if (vendor === 'Juniper') return 'bg-purple-500/20 text-purple-400 border border-purple-500/30';
  if (vendor === 'Huawei') return 'bg-red-500/20 text-red-400 border border-red-500/30';
  if (vendor === 'Nokia') return 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30';
  if (vendor === 'ZTE') return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
  if (vendor === 'MikroTik') return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
  return 'bg-slate-800 text-slate-400';
}

async function queryRawFlows() {
  const src = document.getElementById('filter-src-ip').value;
  const dst = document.getElementById('filter-dst-ip').value;
  const proto = document.getElementById('filter-proto').value;
  const dscp = document.getElementById('filter-dscp').value;

  const params = new URLSearchParams();
  params.set('limit', '50');
  if (src) params.set('src_ip', src);
  if (dst) params.set('dst_ip', dst);
  if (proto) params.set('protocol', proto);
  if (dscp) params.set('dscp', dscp);

  try {
    const res = await fetch(`/api/v1/raw-flows?${params.toString()}`);
    const flows = await res.json();

    const tbody = document.getElementById('table-raw-flows');
    tbody.innerHTML = flows.map(f => `
      <tr class="hover:bg-slate-800/40">
        <td class="py-2 text-slate-400">${f.timestamp ? f.timestamp.split('T')[1].slice(0, 8) : '--'}</td>
        <td class="py-2 text-slate-300">${f.device_name}</td>
        <td class="py-2 text-cyan-400 font-semibold">${f.src_ip}</td>
        <td class="py-2 text-slate-400">${f.src_as_name || 'AS'}</td>
        <td class="py-2 text-blue-400 font-semibold">${f.dst_ip}</td>
        <td class="py-2 text-slate-400">${f.dst_as_name || 'AS'}</td>
        <td class="py-2 text-slate-300">${f.protocol === 6 ? 'TCP' : (f.protocol === 17 ? 'UDP' : 'ICMP')}</td>
        <td class="py-2 text-slate-400">${f.dst_port}</td>
        <td class="py-2 text-slate-200"><span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px]">${f.application}</span></td>
        <td class="py-2 text-slate-400">${f.dscp_name}</td>
        <td class="py-2 text-right font-mono">${(f.packets || 0).toLocaleString()}</td>
        <td class="py-2 text-right font-mono text-emerald-400">${formatBytes(f.bytes || 0)}</td>
      </tr>
    `).join('') || '<tr><td colspan="12" class="py-4 text-center text-slate-500">No records matching query</td></tr>';

  } catch (e) {
    console.error('Failed to query raw flows:', e);
  }
}

// ================= TRAFFIC PATTERN STUDIO =================

let patternOptionsLoaded = false;
let currentPatternViewMode = 'sankey';
let currentBarCategory = 'providers';
let activePatternMultiviewData = null;
let currentPatternPreset = 'CDN_ENTRY_EXIT';

async function loadPatternStudio() {
  if (!patternOptionsLoaded) {
    try {
      const res = await fetch('/api/v1/pattern/options');
      const opts = await res.json();
      
      const devSelect = document.getElementById('pat-device');
      if (devSelect && opts.devices) {
        devSelect.innerHTML = '<option value="">All Exporter Devices (1,000+)</option>' + 
          opts.devices.map(d => `<option value="${d.device_id}">${d.device_name} (${d.vendor} - ${d.site})</option>`).join('');
      }

      const upSelect = document.getElementById('pat-upstream');
      if (upSelect && opts.upstream_providers) {
        upSelect.innerHTML = '<option value="">All Providers (Transit & Peering)</option>' +
          opts.upstream_providers.map(p => `<option value="${p}">${p}</option>`).join('');
      }

      const svcSelect = document.getElementById('pat-service');
      if (svcSelect && opts.services) {
        svcSelect.innerHTML = '<option value="">All Services (IPT, PNI, CDN...)</option>' +
          opts.services.map(s => `<option value="${s}">${s}</option>`).join('');
      }

      // Default target day for Day-to-Day comparison
      const targetDayInput = document.getElementById('cmp-target-date');
      if (targetDayInput && !targetDayInput.value) {
        targetDayInput.value = '2026-10-30';
      }

      patternOptionsLoaded = true;
    } catch (e) {
      console.error('Failed to load pattern options:', e);
    }
  }

  // Execute initial pattern query
  executePatternQuery();
}

function switchGraphView(viewMode) {
  currentPatternViewMode = viewMode;
  
  const viewBtns = ['sankey', 'bar', 'table', 'area', 'treemap', 'sunburst'];
  viewBtns.forEach(m => {
    const btn = document.getElementById(`btn-view-${m}`);
    const container = document.getElementById(`view-${m}-container`);
    if (btn) {
      if (m === viewMode) {
        btn.className = "px-3 py-1.5 rounded-lg bg-cyan-600/30 text-cyan-300 border border-cyan-500/50 text-xs font-bold flex items-center space-x-1.5 shadow-sm shadow-cyan-500/20";
      } else {
        btn.className = "px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60 text-xs font-medium flex items-center space-x-1.5 transition";
      }
    }
    if (container) {
      if (m === viewMode) {
        container.classList.remove('hidden');
      } else {
        container.classList.add('hidden');
      }
    }
  });

  renderActiveGraphView();
}

function renderActiveGraphView() {
  if (!activePatternMultiviewData) return;

  if (currentPatternViewMode === 'sankey') {
    if (activePatternMultiviewData.sankey) {
      renderSankeyChart(
        activePatternMultiviewData.sankey.nodes,
        activePatternMultiviewData.sankey.links,
        activePatternMultiviewData.view_name
      );
    }
  } else if (currentPatternViewMode === 'bar') {
    if (activePatternMultiviewData.bars) {
      renderRankedBarChart(activePatternMultiviewData.bars, currentBarCategory);
    }
  } else if (currentPatternViewMode === 'table') {
    renderPatternTable(activePatternMultiviewData.table || []);
  } else if (currentPatternViewMode === 'area') {
    if (activePatternMultiviewData.timeseries) {
      renderAreaTrendChart(activePatternMultiviewData.timeseries);
    }
  } else if (currentPatternViewMode === 'treemap') {
    if (activePatternMultiviewData.treemap) {
      renderTreemapChart(activePatternMultiviewData.treemap);
    }
  } else if (currentPatternViewMode === 'sunburst') {
    if (activePatternMultiviewData.sunburst) {
      renderSunburstChart(activePatternMultiviewData.sunburst);
    }
  }

  setTimeout(() => {
    if (currentPatternViewMode === 'sankey' && chartSankey) chartSankey.resize();
    else if (currentPatternViewMode === 'bar' && chartRankedBar) chartRankedBar.resize();
    else if (currentPatternViewMode === 'area' && chartPatternTimeseries) chartPatternTimeseries.resize();
    else if (currentPatternViewMode === 'treemap' && chartTreemap) chartTreemap.resize();
    else if (currentPatternViewMode === 'sunburst' && chartSunburst) chartSunburst.resize();
  }, 60);
}

function switchBarSubcategory(subcat) {
  currentBarCategory = subcat;
  ['providers', 'prefixes', 'interconnects'].forEach(c => {
    const el = document.getElementById(`btn-bar-${c}`);
    if (el) {
      if (c === subcat) {
        el.className = "px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold";
      } else {
        el.className = "px-2.5 py-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200 text-xs";
      }
    }
  });
  if (activePatternMultiviewData && activePatternMultiviewData.bars) {
    renderRankedBarChart(activePatternMultiviewData.bars, currentBarCategory);
  }
}

function renderPatternTable(rows) {
  const tbody = document.getElementById('view-table-body');
  if (!tbody) return;

  tbody.innerHTML = rows.map(r => `
    <tr class="hover:bg-slate-800/40 transition">
      <td class="py-2.5 px-3 text-slate-500 font-mono text-[11px]">${r.rank}</td>
      <td class="py-2.5 px-3 font-semibold text-cyan-400 font-mono">${r.src_entity}</td>
      <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${getInterconnectBadge(r.interconnect)}">${r.interconnect}</span></td>
      <td class="py-2.5 px-3 text-slate-300 font-mono font-semibold">${r.ingress_site}</td>
      <td class="py-2.5 px-3 text-slate-400 font-mono">${r.egress_site}</td>
      <td class="py-2.5 px-3 text-purple-400 font-mono font-semibold">${r.dst_prefix}</td>
      <td class="py-2.5 px-3 text-slate-300">${r.application}</td>
      <td class="py-2.5 px-3 text-right font-mono font-bold text-cyan-400">${Number(r.mbps).toLocaleString()} Mbps</td>
      <td class="py-2.5 px-3 text-right font-mono text-emerald-400 font-bold">${r.total_gb} GB</td>
      <td class="py-2.5 px-3 text-right font-mono text-slate-400">${(r.pps || 0).toLocaleString()}</td>
      <td class="py-2.5 px-3">
        <div class="flex items-center space-x-2">
          <div class="flex-1 bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div class="bg-gradient-to-r from-cyan-500 to-blue-500 h-1.5 rounded-full" style="width: ${Math.min(100, r.share_pct)}%"></div>
          </div>
          <span class="text-[11px] font-mono text-slate-300 w-10 text-right">${r.share_pct}%</span>
        </div>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="11" class="py-6 text-center text-slate-500">No flow paths found</td></tr>';
}

function getInterconnectBadge(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('free')) return 'bg-teal-500/20 text-teal-300 border border-teal-500/30';
  if (t.includes('paid')) return 'bg-orange-500/20 text-orange-300 border border-orange-500/30';
  if (t.includes('transit')) return 'bg-slate-700 text-slate-300 border border-slate-600';
  if (t.includes('customer')) return 'bg-sky-500/20 text-sky-300 border border-sky-500/30';
  return 'bg-slate-800 text-slate-400';
}

function filterPatternTable(term) {
  if (!activePatternMultiviewData || !activePatternMultiviewData.table) return;
  const q = term.toLowerCase().trim();
  if (!q) {
    renderPatternTable(activePatternMultiviewData.table);
    return;
  }
  const filtered = activePatternMultiviewData.table.filter(r => 
    String(r.src_entity).toLowerCase().includes(q) ||
    String(r.interconnect).toLowerCase().includes(q) ||
    String(r.ingress_site).toLowerCase().includes(q) ||
    String(r.egress_site).toLowerCase().includes(q) ||
    String(r.dst_prefix).toLowerCase().includes(q) ||
    String(r.application).toLowerCase().includes(q)
  );
  renderPatternTable(filtered);
}

function exportPatternDataToCSV() {
  if (!activePatternMultiviewData || !activePatternMultiviewData.table) {
    showToast('No active dataset to export', 'error');
    return;
  }
  const rows = activePatternMultiviewData.table;
  const headers = ["Rank", "Source Entity", "Interconnect", "Ingress Site", "Egress Site", "Destination Prefix", "Application", "Throughput (Mbps)", "Total Data (GB)", "Packets (PPS)", "Share (%)"];
  const csvContent = [
    headers.join(","),
    ...rows.map(r => `"${r.rank}","${r.src_entity}","${r.interconnect}","${r.ingress_site}","${r.egress_site}","${r.dst_prefix}","${r.application}",${r.mbps},${r.total_gb},${r.pps},${r.share_pct}`)
  ].join("\n");

  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aegisflow_traffic_flow_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast('Exported CSV dataset successfully', 'success');
}

function onPresetSelected(presetId) {
  currentPatternPreset = presetId;
  const badge = document.getElementById('active-view-badge');
  if (presetId === 'CDN_ENTRY_EXIT') {
    if (badge) badge.innerText = "★ Saved View: CDN Traffic Network Entry & Exit";
    resetPatternFilterFields();
  } else {
    if (badge) badge.innerText = "Dynamic Multi-Condition Filter Flow";
  }
  executePatternQuery();
}

function jumpToCdnSankey() {
  switchTab('pattern');
  const sel = document.getElementById('select-pattern-preset');
  if (sel) sel.value = 'CDN_ENTRY_EXIT';
  currentPatternPreset = 'CDN_ENTRY_EXIT';
  const badge = document.getElementById('active-view-badge');
  if (badge) badge.innerText = "★ Saved View: CDN Traffic Network Entry & Exit";
  switchGraphView('sankey');
  
  // Highlight sidebar item
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.className = "nav-btn w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium transition text-slate-400 hover:text-white hover:bg-slate-800/60";
  });
  const navBtn = document.getElementById('nav-cdn-sankey');
  if (navBtn) {
    navBtn.className = "nav-btn w-full flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium transition text-white bg-cyan-600/20 border border-cyan-500/30";
  }

  executePatternQuery();
}

function onPatternTimeChange(val) {
  const customContainer = document.getElementById('pat-custom-date-container');
  if (val === 'CUSTOM') {
    customContainer?.classList.remove('hidden');
  } else {
    customContainer?.classList.add('hidden');
    clearPatternDatePreset(false);
  }
}

function toggleCustomDatePicker() {
  const customContainer = document.getElementById('pat-custom-date-container');
  if (customContainer) {
    customContainer.classList.toggle('hidden');
    if (!customContainer.classList.contains('hidden')) {
      const timeSelect = document.getElementById('pat-time');
      if (timeSelect) timeSelect.value = 'CUSTOM';
    }
  }
}

function setPatternDatePreset(preset) {
  const startEl = document.getElementById('pat-start-datetime');
  const endEl = document.getElementById('pat-end-datetime');
  const badgeEl = document.getElementById('pat-date-badge');
  const timeSelect = document.getElementById('pat-time');
  const customContainer = document.getElementById('pat-custom-date-container');

  if (timeSelect) timeSelect.value = 'CUSTOM';
  if (customContainer) customContainer.classList.remove('hidden');
  if (badgeEl) badgeEl.classList.remove('hidden');

  if (preset === 'today') {
    startEl.value = '2026-10-30T00:00';
    endEl.value = '2026-10-30T23:59';
  } else if (preset === 'yesterday') {
    startEl.value = '2026-10-29T00:00';
    endEl.value = '2026-10-29T23:59';
  } else if (preset === 'last7d') {
    startEl.value = '2026-10-23T00:00';
    endEl.value = '2026-10-30T23:59';
  } else if (preset === 'last30d') {
    startEl.value = '2026-10-01T00:00';
    endEl.value = '2026-10-30T23:59';
  }
}

function clearPatternDatePreset(resetDropdown = true) {
  const startEl = document.getElementById('pat-start-datetime');
  const endEl = document.getElementById('pat-end-datetime');
  const badgeEl = document.getElementById('pat-date-badge');
  const timeSelect = document.getElementById('pat-time');
  const customContainer = document.getElementById('pat-custom-date-container');

  if (startEl) startEl.value = '';
  if (endEl) endEl.value = '';
  if (badgeEl) badgeEl.classList.add('hidden');
  if (customContainer) customContainer.classList.add('hidden');
  if (resetDropdown && timeSelect && timeSelect.value === 'CUSTOM') {
    timeSelect.value = '60';
  }
}

async function executePatternQuery() {
  const startDt = document.getElementById('pat-start-datetime')?.value;
  const endDt = document.getElementById('pat-end-datetime')?.value;
  const timeVal = document.getElementById('pat-time')?.value;
  const timeMinutes = timeVal === 'CUSTOM' ? 60 : parseInt(timeVal || 60);

  const reqBody = {
    src_as: document.getElementById('pat-src-as').value ? parseInt(document.getElementById('pat-src-as').value) : null,
    dst_as: document.getElementById('pat-dst-as').value ? parseInt(document.getElementById('pat-dst-as').value) : null,
    src_country: document.getElementById('pat-src-country').value || null,
    dst_country: document.getElementById('pat-dst-country').value || null,
    src_prefix: document.getElementById('pat-src-prefix').value || null,
    dst_prefix: document.getElementById('pat-dst-prefix').value || null,
    in_if_name: document.getElementById('pat-in-if').value || null,
    device_id: document.getElementById('pat-device').value || null,
    application: document.getElementById('pat-app').value || null,
    dscp: document.getElementById('pat-dscp').value !== "" ? parseInt(document.getElementById('pat-dscp').value) : null,
    flow_direction: document.getElementById('pat-direction').value || null,
    upstream_provider: document.getElementById('pat-upstream')?.value || null,
    service_name: document.getElementById('pat-service')?.value || null,
    time_window_minutes: timeMinutes,
    start_time: startDt || null,
    end_time: endDt || null,
    preset: currentPatternPreset
  };

  try {
    const [queryRes, multiRes] = await Promise.all([
      fetch('/api/v1/pattern/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reqBody)
      }),
      fetch('/api/v1/pattern/multiview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reqBody)
      })
    ]);

    const data = await queryRes.json();
    const multiview = await multiRes.json();
    activePatternMultiviewData = multiview;

    // Update Pattern KPIs
    const sm = multiview.summary || data.summary || {};
    document.getElementById('pat-kpi-mbps').innerText = `${Number(sm.total_mbps || sm.avg_mbps || 0).toLocaleString()} Mbps`;
    document.getElementById('pat-kpi-bytes').innerText = formatBytes((sm.total_gb ? sm.total_gb * 1024 * 1024 * 1024 : sm.total_bytes) || 0);
    document.getElementById('pat-kpi-flows').innerText = (sm.total_flows || sm.flow_count || 0).toLocaleString();
    document.getElementById('pat-kpi-endpoints').innerText = sm.top_talker ? sm.top_talker : `${sm.unique_sources || 0} Src / ${sm.unique_destinations || 0} Dst`;

    // Render Active Graph View (Sankey, Bar, Table, Area, Treemap, Sunburst)
    renderActiveGraphView();

    // Update Matched ASNs
    const asnTbody = document.getElementById('table-pattern-asns');
    if (asnTbody) {
      asnTbody.innerHTML = (data.top_asns || []).map(a => `
        <tr class="hover:bg-slate-800/40">
          <td class="py-2 text-slate-300">AS${a.src_as} (${a.src_as_name})</td>
          <td class="py-2 text-cyan-400 font-bold">AS${a.dst_as} (${a.dst_as_name})</td>
          <td class="py-2 text-right text-emerald-400 font-bold">${a.mbps} Mbps</td>
        </tr>
      `).join('') || '<tr><td colspan="3" class="py-3 text-center text-slate-500">No matching ASNs in filter</td></tr>';
    }

    // Update Matched Interfaces
    const ifTbody = document.getElementById('table-pattern-interfaces');
    if (ifTbody) {
      ifTbody.innerHTML = (data.top_interfaces || []).map(i => `
        <tr class="hover:bg-slate-800/40">
          <td class="py-2 text-slate-200">${i.device_name}</td>
          <td class="py-2 text-cyan-400 font-bold">${i.in_if_name || 'N/A'}</td>
          <td class="py-2 text-right text-emerald-400 font-bold">${i.mbps} Mbps</td>
        </tr>
      `).join('') || '<tr><td colspan="3" class="py-3 text-center text-slate-500">No matching interfaces in filter</td></tr>';
    }

    // Update Conversations
    const convTbody = document.getElementById('table-pattern-conversations');
    if (convTbody) {
      convTbody.innerHTML = (data.top_conversations || []).map(c => `
        <tr class="hover:bg-slate-800/40">
          <td class="py-2 text-cyan-400 font-bold">${c.src_ip} <span class="text-slate-400 text-[10px]">(${c.src_country} · ${c.src_as_name})</span></td>
          <td class="py-2 text-blue-400 font-bold">${c.dst_ip} <span class="text-slate-400 text-[10px]">(${c.dst_country} · ${c.dst_as_name})</span></td>
          <td class="py-2 text-slate-300"><span class="px-2 py-0.5 rounded bg-slate-800 text-[10px] border border-slate-700">${c.application}</span></td>
          <td class="py-2 text-slate-400">${c.protocol === 6 ? 'TCP' : 'UDP'}/${c.dst_port}</td>
          <td class="py-2"><span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">${c.flow_direction}</span></td>
          <td class="py-2 text-right text-emerald-400 font-bold">${c.mbps} Mbps</td>
        </tr>
      `).join('') || '<tr><td colspan="6" class="py-4 text-center text-slate-500">No matching flows for current criteria</td></tr>';
    }

  } catch (e) {
    console.error('Pattern query failed:', e);
    showToast('Failed to execute pattern query', 'error');
  }
}

function resetPatternFilterFields() {
  document.getElementById('pat-src-as').value = '';
  document.getElementById('pat-dst-as').value = '';
  document.getElementById('pat-src-country').value = '';
  document.getElementById('pat-dst-country').value = '';
  document.getElementById('pat-src-prefix').value = '';
  document.getElementById('pat-dst-prefix').value = '';
  document.getElementById('pat-in-if').value = '';
  document.getElementById('pat-device').value = '';
  document.getElementById('pat-app').value = '';
  document.getElementById('pat-dscp').value = '';
  document.getElementById('pat-direction').value = '';
  if (document.getElementById('pat-upstream')) document.getElementById('pat-upstream').value = '';
  if (document.getElementById('pat-service')) document.getElementById('pat-service').value = '';
  document.getElementById('pat-time').value = '60';
  clearPatternDatePreset(true);
}

function resetPatternFilters() {
  resetPatternFilterFields();
  currentPatternPreset = 'DYNAMIC';
  const sel = document.getElementById('select-pattern-preset');
  if (sel) sel.value = 'DYNAMIC';
  const badge = document.getElementById('active-view-badge');
  if (badge) badge.innerText = "Dynamic Multi-Condition Filter Flow";
  executePatternQuery();
}

// ================= TRAFFIC PATTERN COMPARISON STUDIO (DoD, WoW, MoM) =================

let currentPatternStudioMode = 'multiview'; // 'multiview' | 'compare'
let currentComparisonMode = 'DAY_TO_DAY';   // 'DAY_TO_DAY' | 'WEEK_TO_WEEK' | 'MONTH_BY_MONTH' | 'CUSTOM'
let currentComparisonView = 'overlay';      // 'overlay' | 'bars' | 'deltas'
let currentDeltaDimension = 'asns';         // 'asns' | 'apps' | 'upstreams' | 'interfaces'
let activeComparisonData = null;
let chartCompareOverlay = null;
let chartCompareBars = null;

function switchPatternStudioMode(mode) {
  currentPatternStudioMode = mode;
  const btnMulti = document.getElementById('btn-mode-multiview');
  const btnCmp = document.getElementById('btn-mode-compare');
  const contMulti = document.getElementById('container-studio-multiview');
  const contCmp = document.getElementById('container-studio-compare');

  if (mode === 'compare') {
    btnCmp.className = "px-4 py-2 rounded-lg bg-amber-500/30 text-amber-300 border border-amber-500/50 text-xs font-bold flex items-center space-x-2 shadow-sm shadow-amber-500/20";
    btnMulti.className = "px-4 py-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60 text-xs font-bold flex items-center space-x-2 transition";
    contMulti?.classList.add('hidden');
    contCmp?.classList.remove('hidden');
    
    if (!activeComparisonData) {
      executePatternComparison();
    } else {
      setTimeout(() => {
        chartCompareOverlay?.resize();
        chartCompareBars?.resize();
      }, 100);
    }
  } else {
    btnMulti.className = "px-4 py-2 rounded-lg bg-cyan-600/30 text-cyan-300 border border-cyan-500/50 text-xs font-bold flex items-center space-x-2 shadow-sm shadow-cyan-500/20";
    btnCmp.className = "px-4 py-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60 text-xs font-bold flex items-center space-x-2 transition";
    contCmp?.classList.add('hidden');
    contMulti?.classList.remove('hidden');
    renderActiveGraphView();
  }
}

function setComparisonMode(mode) {
  currentComparisonMode = mode;
  ['dod', 'wow', 'mom', 'custom'].forEach(m => {
    const btn = document.getElementById(`btn-cmp-${m}`);
    if (btn) {
      const isMatch = (mode === 'DAY_TO_DAY' && m === 'dod') ||
                      (mode === 'WEEK_TO_WEEK' && m === 'wow') ||
                      (mode === 'MONTH_BY_MONTH' && m === 'mom') ||
                      (mode === 'CUSTOM' && m === 'custom');
      if (isMatch) {
        btn.className = "px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-bold flex items-center space-x-1.5 shadow-sm shadow-amber-500/10";
      } else {
        btn.className = "px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700 text-xs font-medium flex items-center space-x-1.5 transition";
      }
    }
  });

  const dayBar = document.getElementById('cmp-day-date-bar');
  const customBar = document.getElementById('cmp-custom-dates-bar');
  if (mode === 'DAY_TO_DAY') {
    dayBar?.classList.remove('hidden');
    customBar?.classList.add('hidden');
  } else if (mode === 'CUSTOM') {
    dayBar?.classList.add('hidden');
    customBar?.classList.remove('hidden');
  } else {
    dayBar?.classList.add('hidden');
    customBar?.classList.add('hidden');
  }

  executePatternComparison();
}

function switchComparisonView(view) {
  currentComparisonView = view;
  ['overlay', 'bars', 'deltas'].forEach(v => {
    const btn = document.getElementById(`btn-cmpview-${v}`);
    const cont = document.getElementById(`cmp-view-${v}-container`);
    if (btn) {
      if (v === view) {
        btn.className = "px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold flex items-center space-x-1.5 shadow-sm shadow-amber-500/10";
      } else {
        btn.className = "px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60 font-medium flex items-center space-x-1.5 transition";
      }
    }
    if (cont) {
      if (v === view) cont.classList.remove('hidden');
      else cont.classList.add('hidden');
    }
  });

  if (activeComparisonData) {
    if (view === 'overlay') {
      setTimeout(() => renderComparisonOverlayChart(activeComparisonData.timeseries_comparison), 50);
    } else if (view === 'bars') {
      setTimeout(() => renderComparisonBarsChart(activeComparisonData.timeseries_comparison), 50);
    } else if (view === 'deltas') {
      renderComparisonDeltasTable();
    }
  }
}

function switchDeltaDimension(dim) {
  currentDeltaDimension = dim;
  ['asns', 'apps', 'upstreams', 'interfaces'].forEach(d => {
    const btn = document.getElementById(`btn-delta-${d}`);
    if (btn) {
      if (d === dim) {
        btn.className = "px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-bold";
      } else {
        btn.className = "px-2.5 py-1 rounded bg-slate-800 text-slate-400 hover:text-slate-200";
      }
    }
  });
  renderComparisonDeltasTable();
}

async function executePatternComparison() {
  const criteria = {
    src_as: document.getElementById('pat-src-as')?.value ? parseInt(document.getElementById('pat-src-as').value) : null,
    dst_as: document.getElementById('pat-dst-as')?.value ? parseInt(document.getElementById('pat-dst-as').value) : null,
    src_country: document.getElementById('pat-src-country')?.value || null,
    dst_country: document.getElementById('pat-dst-country')?.value || null,
    src_prefix: document.getElementById('pat-src-prefix')?.value || null,
    dst_prefix: document.getElementById('pat-dst-prefix')?.value || null,
    in_if_name: document.getElementById('pat-in-if')?.value || null,
    device_id: document.getElementById('pat-device')?.value || null,
    application: document.getElementById('pat-app')?.value || null,
    dscp: document.getElementById('pat-dscp')?.value !== "" ? parseInt(document.getElementById('pat-dscp').value) : null,
    flow_direction: document.getElementById('pat-direction')?.value || null,
    upstream_provider: document.getElementById('pat-upstream')?.value || null,
    service_name: document.getElementById('pat-service')?.value || null,
  };

  if (currentComparisonMode === 'DAY_TO_DAY') {
    const targetDay = document.getElementById('cmp-target-date')?.value;
    if (targetDay) criteria.selected_date = targetDay;
  }

  const payload = {
    criteria: criteria,
    compare_mode: currentComparisonMode
  };

  if (currentComparisonMode === 'CUSTOM') {
    payload.period_current = {
      start_time: document.getElementById('cmp-p1-start')?.value || null,
      end_time: document.getElementById('cmp-p1-end')?.value || null
    };
    payload.period_baseline = {
      start_time: document.getElementById('cmp-p2-start')?.value || null,
      end_time: document.getElementById('cmp-p2-end')?.value || null
    };
  }

  try {
    const res = await fetch('/api/v1/pattern/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    activeComparisonData = data;
    renderComparisonDashboard(data);
  } catch (e) {
    console.error('Pattern comparison failed:', e);
    showToast('Failed to execute pattern comparison', 'error');
  }
}

function renderComparisonDashboard(data) {
  if (!data || !data.summary_delta) return;
  const sm = data.summary_delta;
  const div = data.divergence || {};

  // KPI 1: Throughput Delta
  const deltaMbpsEl = document.getElementById('cmp-kpi-delta-mbps');
  const deltaMbpsBadge = document.getElementById('cmp-badge-mbps-trend');
  if (deltaMbpsEl) deltaMbpsEl.innerText = `${sm.delta_mbps > 0 ? '+' : ''}${Number(sm.delta_mbps).toLocaleString()} Mbps`;
  if (deltaMbpsBadge) {
    const isUp = sm.delta_mbps >= 0;
    deltaMbpsBadge.innerText = `${isUp ? '▲ +' : '▼ '}${sm.pct_change_mbps}%`;
    deltaMbpsBadge.className = isUp 
      ? "px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
      : "px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30";
  }
  document.getElementById('cmp-kpi-cur-mbps').innerText = `${Number(sm.current_avg_mbps).toLocaleString()} Mbps`;
  document.getElementById('cmp-kpi-base-mbps').innerText = `${Number(sm.baseline_avg_mbps).toLocaleString()} Mbps`;

  // KPI 2: Total Volume Delta
  const deltaGbEl = document.getElementById('cmp-kpi-delta-gb');
  const deltaGbBadge = document.getElementById('cmp-badge-volume-trend');
  if (deltaGbEl) deltaGbEl.innerText = `${sm.delta_gb > 0 ? '+' : ''}${sm.delta_gb.toLocaleString()} GB`;
  if (deltaGbBadge) {
    deltaGbBadge.innerText = `${sm.pct_change_bytes > 0 ? '▲ +' : '▼ '}${sm.pct_change_bytes}%`;
  }
  document.getElementById('cmp-kpi-cur-gb').innerText = `${sm.current_total_gb.toLocaleString()} GB`;
  document.getElementById('cmp-kpi-base-gb').innerText = `${sm.baseline_total_gb.toLocaleString()} GB`;

  // KPI 3: Peak Wire-Rate Delta
  const deltaPeakEl = document.getElementById('cmp-kpi-delta-peak');
  const deltaPeakBadge = document.getElementById('cmp-badge-peak-trend');
  if (deltaPeakEl) deltaPeakEl.innerText = `${sm.delta_peak_mbps > 0 ? '+' : ''}${Number(sm.delta_peak_mbps).toLocaleString()} Mbps`;
  if (deltaPeakBadge) {
    deltaPeakBadge.innerText = `${sm.pct_change_peak > 0 ? '▲ +' : '▼ '}${sm.pct_change_peak}%`;
  }
  document.getElementById('cmp-kpi-cur-peak').innerText = `${Number(sm.current_peak_mbps).toLocaleString()} Mbps`;
  document.getElementById('cmp-kpi-base-peak').innerText = `${Number(sm.baseline_peak_mbps).toLocaleString()} Mbps`;

  // KPI 4: Divergence & Status
  const divMsg = document.getElementById('cmp-kpi-divergence-msg');
  const divBadge = document.getElementById('cmp-badge-divergence');
  const periodLbl = document.getElementById('cmp-kpi-period-label');
  if (divMsg) divMsg.innerText = div.message || "Normal diurnal variance";
  if (divBadge) {
    divBadge.innerText = div.status || "NORMAL";
    if (div.status === 'SPIKE_SURGE') {
      divBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30";
    } else if (div.status === 'DROP_DIVERGENCE') {
      divBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30";
    } else {
      divBadge.className = "px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30";
    }
  }
  if (periodLbl) periodLbl.innerText = data.mode_label || "Comparison Horizon";

  // Render view
  if (currentComparisonView === 'overlay') {
    renderComparisonOverlayChart(data.timeseries_comparison);
  } else if (currentComparisonView === 'bars') {
    renderComparisonBarsChart(data.timeseries_comparison);
  } else if (currentComparisonView === 'deltas') {
    renderComparisonDeltasTable();
  }
}

function renderComparisonOverlayChart(seriesData) {
  const chartDom = document.getElementById('chart-compare-overlay');
  if (!chartDom || !window.echarts) return;
  if (!chartCompareOverlay) chartCompareOverlay = echarts.init(chartDom);

  const labels = (seriesData || []).map(s => s.label);
  const currentVals = (seriesData || []).map(s => s.current_mbps);
  const baselineVals = (seriesData || []).map(s => s.baseline_mbps);

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#0f172a',
      borderColor: '#334155',
      textStyle: { color: '#f8fafc', fontSize: 12 },
      formatter: function (params) {
        if (!params || !params.length) return '';
        const idx = params[0].dataIndex;
        const item = seriesData[idx] || {};
        const sign = item.delta_mbps >= 0 ? '+' : '';
        const color = item.delta_mbps >= 0 ? '#10b981' : '#f43f5e';
        return `
          <div class="font-bold text-slate-200 border-b border-slate-700 pb-1 mb-1.5">${item.label}</div>
          <div class="flex items-center justify-between space-x-4 mb-1">
            <span class="text-cyan-400 font-semibold">● Current Period:</span>
            <span class="font-mono font-bold text-white">${Number(item.current_mbps).toLocaleString()} Mbps</span>
          </div>
          <div class="flex items-center justify-between space-x-4 mb-1.5">
            <span class="text-amber-400 font-semibold">● Baseline Period:</span>
            <span class="font-mono font-bold text-slate-300">${Number(item.baseline_mbps).toLocaleString()} Mbps</span>
          </div>
          <div class="flex items-center justify-between space-x-4 pt-1 border-t border-slate-800 text-[11px]">
            <span class="text-slate-400">Delta Variance:</span>
            <span class="font-mono font-bold" style="color: ${color}">${sign}${item.delta_mbps} Mbps (${sign}${item.pct_change}%)</span>
          </div>
        `;
      }
    },
    legend: {
      data: ['Current Period', 'Baseline Period'],
      textStyle: { color: '#94a3b8', fontSize: 11 },
      top: 5
    },
    grid: { left: '3%', right: '4%', bottom: '8%', top: '15%', containLabel: true },
    xAxis: {
      type: 'category',
      data: labels,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      name: 'Wire-Rate (Mbps)',
      nameTextStyle: { color: '#94a3b8', fontSize: 11 },
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: 'rgba(51, 65, 85, 0.4)' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    series: [
      {
        name: 'Current Period',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 3, color: '#06b6d4' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(6, 182, 212, 0.35)' },
            { offset: 1, color: 'rgba(6, 182, 212, 0.02)' }
          ])
        },
        data: currentVals
      },
      {
        name: 'Baseline Period',
        type: 'line',
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2.5, color: '#f59e0b', type: 'dashed' },
        data: baselineVals
      }
    ]
  };

  chartCompareOverlay.setOption(option);
}

function renderComparisonBarsChart(seriesData) {
  const chartDom = document.getElementById('chart-compare-bars');
  if (!chartDom || !window.echarts) return;
  if (!chartCompareBars) chartCompareBars = echarts.init(chartDom);

  const labels = (seriesData || []).map(s => s.label);
  const currentVals = (seriesData || []).map(s => s.current_mbps);
  const baselineVals = (seriesData || []).map(s => s.baseline_mbps);

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: '#0f172a',
      borderColor: '#334155',
      textStyle: { color: '#f8fafc', fontSize: 12 }
    },
    legend: {
      data: ['Current Period', 'Baseline Period'],
      textStyle: { color: '#94a3b8', fontSize: 11 },
      top: 5
    },
    grid: { left: '3%', right: '4%', bottom: '8%', top: '15%', containLabel: true },
    xAxis: {
      type: 'category',
      data: labels,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      name: 'Throughput (Mbps)',
      nameTextStyle: { color: '#94a3b8', fontSize: 11 },
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: 'rgba(51, 65, 85, 0.4)' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    series: [
      {
        name: 'Current Period',
        type: 'bar',
        barGap: '15%',
        itemStyle: { color: '#06b6d4', borderRadius: [4, 4, 0, 0] },
        data: currentVals
      },
      {
        name: 'Baseline Period',
        type: 'bar',
        itemStyle: { color: '#f59e0b', borderRadius: [4, 4, 0, 0] },
        data: baselineVals
      }
    ]
  };

  chartCompareBars.setOption(option);
}

function renderComparisonDeltasTable() {
  const tbody = document.getElementById('table-compare-deltas-body');
  if (!tbody || !activeComparisonData) return;

  const keyMap = {
    asns: 'top_asns',
    apps: 'top_applications',
    upstreams: 'top_upstreams',
    interfaces: 'top_interfaces'
  };

  const list = activeComparisonData.dimensional_deltas?.[keyMap[currentDeltaDimension]] || [];
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="py-4 text-center text-slate-500">No dimensional changes detected for current filters</td></tr>';
    return;
  }

  tbody.innerHTML = list.map(item => {
    const isUp = item.delta_mbps >= 0;
    const badgeClass = isUp 
      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
      : 'bg-rose-500/20 text-rose-300 border border-rose-500/30';
    const icon = isUp ? '<i class="fa-solid fa-arrow-up text-emerald-400 mr-1"></i>' : '<i class="fa-solid fa-arrow-down text-rose-400 mr-1"></i>';
    const sign = isUp ? '+' : '';

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-2.5 px-3 font-semibold text-slate-200">${item.entity}</td>
        <td class="py-2.5 px-3 text-right text-slate-400">${Number(item.baseline_mbps).toLocaleString()} Mbps</td>
        <td class="py-2.5 px-3 text-right text-cyan-400 font-bold">${Number(item.current_mbps).toLocaleString()} Mbps</td>
        <td class="py-2.5 px-3 text-right font-bold ${isUp ? 'text-emerald-400' : 'text-rose-400'}">${sign}${item.delta_mbps} Mbps</td>
        <td class="py-2.5 px-3 text-right"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${sign}${item.pct_change}%</span></td>
        <td class="py-2.5 px-3 text-center text-xs font-semibold">${icon}${item.direction}</td>
      </tr>
    `;
  }).join('');
}

function exportComparisonCSV() {
  if (!activeComparisonData) {
    showToast('Run a comparison first before exporting', 'error');
    return;
  }

  let csv = "Step,Label,Current_Mbps,Baseline_Mbps,Delta_Mbps,Pct_Change\n";
  (activeComparisonData.timeseries_comparison || []).forEach(s => {
    csv += `${s.step},"${s.label}",${s.current_mbps},${s.baseline_mbps},${s.delta_mbps},${s.pct_change}\n`;
  });

  csv += "\nDimension,Entity,Current_Mbps,Baseline_Mbps,Delta_Mbps,Pct_Change,Direction\n";
  const deltas = activeComparisonData.dimensional_deltas || {};
  Object.keys(deltas).forEach(dim => {
    (deltas[dim] || []).forEach(item => {
      csv += `${dim},"${item.entity}",${item.current_mbps},${item.baseline_mbps},${item.delta_mbps},${item.pct_change},${item.direction}\n`;
    });
  });

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `AegisFlow_Comparison_${activeComparisonData.compare_mode}_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast('Comparison CSV exported successfully');
}

function openCreateReportModalWithCurrentFilters() {
  document.getElementById('rep-form-src-as').value = document.getElementById('pat-src-as').value;
  document.getElementById('rep-form-dst-as').value = document.getElementById('pat-dst-as').value;
  document.getElementById('rep-form-src-prefix').value = document.getElementById('pat-src-prefix').value;
  document.getElementById('rep-form-dst-prefix').value = document.getElementById('pat-dst-prefix').value;
  document.getElementById('rep-form-in-if').value = document.getElementById('pat-in-if').value;
  document.getElementById('rep-form-country').value = document.getElementById('pat-dst-country').value;
  document.getElementById('rep-form-window').value = document.getElementById('pat-time').value;

  const desc = [];
  if (document.getElementById('pat-src-as').value) desc.push(`Src AS${document.getElementById('pat-src-as').value}`);
  if (document.getElementById('pat-dst-as').value) desc.push(`Dst AS${document.getElementById('pat-dst-as').value}`);
  if (document.getElementById('pat-src-prefix').value) desc.push(`Prefix ${document.getElementById('pat-src-prefix').value}`);
  if (document.getElementById('pat-in-if').value) desc.push(`Interface ${document.getElementById('pat-in-if').value}`);

  document.getElementById('rep-form-name').value = desc.length ? `Automated ${desc.join(' to ')} Report` : "Custom Traffic Pattern Report";
  document.getElementById('rep-form-desc').value = `Monitors bandwidth, top talkers, and saturation for: ${desc.join(', ')}`;

  openCreateReportModal();
}

// ================= AUTOMATED REPORTS & NOTIFICATIONS =================

async function loadReports() {
  try {
    const [reportsRes, historyRes] = await Promise.all([
      fetch('/api/v1/reports'),
      fetch('/api/v1/reports/history/all')
    ]);
    const reports = await reportsRes.json();
    const history = await historyRes.json();

    // Render Saved Report Cards
    const grid = document.getElementById('grid-saved-reports');
    if (!reports.length) {
      grid.innerHTML = '<div class="p-6 text-center text-slate-500 font-mono text-xs col-span-3">No saved reports found. Click "+ Create New Report".</div>';
    } else {
      grid.innerHTML = reports.map(r => {
        const conds = r.conditions || {};
        const condBadges = Object.entries(conds)
          .filter(([k, v]) => v)
          .map(([k, v]) => `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 font-mono text-[10px] border border-slate-700">${k}: <b>${v}</b></span>`)
          .join(' ');

        const lastRunStr = r.last_run ? new Date(r.last_run * 1000).toLocaleString() : 'Never Executed';

        return `
          <div class="glass-card p-5 rounded-xl border border-slate-800 flex flex-col justify-between space-y-4 hover:border-slate-700 transition">
            <div>
              <div class="flex items-center justify-between">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${r.schedule === 'DAILY' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (r.schedule === 'HOURLY' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-purple-500/20 text-purple-400 border border-purple-500/30')}">${r.schedule}</span>
                <span class="text-[11px] text-slate-500 font-mono">${r.id}</span>
              </div>
              <h3 class="text-sm font-bold text-white mt-2">${r.name}</h3>
              <p class="text-xs text-slate-400 mt-1">${r.description || 'Condition-based traffic report'}</p>
              
              <div class="mt-3 flex flex-wrap gap-1">
                ${condBadges || '<span class="text-[10px] text-slate-500">Global traffic scope</span>'}
              </div>

              <div class="text-[11px] text-slate-400 mt-3 pt-3 border-t border-slate-800/80 space-y-1">
                <div><i class="fa-solid fa-clock text-slate-500 mr-1.5"></i>Last Run: <span class="text-slate-200 font-semibold">${lastRunStr}</span></div>
                ${r.recipients && r.recipients.length ? `<div><i class="fa-solid fa-envelope text-slate-500 mr-1.5"></i>Recipients: <span class="text-slate-300">${r.recipients.join(', ')}</span></div>` : ''}
                ${r.webhook_url ? `<div><i class="fa-solid fa-satellite-dish text-slate-500 mr-1.5"></i>Webhook Active</div>` : ''}
              </div>
            </div>

            <div class="flex items-center justify-between pt-2 border-t border-slate-800">
              <button onclick="runReportNow('${r.id}')" class="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center space-x-1 shadow-md shadow-emerald-600/30">
                <i class="fa-solid fa-play"></i>
                <span>Run Now</span>
              </button>
              <div class="flex items-center space-x-1.5">
                <a href="/api/v1/reports/${r.id}/export/html" target="_blank" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold" title="View Executive HTML Report">
                  <i class="fa-solid fa-eye"></i>
                </a>
                <a href="/api/v1/reports/${r.id}/export/csv" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 text-xs font-semibold" title="Download CSV">
                  <i class="fa-solid fa-file-csv"></i>
                </a>
                <button onclick="deleteReport('${r.id}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-red-900/40 text-red-400 text-xs font-semibold" title="Delete Report">
                  <i class="fa-solid fa-trash-can"></i>
                </button>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }

    // Render Execution History Table
    const tbody = document.getElementById('table-report-history');
    tbody.innerHTML = (history || []).map(h => {
      const emailStatus = h.dispatch_status && h.dispatch_status.email ? h.dispatch_status.email.status : 'SKIPPED';
      const emailClass = emailStatus === 'SENT' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (emailStatus === 'SPOOLED' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-500');
      
      const whStatus = h.dispatch_status && h.dispatch_status.webhook ? h.dispatch_status.webhook.status : 'SKIPPED';
      const whClass = whStatus === 'DELIVERED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : (whStatus === 'FAILED' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-slate-800 text-slate-500');

      return `
        <tr class="hover:bg-slate-800/40">
          <td class="py-2.5 text-slate-400 font-mono">${new Date(h.timestamp * 1000).toLocaleString()}</td>
          <td class="py-2.5 font-bold text-white">${h.report_name}</td>
          <td class="py-2.5 text-right font-bold text-cyan-400 font-mono">${h.avg_mbps} Mbps</td>
          <td class="py-2.5 text-right font-semibold text-emerald-400 font-mono">${h.total_data_formatted}</td>
          <td class="py-2.5 text-right text-slate-300 font-mono">${(h.flow_count || 0).toLocaleString()}</td>
          <td class="py-2.5 text-center">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${emailClass}">${emailStatus}</span>
          </td>
          <td class="py-2.5 text-center">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${whClass}">${whStatus}</span>
          </td>
          <td class="py-2.5 text-center">
            <a href="/api/v1/reports/${h.report_id}/export/html" target="_blank" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold mr-1">HTML</a>
            <a href="/api/v1/reports/${h.report_id}/export/csv" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-400 text-xs font-semibold">CSV</a>
          </td>
        </tr>
      `;
    }).join('') || '<tr><td colspan="8" class="py-4 text-center text-slate-500">No report execution history</td></tr>';

  } catch (e) {
    console.error('Failed to load reports:', e);
  }
}

async function runReportNow(reportId) {
  try {
    showToast('Executing report & generating notifications...', 'info');
    const res = await fetch(`/api/v1/reports/${reportId}/run?notify=true`, { method: 'POST' });
    const data = await res.json();
    if (data.status === 'SUCCESS') {
      const run = data.run;
      const emailStatus = run.dispatch_status && run.dispatch_status.email ? run.dispatch_status.email.status : 'None';
      showToast(`Report '${run.report_name}' generated! Email: ${emailStatus}`, 'success');
      loadReports();
    } else {
      showToast(data.error || 'Execution failed', 'error');
    }
  } catch (e) {
    showToast('Failed to run report', 'error');
  }
}

async function deleteReport(reportId) {
  if (!confirm(`Are you sure you want to delete report '${reportId}'?`)) return;
  try {
    await fetch(`/api/v1/reports/${reportId}`, { method: 'DELETE' });
    showToast('Report deleted', 'info');
    loadReports();
  } catch (e) {
    showToast('Delete failed', 'error');
  }
}

function openCreateReportModal() {
  document.getElementById('modal-report').classList.remove('hidden');
}

function closeCreateReportModal() {
  document.getElementById('modal-report').classList.add('hidden');
}

async function submitSaveReport() {
  const name = document.getElementById('rep-form-name').value.trim();
  if (!name) {
    alert('Please enter a Report Name');
    return;
  }

  const emailsRaw = document.getElementById('rep-form-emails').value;
  const recipients = emailsRaw ? emailsRaw.split(',').map(e => e.trim()).filter(e => e) : [];

  const conditions = {
    src_as: document.getElementById('rep-form-src-as').value ? parseInt(document.getElementById('rep-form-src-as').value) : null,
    dst_as: document.getElementById('rep-form-dst-as').value ? parseInt(document.getElementById('rep-form-dst-as').value) : null,
    src_prefix: document.getElementById('rep-form-src-prefix').value.trim() || null,
    dst_prefix: document.getElementById('rep-form-dst-prefix').value.trim() || null,
    in_if_name: document.getElementById('rep-form-in-if').value.trim() || null,
    dst_country: document.getElementById('rep-form-country').value.trim() || null,
    time_window_minutes: parseInt(document.getElementById('rep-form-window').value || 60)
  };

  const payload = {
    name: name,
    description: document.getElementById('rep-form-desc').value.trim(),
    schedule: document.getElementById('rep-form-schedule').value,
    conditions: conditions,
    recipients: recipients,
    webhook_url: document.getElementById('rep-form-webhook').value.trim(),
    status: 'ACTIVE'
  };

  try {
    const res = await fetch('/api/v1/reports', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    showToast(`Report '${payload.name}' saved and scheduled!`, 'success');
    closeCreateReportModal();
    loadReports();
  } catch (e) {
    showToast('Failed to save report', 'error');
  }
}

// ================= NOTIFICATION CENTER =================

async function openNotificationModal() {
  document.getElementById('modal-notification').classList.remove('hidden');
  try {
    const res = await fetch('/api/v1/notifications');
    const logs = await res.json();
    const listEl = document.getElementById('list-notifications-log');
    document.getElementById('badge-notification-count').innerText = logs.length;

    listEl.innerHTML = (logs || []).map(l => `
      <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-start justify-between">
        <div class="space-y-0.5">
          <div class="font-bold text-white text-xs">${l.summary || l.type}</div>
          <div class="text-[10px] text-slate-500 font-mono">${new Date(l.timestamp * 1000).toLocaleString()}</div>
        </div>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.email_status === 'SENT' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-cyan-500/20 text-cyan-400'}">${l.email_status || 'LOGGED'}</span>
      </div>
    `).join('') || '<div class="p-4 text-center text-slate-500">No alert logs</div>';
  } catch (e) {
    console.error('Failed to load notifications:', e);
  }
}

function closeNotificationModal() {
  document.getElementById('modal-notification').classList.add('hidden');
}

async function dispatchTestNotification() {
  const email = document.getElementById('test-notif-email').value.trim();
  const webhook = document.getElementById('test-notif-webhook').value.trim();

  if (!email && !webhook) {
    alert('Please enter at least an email address or webhook URL.');
    return;
  }

  try {
    showToast('Dispatching test notification...', 'info');
    const params = new URLSearchParams();
    if (email) params.set('email', email);
    if (webhook) params.set('webhook', webhook);

    const res = await fetch(`/api/v1/notifications/test?${params.toString()}`, { method: 'POST' });
    const data = await res.json();
    showToast('Test notification dispatched! Check logs.', 'success');
    openNotificationModal();
  } catch (e) {
    showToast('Test notification failed', 'error');
  }
}

function openRouterConfigModal() {
  const modal = document.getElementById('modal-router-config');
  if (modal) modal.classList.remove('hidden');
}

function closeRouterConfigModal() {
  const modal = document.getElementById('modal-router-config');
  if (modal) modal.classList.add('hidden');
}

// ================= UTILITIES =================

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  const colorClass = type === 'success' ? 'bg-emerald-950/80 border-emerald-500/50 text-emerald-200' : (type === 'warning' ? 'bg-amber-950/80 border-amber-500/50 text-amber-200' : (type === 'error' ? 'bg-red-950/80 border-red-500/50 text-red-200' : 'bg-slate-900 border-slate-700 text-slate-200'));

  toast.className = `px-4 py-3 rounded-lg border shadow-xl flex items-center space-x-2 text-xs font-semibold transition transform duration-300 glass-card ${colorClass}`;
  toast.innerHTML = `<i class="fa-solid fa-circle-info"></i><span>${message}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ================= UPSTREAM & IIG TRAFFIC SHIFT ENGINE =================

let rawUpstreamsList = [];
let currentShiftSuggestions = [];
let currentActiveShiftIdx = 0;
let currentMultiParamData = [];
let currentMultiParamMode = 'IP_TO_IP';

async function loadUpstreamData() {
  try {
    const res = await fetch('/api/v1/upstreams?minutes=5');
    const data = await res.json();
    rawUpstreamsList = data.upstreams || [];

    const summary = data.summary || {};
    const capEl = document.getElementById('kpi-upstream-total-cap');
    const capSubEl = document.getElementById('kpi-upstream-total-cap-sub');
    const utilEl = document.getElementById('kpi-upstream-total-utilized');
    const utilPctEl = document.getElementById('kpi-upstream-util-pct');
    const headroomEl = document.getElementById('kpi-upstream-total-headroom');
    const congEl = document.getElementById('kpi-upstream-congested');
    const congSubEl = document.getElementById('kpi-upstream-congested-sub');
    const badgeIig = document.getElementById('badge-congested-iig');

    if (capEl) capEl.innerText = `${summary.total_capacity_tbps || 0} Tbps`;
    if (capSubEl) capSubEl.innerText = `${(summary.total_capacity_gbps || 0).toLocaleString()} Gbps Purchased Capacity`;
    if (utilEl) utilEl.innerText = `${(summary.total_utilized_gbps || 0).toLocaleString()} Gbps`;
    if (utilPctEl) utilPctEl.innerText = `${summary.overall_utilization_pct || 0}% Aggregate Utilization`;
    if (headroomEl) headroomEl.innerText = `${(summary.overall_headroom_gbps || 0).toLocaleString()} Gbps`;

    const congCount = summary.congested_count || 0;
    if (congEl) congEl.innerText = `${congCount} ${congCount === 1 ? 'Link' : 'Links'}`;
    if (congSubEl) {
      congSubEl.innerText = congCount > 0 ? `${congCount} IIG over warning threshold` : 'All IIG links operating within limits';
      congSubEl.className = congCount > 0 ? 'text-[11px] text-amber-400 mt-1 font-semibold' : 'text-[11px] text-emerald-400 mt-1';
    }

    if (badgeIig) {
      if (congCount > 0) {
        badgeIig.innerText = `! ${congCount}`;
        badgeIig.classList.remove('hidden');
      } else {
        badgeIig.classList.add('hidden');
      }
    }

    renderUpstreamTable(rawUpstreamsList);
    loadTrafficShiftSuggestions();
  } catch (e) {
    console.error('Failed to load upstream data:', e);
  }
}

function renderUpstreamTable(list) {
  const tbody = document.getElementById('table-upstreams-body');
  if (!tbody) return;

  if (!list || list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="py-6 text-center text-slate-500">No configured upstream providers found. Click "+ Add Upstream / Service" to create one.</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(u => {
    let serviceBadge = 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
    if (u.service_name === 'PNI') serviceBadge = 'bg-blue-500/20 text-blue-300 border-blue-500/30';
    else if (u.service_name === 'GGC' || u.service_name === 'FNA') serviceBadge = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
    else if (u.service_name === 'MixCDN' || u.service_name === 'Baishan') serviceBadge = 'bg-purple-500/20 text-purple-300 border-purple-500/30';
    else if (u.service_name === 'IX') serviceBadge = 'bg-amber-500/20 text-amber-300 border-amber-500/30';

    let barColor = 'bg-emerald-500';
    let textColor = 'text-emerald-400';
    if (u.health === 'CRITICAL') {
      barColor = 'bg-red-500 animate-pulse';
      textColor = 'text-red-400 font-bold';
    } else if (u.health === 'WARNING') {
      barColor = 'bg-amber-500';
      textColor = 'text-amber-400 font-bold';
    }

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-3">
          <div class="font-bold text-white flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full ${u.status === 'ACTIVE' ? 'bg-emerald-400' : 'bg-slate-500'}"></span>
            <span>${u.provider_name}</span>
          </div>
          <div class="text-[10px] text-slate-400 truncate max-w-xs">${u.description || u.id}</div>
        </td>
        <td class="py-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${serviceBadge}">${u.service_name}</span>
        </td>
        <td class="py-3 text-right font-semibold text-slate-200">${u.capacity_gbps.toLocaleString()} Gbps</td>
        <td class="py-3 text-right font-bold ${textColor}">${u.current_gbps.toLocaleString()} Gbps</td>
        <td class="py-3 text-right text-emerald-400">${u.headroom_gbps.toLocaleString()} Gbps</td>
        <td class="py-3">
          <div class="flex items-center space-x-2">
            <div class="flex-1 bg-slate-800 rounded-full h-2 overflow-hidden border border-slate-700">
              <div class="${barColor} h-2 rounded-full transition-all duration-500" style="width: ${Math.min(u.utilization_pct, 100)}%"></div>
            </div>
            <span class="w-12 text-right ${textColor}">${u.utilization_pct}%</span>
          </div>
        </td>
        <td class="py-3 text-center">
          <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${u.status === 'ACTIVE' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-slate-700 text-slate-400'}">${u.status}</span>
        </td>
        <td class="py-3 text-right">
          <div class="flex items-center justify-end space-x-1.5">
            <button onclick="editUpstream('${u.id}')" title="Edit Configuration" class="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-cyan-400 transition"><i class="fa-solid fa-pen text-xs"></i></button>
            <button onclick="deleteUpstream('${u.id}')" title="Delete" class="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-red-400 transition"><i class="fa-solid fa-trash text-xs"></i></button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function filterUpstreamServiceTable(svc) {
  // Update active chip style
  const container = document.getElementById('filter-chips-services');
  if (container) {
    container.querySelectorAll('button').forEach(btn => {
      if (btn.innerText.trim() === svc) {
        btn.className = 'px-2.5 py-1 rounded-lg bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 font-semibold';
      } else {
        btn.className = 'px-2.5 py-1 rounded-lg bg-slate-800 text-slate-400 hover:text-white';
      }
    });
  }

  if (svc === 'ALL') {
    renderUpstreamTable(rawUpstreamsList);
  } else {
    const filtered = rawUpstreamsList.filter(u => u.service_name === svc);
    renderUpstreamTable(filtered);
  }
}

async function loadTrafficShiftSuggestions() {
  const container = document.getElementById('container-shift-suggestions');
  if (!container) return;

  try {
    const res = await fetch('/api/v1/upstreams/shift-suggestions?minutes=5');
    const suggestions = await res.json();
    currentShiftSuggestions = suggestions || [];

    if (!suggestions || suggestions.length === 0) {
      container.innerHTML = `
        <div class="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex items-center justify-between text-xs font-mono">
          <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center border border-emerald-500/30">
              <i class="fa-solid fa-circle-check text-base"></i>
            </div>
            <div>
              <div class="font-bold text-white font-sans text-sm">All Upstream IIG Bandwidths Balanced</div>
              <div class="text-slate-400 text-xs mt-0.5">All 5+ upstream providers are operating below 80% threshold. No traffic rebalancing required.</div>
            </div>
          </div>
          <span class="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[11px] border border-emerald-500/30">BALANCED</span>
        </div>
      `;
      return;
    }

    container.innerHTML = suggestions.map((s, idx) => {
      const isCrit = s.priority === 'HIGH';
      const badgeClass = isCrit ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      const borderClass = isCrit ? 'border-red-500/50 bg-red-950/30' : 'border-amber-500/50 bg-amber-950/30';

      const asnsHtml = (s.candidate_asns || []).map(a =>
        `<span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 text-[10px]">
          <strong>${a.name}</strong> (${a.sample_prefix}) · <span class="text-amber-400 font-bold">~${a.estimated_traffic_gbps} Gbps</span>
        </span>`
      ).join(' ');

      return `
        <div class="p-5 rounded-xl border ${borderClass} shadow-xl space-y-3">
          <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div class="flex items-start space-x-3">
              <div class="w-9 h-9 rounded-lg ${badgeClass} border flex items-center justify-center mt-0.5">
                <i class="fa-solid fa-triangle-exclamation text-base ${isCrit ? 'animate-bounce' : ''}"></i>
              </div>
              <div>
                <div class="flex items-center space-x-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}">${s.priority} CONGESTION</span>
                  <span class="text-sm font-bold text-white">${s.title}</span>
                </div>
                <p class="text-xs text-slate-300 mt-1">${s.reason}</p>
              </div>
            </div>
            <div class="flex items-center space-x-2">
              <button onclick="openShiftDetailsModal(${idx})" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold flex items-center space-x-1.5 transition">
                <i class="fa-solid fa-code text-cyan-400"></i>
                <span>View BGP Policy</span>
              </button>
              <button onclick="executeShiftDirectly(${idx})" class="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs flex items-center space-x-1.5 shadow-lg shadow-amber-600/30 transition">
                <i class="fa-solid fa-bolt"></i>
                <span>Deploy Traffic Shift</span>
              </button>
            </div>
          </div>

          <div class="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
            <span class="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">Candidate ASNs to Divert:</span>
            <div class="flex flex-wrap gap-1.5 font-mono">
              ${asnsHtml}
            </div>
          </div>
        </div>
      `;
    }).join('');
  } catch (e) {
    console.error('Failed to load traffic shift suggestions:', e);
  }
}

function openShiftDetailsModal(idx) {
  const s = currentShiftSuggestions[idx];
  if (!s) return;
  currentActiveShiftIdx = idx;

  const modal = document.getElementById('modal-traffic-shift-details');
  const content = document.getElementById('modal-shift-content');
  if (!modal || !content) return;

  content.innerHTML = `
    <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
      <div class="text-sm font-bold text-white">${s.title}</div>
      <div class="text-xs text-slate-400">${s.reason}</div>
      <div class="grid grid-cols-2 gap-3 text-xs pt-1">
        <div>
          <span class="text-slate-500">Source Congested IIG:</span>
          <div class="text-red-400 font-bold">${s.source_upstream.provider_name} (${s.source_upstream.service_name}) - ${s.source_upstream.utilization_pct}% (${s.source_upstream.current_gbps}G / ${s.source_upstream.capacity_gbps}G)</div>
        </div>
        <div>
          <span class="text-slate-500">Target Absorption IIG:</span>
          <div class="text-emerald-400 font-bold">${s.target_upstream.provider_name} (${s.target_upstream.service_name}) - ${s.target_upstream.headroom_gbps}G Headroom</div>
        </div>
      </div>
    </div>

    <div>
      <div class="text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
        <span>BGP Routing Configuration (Cisco IOS-XR / ASR 9000)</span>
        <button onclick="copyToClipboard('code-bgp-cisco')" class="text-cyan-400 hover:text-cyan-300 text-[11px]"><i class="fa-solid fa-copy mr-1"></i>Copy</button>
      </div>
      <pre id="code-bgp-cisco" class="p-3 rounded bg-slate-950 text-cyan-300 text-[11px] border border-slate-800 overflow-x-auto">${s.bgp_commands.cisco_iosxr}</pre>
    </div>

    <div>
      <div class="text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
        <span>BGP Routing Configuration (Juniper Junos PTX / MX)</span>
        <button onclick="copyToClipboard('code-bgp-juniper')" class="text-cyan-400 hover:text-cyan-300 text-[11px]"><i class="fa-solid fa-copy mr-1"></i>Copy</button>
      </div>
      <pre id="code-bgp-juniper" class="p-3 rounded bg-slate-950 text-emerald-300 text-[11px] border border-slate-800 overflow-x-auto">${s.bgp_commands.juniper_junos}</pre>
    </div>
  `;

  modal.classList.remove('hidden');
}

function closeShiftDetailsModal() {
  const modal = document.getElementById('modal-traffic-shift-details');
  if (modal) modal.classList.add('hidden');
}

function copyToClipboard(elemId) {
  const el = document.getElementById(elemId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    showToast('BGP command copied to clipboard!', 'success');
  });
}

async function executeCurrentShift() {
  closeShiftDetailsModal();
  await executeShiftDirectly(currentActiveShiftIdx);
}

async function executeShiftDirectly(idx) {
  const s = currentShiftSuggestions[idx];
  if (!s) return;

  try {
    showToast(`Deploying BGP traffic shift from ${s.source_upstream.provider_name} to ${s.target_upstream.provider_name}...`, 'info');
    const res = await fetch('/api/v1/upstreams/shift-execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(s)
    });
    const data = await res.json();
    showToast('Traffic shift policy dispatched! BGP local-preference updated.', 'success');
    loadUpstreamData();
  } catch (e) {
    showToast('Failed to deploy traffic shift', 'error');
  }
}

// ================= MULTI-PARAMETER FLOW MAPPING =================

async function loadMultiParameterFlows(groupBy = 'IP_TO_IP') {
  currentMultiParamMode = groupBy;

  // Update button highlights
  ['ip-to-ip', 'prefix', 'device', 'asn', 'up-svc'].forEach(key => {
    const btn = document.getElementById(`btn-map-${key}`);
    if (btn) btn.className = 'px-2.5 py-1 rounded bg-slate-800 text-slate-400 hover:text-white';
  });

  if (groupBy === 'IP_TO_IP') {
    const b = document.getElementById('btn-map-ip-to-ip');
    if (b) b.className = 'px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-semibold';
    document.getElementById('th-map-src').innerText = 'Source IP';
    document.getElementById('th-map-dst').innerText = 'Destination IP';
  } else if (groupBy === 'PREFIX_TO_PREFIX') {
    const b = document.getElementById('btn-map-prefix');
    if (b) b.className = 'px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-semibold';
    document.getElementById('th-map-src').innerText = 'Source Subnet Prefix (/24)';
    document.getElementById('th-map-dst').innerText = 'Destination Subnet Prefix (/24)';
  } else if (groupBy === 'DEVICE_TO_IP') {
    const b = document.getElementById('btn-map-device');
    if (b) b.className = 'px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-semibold';
    document.getElementById('th-map-src').innerText = 'Edge Router / Device';
    document.getElementById('th-map-dst').innerText = 'Destination IP';
  } else if (groupBy === 'ASN_TO_ASN') {
    const b = document.getElementById('btn-map-asn');
    if (b) b.className = 'px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-semibold';
    document.getElementById('th-map-src').innerText = 'Origin Autonomous System (ASN)';
    document.getElementById('th-map-dst').innerText = 'Destination Autonomous System (ASN)';
  } else if (groupBy === 'UPSTREAM_TO_SERVICE') {
    const b = document.getElementById('btn-map-up-svc');
    if (b) b.className = 'px-2.5 py-1 rounded bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-semibold';
    document.getElementById('th-map-src').innerText = 'Carrier Upstream Provider';
    document.getElementById('th-map-dst').innerText = 'Delivery Service Pool';
  }

  const tbody = document.getElementById('table-multiparam-flows-body');
  if (tbody) tbody.innerHTML = `<tr><td colspan="8" class="py-6 text-center text-slate-500">Querying multi-parameter flow correlation...</td></tr>`;

  try {
    const res = await fetch(`/api/v1/upstreams/multi-parameter-flows?group_by=${groupBy}&minutes=60&limit=30`);
    const data = await res.json();
    currentMultiParamData = data.flows || [];

    if (!currentMultiParamData || currentMultiParamData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="py-6 text-center text-slate-500">No active flow records found for this parameter grouping.</td></tr>`;
      return;
    }

    tbody.innerHTML = currentMultiParamData.map(f => `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-2.5 font-bold text-white">${f.source_entity || 'N/A'}</td>
        <td class="py-2.5 text-slate-200">${f.destination_entity || 'N/A'}</td>
        <td class="py-2.5 font-semibold text-cyan-300">${f.upstream_provider || 'Tata Communications'}</td>
        <td class="py-2.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">${f.service_name || 'IPT'}</span></td>
        <td class="py-2.5 text-right font-bold text-cyan-400">${f.gbps || (f.mbps / 1000).toFixed(3)} Gbps</td>
        <td class="py-2.5 text-right text-slate-300">${(f.mbps || 0).toLocaleString()} Mbps</td>
        <td class="py-2.5 text-right text-slate-400">${(f.packets || 0).toLocaleString()}</td>
        <td class="py-2.5 text-right text-slate-400">${(f.flow_count || 1).toLocaleString()}</td>
      </tr>
    `).join('');
  } catch (e) {
    console.error('Failed to load multi-parameter flows:', e);
  }
}

function exportMultiParamCSV() {
  if (!currentMultiParamData || currentMultiParamData.length === 0) {
    showToast('No flow mapping data available to export.', 'warning');
    return;
  }

  const headers = ['Source Entity', 'Destination Entity', 'Upstream Provider', 'Service Name', 'Gbps', 'Mbps', 'Packets', 'Flow Count'];
  const rows = currentMultiParamData.map(f => [
    `"${f.source_entity || ''}"`,
    `"${f.destination_entity || ''}"`,
    `"${f.upstream_provider || ''}"`,
    `"${f.service_name || ''}"`,
    f.gbps || 0,
    f.mbps || 0,
    f.packets || 0,
    f.flow_count || 1
  ]);

  const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', `AegisFlow_TrafficMapping_${currentMultiParamMode}_${Date.now()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast('Flow mapping CSV exported successfully.', 'success');
}

// ================= MODAL CONTROLLERS =================

function openAddUpstreamModal() {
  document.getElementById('modal-up-id').value = '';
  document.getElementById('modal-up-title').innerText = 'Add Upstream Provider & Service Capacity';
  document.getElementById('modal-up-provider-name').value = '';
  document.getElementById('modal-up-service-name').value = 'IPT';
  document.getElementById('modal-up-capacity-gbps').value = '200';
  document.getElementById('modal-up-warn-th').value = '80';
  document.getElementById('modal-up-crit-th').value = '90';
  document.getElementById('modal-up-cost').value = '0.45';
  document.getElementById('modal-up-asns').value = '';
  document.getElementById('modal-up-interfaces').value = '';
  document.getElementById('wrapper-custom-service').classList.add('hidden');
  document.getElementById('modal-upstream-provider').classList.remove('hidden');
}

function closeUpstreamModal() {
  document.getElementById('modal-upstream-provider').classList.add('hidden');
}

function onServiceTypeChange(val) {
  const customWrapper = document.getElementById('wrapper-custom-service');
  if (val === 'CUSTOM') {
    customWrapper.classList.remove('hidden');
  } else {
    customWrapper.classList.add('hidden');
  }
}

function setUpstreamPreset(provider, service, cap) {
  document.getElementById('modal-up-provider-name').value = provider;
  document.getElementById('modal-up-service-name').value = service;
  document.getElementById('modal-up-capacity-gbps').value = cap;
  onServiceTypeChange(service);
}

function editUpstream(id) {
  const u = rawUpstreamsList.find(x => x.id === id);
  if (!u) return;

  document.getElementById('modal-up-id').value = u.id;
  document.getElementById('modal-up-title').innerText = `Edit ${u.provider_name} (${u.service_name})`;
  document.getElementById('modal-up-provider-name').value = u.provider_name;
  document.getElementById('modal-up-service-name').value = u.service_name;
  document.getElementById('modal-up-capacity-gbps').value = u.capacity_gbps;
  document.getElementById('modal-up-warn-th').value = u.warn_threshold_pct;
  document.getElementById('modal-up-crit-th').value = u.crit_threshold_pct;
  document.getElementById('modal-up-cost').value = u.cost_per_mbps || 0;
  document.getElementById('modal-up-asns').value = (u.associated_asns || []).join(', ');
  document.getElementById('modal-up-interfaces').value = (u.associated_interfaces || []).join(', ');
  onServiceTypeChange(u.service_name);

  document.getElementById('modal-upstream-provider').classList.remove('hidden');
}

async function saveUpstreamProvider() {
  const uid = document.getElementById('modal-up-id').value.trim();
  const provider = document.getElementById('modal-up-provider-name').value.trim();
  let service = document.getElementById('modal-up-service-name').value;
  if (service === 'CUSTOM') {
    service = document.getElementById('modal-up-custom-service').value.trim().toUpperCase() || 'CUSTOM';
  }
  const cap = parseFloat(document.getElementById('modal-up-capacity-gbps').value) || 100.0;
  const warn = parseFloat(document.getElementById('modal-up-warn-th').value) || 80.0;
  const crit = parseFloat(document.getElementById('modal-up-crit-th').value) || 90.0;
  const cost = parseFloat(document.getElementById('modal-up-cost').value) || 0.40;

  const asnsRaw = document.getElementById('modal-up-asns').value;
  const asns = asnsRaw.split(',').map(x => parseInt(x.trim())).filter(x => !isNaN(x));

  const ifacesRaw = document.getElementById('modal-up-interfaces').value;
  const ifaces = ifacesRaw.split(',').map(x => x.trim()).filter(x => x.length > 0);

  if (!provider) {
    alert('Please enter an Upstream Provider Name.');
    return;
  }

  const payload = {
    provider_name: provider,
    service_name: service,
    capacity_gbps: cap,
    warn_threshold_pct: warn,
    crit_threshold_pct: crit,
    cost_per_mbps: cost,
    associated_asns: asns,
    associated_interfaces: ifaces,
    status: 'ACTIVE'
  };

  try {
    if (uid) {
      await fetch(`/api/v1/upstreams/${uid}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showToast(`Updated upstream provider ${provider} (${service})`, 'success');
    } else {
      await fetch('/api/v1/upstreams', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      showToast(`Created upstream provider ${provider} (${service})`, 'success');
    }
    closeUpstreamModal();
    loadUpstreamData();
  } catch (e) {
    showToast('Failed to save upstream provider', 'error');
  }
}

async function deleteUpstream(id) {
  if (!confirm(`Are you sure you want to remove upstream provider ${id}?`)) return;
  try {
    await fetch(`/api/v1/upstreams/${id}`, { method: 'DELETE' });
    showToast('Upstream provider removed', 'success');
    loadUpstreamData();
  } catch (e) {
    showToast('Failed to delete upstream', 'error');
  }
}
