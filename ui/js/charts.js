/**
 * ECharts Configuration and Visualizations for AegisFlow
 */

const darkTheme = {
  backgroundColor: 'transparent',
  textStyle: { color: '#94a3b8', fontFamily: '-apple-system, sans-serif' },
  title: { textStyle: { color: '#f8fafc' } },
  tooltip: {
    backgroundColor: 'rgba(15, 23, 42, 0.95)',
    borderColor: '#334155',
    textStyle: { color: '#f8fafc' },
    padding: [10, 14]
  }
};

let chartThroughput = null;
let chartAppPie = null;
let chartDirectionPie = null;
let chartPeeringRatio = null;
let chartSiteToSite = null;
let chartQosPie = null;
let chartCapacity = null;
let chartPatternTimeseries = null;
let chartSankey = null;
let chartRankedBar = null;
let chartTreemap = null;
let chartSunburst = null;

function initCharts() {
  const elThroughput = document.getElementById('chart-throughput');
  if (elThroughput) chartThroughput = echarts.init(elThroughput);

  const elApp = document.getElementById('chart-applications-pie');
  if (elApp) chartAppPie = echarts.init(elApp);

  const elDir = document.getElementById('chart-direction-pie');
  if (elDir) chartDirectionPie = echarts.init(elDir);

  const elPeer = document.getElementById('chart-peering-ratio');
  if (elPeer) chartPeeringRatio = echarts.init(elPeer);

  const elSite = document.getElementById('chart-site-to-site');
  if (elSite) chartSiteToSite = echarts.init(elSite);

  const elQos = document.getElementById('chart-qos-distribution');
  if (elQos) chartQosPie = echarts.init(elQos);

  const elCap = document.getElementById('chart-capacity-forecast');
  if (elCap) chartCapacity = echarts.init(elCap);

  const elPattern = document.getElementById('chart-pattern-timeseries');
  if (elPattern) chartPatternTimeseries = echarts.init(elPattern);

  const elSankey = document.getElementById('chart-pattern-sankey');
  if (elSankey) chartSankey = echarts.init(elSankey);

  const elBar = document.getElementById('chart-pattern-bar');
  if (elBar) chartRankedBar = echarts.init(elBar);

  const elTreemap = document.getElementById('chart-pattern-treemap');
  if (elTreemap) chartTreemap = echarts.init(elTreemap);

  const elSunburst = document.getElementById('chart-pattern-sunburst');
  if (elSunburst) chartSunburst = echarts.init(elSunburst);

  window.addEventListener('resize', () => {
    [chartThroughput, chartAppPie, chartDirectionPie, chartPeeringRatio, chartSiteToSite, 
     chartQosPie, chartCapacity, chartPatternTimeseries, chartSankey, chartRankedBar, chartTreemap, chartSunburst]
      .forEach(c => c && c.resize());
  });
}

function updateThroughputChart(timeseriesData) {
  if (!chartThroughput) return;

  const times = timeseriesData.map(d => {
    const dt = new Date(d.time_point);
    return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  });
  const mbpsVals = timeseriesData.map(d => Math.round(d.mbps));

  const option = {
    ...darkTheme,
    grid: { top: 20, right: 30, bottom: 25, left: 55 },
    tooltip: {
      trigger: 'axis',
      formatter: '{b}<br/><span style="color:#06b6d4">●</span> Wire Rate: <b>{c} Mbps</b>'
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLabel: { color: '#94a3b8', formatter: '{value} M' }
    },
    series: [{
      name: 'Throughput',
      type: 'line',
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 3, color: '#06b6d4' },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(6, 182, 212, 0.45)' },
          { offset: 1, color: 'rgba(6, 182, 212, 0.01)' }
        ])
      },
      data: mbpsVals
    }]
  };
  chartThroughput.setOption(option);
}

function updateAppPieChart(apps) {
  if (!chartAppPie) return;
  const data = apps.map(a => ({ name: a.application, value: a.bytes }));
  const colors = ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#64748b'];

  const option = {
    ...darkTheme,
    tooltip: { trigger: 'item', formatter: '{b}: {d}%' },
    series: [{
      name: 'Application',
      type: 'pie',
      radius: ['45%', '70%'],
      avoidLabelOverlap: false,
      itemStyle: { borderRadius: 6, borderColor: '#0f172a', borderWidth: 2 },
      color: colors,
      label: { show: false },
      data: data
    }]
  };
  chartAppPie.setOption(option);
}

function updateDirectionPieChart(data) {
  if (!chartDirectionPie) return;
  const colors = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'];
  const option = {
    ...darkTheme,
    tooltip: { trigger: 'item', formatter: '{b}: {d}%' },
    series: [{
      name: 'Direction',
      type: 'pie',
      radius: ['45%', '70%'],
      avoidLabelOverlap: false,
      itemStyle: { borderRadius: 6, borderColor: '#0f172a', borderWidth: 2 },
      color: colors,
      label: { show: false },
      data: data
    }]
  };
  chartDirectionPie.setOption(option);
}

function updatePeeringRatioChart(categories) {
  if (!chartPeeringRatio) return;
  const data = categories.map(c => ({ name: c.dst_as_category || 'Other', value: c.bytes }));
  const colors = ['#10b981', '#ef4444', '#3b82f6', '#8b5cf6'];

  const option = {
    ...darkTheme,
    tooltip: { trigger: 'item', formatter: '{b}: {d}%' },
    legend: { bottom: 0, textStyle: { color: '#94a3b8', fontSize: 11 } },
    series: [{
      name: 'Transit vs Peering',
      type: 'pie',
      radius: ['40%', '65%'],
      center: ['50%', '42%'],
      itemStyle: { borderRadius: 6, borderColor: '#0f172a', borderWidth: 2 },
      color: colors,
      label: { show: false },
      data: data
    }]
  };
  chartPeeringRatio.setOption(option);
}

function updateSiteToSiteChart(sites) {
  if (!chartSiteToSite) return;
  const categories = sites.map(s => `${s.src_site} → ${s.dst_site_or_cloud}`);
  const vals = sites.map(s => s.mbps);

  const option = {
    ...darkTheme,
    grid: { top: 20, right: 30, bottom: 60, left: 60 },
    tooltip: { trigger: 'axis', formatter: '{b}<br/>Throughput: <b>{c} Mbps</b>' },
    xAxis: {
      type: 'category',
      data: categories,
      axisLabel: { rotate: 30, color: '#94a3b8', fontSize: 10 },
      axisLine: { lineStyle: { color: '#334155' } }
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLabel: { color: '#94a3b8', formatter: '{value} M' }
    },
    series: [{
      type: 'bar',
      barWidth: '40%',
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#8b5cf6' },
          { offset: 1, color: '#3b82f6' }
        ]),
        borderRadius: [4, 4, 0, 0]
      },
      data: vals
    }]
  };
  chartSiteToSite.setOption(option);
}

function updateQosChart(qosData) {
  if (!chartQosPie) return;
  const data = qosData.map(q => ({ name: q.dscp_name, value: q.bytes }));
  const colors = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#64748b'];

  const option = {
    ...darkTheme,
    tooltip: { trigger: 'item', formatter: '{b}: {d}%' },
    series: [{
      name: 'DSCP Class',
      type: 'pie',
      radius: ['45%', '70%'],
      itemStyle: { borderRadius: 6, borderColor: '#0f172a', borderWidth: 2 },
      color: colors,
      label: { show: false },
      data: data
    }]
  };
  chartQosPie.setOption(option);
}

function updateCapacityChart(forecast) {
  if (!chartCapacity) return;

  const points = forecast.data_points || [];
  const days = points.map(p => p.day);
  const peaks = points.map(p => p.peak_mbps);

  // Add 3 projected future days
  const lastDay = new Date(days[days.length - 1] || Date.now());
  const futureDays = [];
  const futureVals = [];
  for (let i = 1; i <= 7; i++) {
    const nextDate = new Date(lastDay);
    nextDate.setDate(lastDay.getDate() + (i * 5));
    futureDays.push(nextDate.toISOString().split('T')[0]);
    futureVals.push(peaks[peaks.length - 1] * (1 + (i * 0.035)));
  }

  const allDays = [...days, ...futureDays];
  const historySeries = [...peaks, ...Array(futureDays.length).fill(null)];
  const forecastSeries = [...Array(days.length - 1).fill(null), peaks[peaks.length - 1], ...futureVals];
  const threshold85 = Array(allDays.length).fill(forecast.threshold_85_mbps);

  const option = {
    ...darkTheme,
    grid: { top: 20, right: 30, bottom: 30, left: 60 },
    legend: { textStyle: { color: '#94a3b8' } },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: allDays,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#94a3b8', fontSize: 10 }
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLabel: { color: '#94a3b8', formatter: '{value} M' }
    },
    series: [
      {
        name: 'Historical Peak',
        type: 'line',
        data: historySeries,
        lineStyle: { color: '#06b6d4', width: 2 },
        itemStyle: { color: '#06b6d4' }
      },
      {
        name: 'Projected Trend',
        type: 'line',
        data: forecastSeries,
        lineStyle: { color: '#f59e0b', width: 2, type: 'dashed' },
        itemStyle: { color: '#f59e0b' }
      },
      {
        name: '85% Capacity Limit',
        type: 'line',
        data: threshold85,
        lineStyle: { color: '#ef4444', width: 2, type: 'dotted' },
        showSymbol: false
      }
    ]
  };
  chartCapacity.setOption(option);
}

function updatePatternTimeseriesChart(timeseriesData) {
  if (!chartPatternTimeseries) {
    const el = document.getElementById('chart-pattern-timeseries');
    if (el) chartPatternTimeseries = echarts.init(el);
  }
  if (!chartPatternTimeseries) return;

  const times = timeseriesData.map(d => {
    const dt = new Date(d.time_point);
    return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  });
  const mbpsVals = timeseriesData.map(d => Math.round(d.mbps));

  const option = {
    ...darkTheme,
    grid: { top: 20, right: 30, bottom: 25, left: 55 },
    tooltip: {
      trigger: 'axis',
      formatter: '{b}<br/><span style="color:#06b6d4">●</span> Pattern Rate: <b>{c} Mbps</b>'
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLabel: { color: '#94a3b8', formatter: '{value} M' }
    },
    series: [{
      name: 'Filtered Wire-Rate',
      type: 'line',
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 3, color: '#38bdf8' },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(56, 189, 248, 0.45)' },
          { offset: 1, color: 'rgba(56, 189, 248, 0.02)' }
        ])
      },
      data: mbpsVals
    }]
  };
  chartPatternTimeseries.setOption(option);
}

function renderSankeyChart(nodes, links, viewName) {
  let el = document.getElementById('chart-pattern-sankey');
  if (!el) return;
  if (!chartSankey) chartSankey = echarts.init(el);

  const option = {
    ...darkTheme,
    title: {
      text: viewName || 'CDN Traffic Network Entry and Exit ★ Saved View',
      left: 15,
      top: 10,
      textStyle: { color: '#f8fafc', fontSize: 13, fontWeight: 600 }
    },
    tooltip: {
      trigger: 'item',
      triggerOn: 'mousemove',
      formatter: function(params) {
        if (params.dataType === 'edge') {
          const sName = params.data.source.replace(/^\d+::/, '').replace(/ \((Entry|Exit)\)/, '');
          const tName = params.data.target.replace(/^\d+::/, '').replace(/ \((Entry|Exit)\)/, '');
          return `<div class="font-sans text-xs">
            <div class="text-slate-400 font-semibold mb-1">Flow Link</div>
            <div class="text-white font-mono text-sm">${sName} <span class="text-cyan-400">➔</span> ${tName}</div>
            <div class="mt-2 text-cyan-400 font-bold">${params.data.value.toLocaleString()} Mbps</div>
          </div>`;
        } else {
          const displayName = (params.data.display || params.data.name).replace(/^\d+::/, '').replace(/ \((Entry|Exit)\)/, '');
          const stageName = params.data.stage || 'Stage';
          return `<div class="font-sans text-xs">
            <div class="text-slate-400 font-semibold">${stageName}</div>
            <div class="text-white font-mono text-sm font-bold">${displayName}</div>
            <div class="mt-1 text-emerald-400 font-bold">Aggregated: ${(params.value || 0).toLocaleString()} Mbps</div>
          </div>`;
        }
      }
    },
    series: [{
      type: 'sankey',
      layout: 'none',
      top: 55,
      bottom: 25,
      left: 25,
      right: 140,
      nodeWidth: 16,
      nodeGap: 14,
      nodeAlign: 'justify',
      draggable: true,
      focusNodeAdjacency: 'allEdges',
      data: nodes,
      links: links,
      label: {
        color: '#f1f5f9',
        fontSize: 11,
        fontFamily: 'monospace',
        formatter: function(params) {
          const raw = params.data.display || params.data.name;
          return raw.replace(/^\d+::/, '').replace(/ \((Entry|Exit)\)/, '');
        }
      },
      lineStyle: {
        color: 'gradient',
        curveness: 0.5,
        opacity: 0.38
      },
      itemStyle: {
        borderWidth: 1,
        borderColor: 'rgba(255,255,255,0.2)'
      }
    }]
  };
  chartSankey.setOption(option, true);
  chartSankey.resize();
}

function renderRankedBarChart(barsData, barCategory = 'providers') {
  let el = document.getElementById('chart-pattern-bar');
  if (!el) return;
  if (!chartRankedBar) chartRankedBar = echarts.init(el);

  const dataset = (barsData && barsData[barCategory]) ? barsData[barCategory] : (barsData?.providers || { labels: [], values: [], colors: [] });
  const labels = [...(dataset.labels || [])].reverse();
  const values = [...(dataset.values || [])].reverse();
  const colors = [...(dataset.colors || [])].reverse();

  const titleMap = {
    providers: 'Top CDN & Autonomous System Providers (Wire-Rate Mbps)',
    prefixes: 'Top Destination IP Prefixes & Subnets (Wire-Rate Mbps)',
    interconnects: 'Interconnect & Peering Routing Distribution (Wire-Rate Mbps)'
  };

  const option = {
    ...darkTheme,
    title: {
      text: titleMap[barCategory] || 'Ranked Bandwidth Distribution',
      left: 15,
      top: 10,
      textStyle: { color: '#f8fafc', fontSize: 13, fontWeight: 600 }
    },
    grid: { top: 50, right: 90, bottom: 25, left: 160 },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      formatter: function(params) {
        const item = params[0];
        return `<div class="font-sans text-xs">
          <div class="text-slate-400 font-mono">${item.name}</div>
          <div class="text-cyan-400 font-bold text-sm mt-1">${(item.value || 0).toLocaleString()} Mbps</div>
        </div>`;
      }
    },
    xAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLabel: { color: '#94a3b8', formatter: '{value} M' }
    },
    yAxis: {
      type: 'category',
      data: labels,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#cbd5e1', fontSize: 11, fontFamily: 'monospace' }
    },
    series: [{
      name: 'Throughput',
      type: 'bar',
      barWidth: 16,
      itemStyle: {
        borderRadius: [0, 4, 4, 0],
        color: function(params) {
          return colors[params.dataIndex] || '#06b6d4';
        }
      },
      label: {
        show: true,
        position: 'right',
        color: '#94a3b8',
        fontSize: 10,
        fontFamily: 'monospace',
        formatter: '{c} Mbps'
      },
      data: values
    }]
  };
  chartRankedBar.setOption(option, true);
  chartRankedBar.resize();
}

function renderTreemapChart(treemapData) {
  let el = document.getElementById('chart-pattern-treemap');
  if (!el) return;
  if (!chartTreemap) chartTreemap = echarts.init(el);

  const option = {
    ...darkTheme,
    title: {
      text: 'Hierarchical Bandwidth Treemap Matrix (Drilldown View)',
      left: 15,
      top: 10,
      textStyle: { color: '#f8fafc', fontSize: 13, fontWeight: 600 }
    },
    tooltip: {
      formatter: function(info) {
        return `<div class="font-sans text-xs">
          <div class="text-slate-400 font-semibold">${info.name}</div>
          <div class="text-cyan-400 font-bold text-sm mt-1">${(info.value || 0).toLocaleString()} Mbps</div>
        </div>`;
      }
    },
    series: [{
      name: 'Traffic Volume',
      type: 'treemap',
      top: 50,
      bottom: 20,
      left: 20,
      right: 20,
      roam: false,
      leafDepth: 2,
      drillDownIcon: '▶',
      visibleMin: 50,
      label: {
        show: true,
        formatter: '{b}\n{c} M',
        color: '#f8fafc',
        fontSize: 11,
        fontFamily: 'monospace'
      },
      itemStyle: {
        borderColor: '#0f172a',
        borderWidth: 2,
        gapWidth: 2
      },
      levels: [
        { itemStyle: { borderColor: '#1e293b', borderWidth: 3, gapWidth: 3 } },
        { colorSaturation: [0.35, 0.65], itemStyle: { borderColorSaturation: 0.7, gapWidth: 2 } }
      ],
      data: treemapData.children || []
    }]
  };
  chartTreemap.setOption(option, true);
  chartTreemap.resize();
}

function renderSunburstChart(sunburstData) {
  let el = document.getElementById('chart-pattern-sunburst');
  if (!el) return;
  if (!chartSunburst) chartSunburst = echarts.init(el);

  const option = {
    ...darkTheme,
    title: {
      text: 'Radial Multi-Ring Flow Sunburst Hierarchy',
      left: 15,
      top: 10,
      textStyle: { color: '#f8fafc', fontSize: 13, fontWeight: 600 }
    },
    tooltip: {
      trigger: 'item',
      formatter: function(params) {
        return `<div class="font-sans text-xs">
          <div class="text-slate-400">${params.treePathInfo ? params.treePathInfo.map(p => p.name).filter(Boolean).join(' ➔ ') : params.name}</div>
          <div class="text-cyan-400 font-bold text-sm mt-1">${(params.value || 0).toLocaleString()} Mbps</div>
        </div>`;
      }
    },
    series: [{
      type: 'sunburst',
      data: sunburstData,
      radius: ['15%', '85%'],
      label: {
        rotate: 'radial',
        color: '#f8fafc',
        fontSize: 10,
        fontFamily: 'monospace'
      },
      itemStyle: {
        borderRadius: 4,
        borderWidth: 2,
        borderColor: '#0f172a'
      }
    }]
  };
  chartSunburst.setOption(option, true);
  chartSunburst.resize();
}

function renderAreaTrendChart(timeseriesData) {
  let el = document.getElementById('chart-pattern-timeseries');
  if (!el) return;
  if (!chartPatternTimeseries) chartPatternTimeseries = echarts.init(el);

  const times = timeseriesData.map(d => {
    if (d.time_point && d.time_point.includes('T')) {
      const dt = new Date(d.time_point);
      return dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return d.time_point;
  });
  const mbpsVals = timeseriesData.map(d => Math.round(d.mbps));

  const option = {
    ...darkTheme,
    title: {
      text: 'Dynamic Time-Series Wire-Rate Wave (1-Min Resolution)',
      left: 15,
      top: 10,
      textStyle: { color: '#f8fafc', fontSize: 13, fontWeight: 600 }
    },
    grid: { top: 50, right: 30, bottom: 25, left: 55 },
    tooltip: {
      trigger: 'axis',
      formatter: '{b}<br/><span style="color:#06b6d4">●</span> Wire Rate: <b>{c} Mbps</b>'
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLine: { lineStyle: { color: '#334155' } },
      axisLabel: { color: '#94a3b8', fontSize: 11 }
    },
    yAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#334155' } },
      splitLine: { lineStyle: { color: '#1e293b' } },
      axisLabel: { color: '#94a3b8', formatter: '{value} M' }
    },
    series: [{
      name: 'Filtered Wire-Rate',
      type: 'line',
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 3, color: '#06b6d4' },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(6, 182, 212, 0.45)' },
          { offset: 1, color: 'rgba(6, 182, 212, 0.02)' }
        ])
      },
      data: mbpsVals
    }]
  };
  chartPatternTimeseries.setOption(option);
  chartPatternTimeseries.resize();
}
