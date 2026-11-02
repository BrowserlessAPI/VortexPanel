// VortexPanel Apps - small shared helpers for App pages (loaded by the core page,
// before any App script). Apps use these instead of their own copies.

function vpaNum(n) { n = Number(n || 0); return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'k' : n.toLocaleString(); }
function vpaTime(t) {
  if (!t) return '-';
  const d = new Date(t * 1000), p = x => String(x).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
function vpaClock(t) { if (!t) return '-'; const d = new Date(t * 1000), p = x => String(x).padStart(2, '0'); return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()); }
function vpaAgo(t) {
  if (!t) return '-';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - t));
  if (s < 60) return s + 's ago'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
}
function vpaDur(sec) {
  if (sec == null) return 'permanent';
  sec = Math.max(0, Math.floor(sec));
  if (sec < 60) return sec + 's'; if (sec < 3600) return Math.floor(sec / 60) + 'm';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h ' + Math.floor(sec % 3600 / 60) + 'm';
  return Math.floor(sec / 86400) + 'd ' + Math.floor(sec % 86400 / 3600) + 'h';
}
function vpaMinutes(m) {
  m = Number(m || 0); if (!m) return 'Permanent';
  if (m % 1440 === 0) return (m / 1440) + ' day' + (m === 1440 ? '' : 's');
  if (m % 60 === 0) return (m / 60) + ' hour' + (m === 60 ? '' : 's');
  return m + ' min';
}
function vpaCssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

// One Chart.js chart per canvas; calling again updates it in place.
const _vpaCharts = new WeakMap();
function vpaChart(canvas, type, labels, datasets, extra) {
  if (!canvas || !window.Chart) return null;
  const grid = vpaCssVar('--border', 'rgba(127,127,127,.15)');
  const txt = vpaCssVar('--text-muted', '#888');
  const palette = [vpaCssVar('--accent', '#5865f2'), vpaCssVar('--red', '#ef4444'), vpaCssVar('--green', '#10b981'),
                   vpaCssVar('--yellow', '#f59e0b'), vpaCssVar('--blue', '#3b82f6')];
  const ds = datasets.map((d, i) => {
    const c = d.color || palette[i % palette.length];
    return Object.assign({
      borderColor: c, backgroundColor: type === 'bar' ? c + 'cc' : c + '22', fill: type === 'line',
      tension: .35, pointRadius: 0, pointHoverRadius: 4, borderWidth: 2, borderRadius: type === 'bar' ? 4 : 0, maxBarThickness: 26,
    }, d);
  });
  let ch = _vpaCharts.get(canvas);
  if (ch && ch.config.type === type) {
    ch.data.labels = labels; ch.data.datasets = ds; ch.update('none'); return ch;
  }
  if (ch) ch.destroy();
  ch = new Chart(canvas, Object.assign({
    type, data: {labels, datasets: ds},
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, interaction: {mode: 'index', intersect: false},
      plugins: {legend: {display: ds.length > 1, labels: {color: txt, boxWidth: 10, font: {size: 11}}}},
      scales: type === 'doughnut' ? {} : {
        x: {grid: {display: false}, ticks: {color: txt, font: {size: 10}, maxRotation: 0, autoSkipPadding: 12}},
        y: {beginAtZero: true, grid: {color: grid}, ticks: {color: txt, font: {size: 10}, precision: 0}},
      },
    },
  }, extra || {}));
  _vpaCharts.set(canvas, ch);
  return ch;
}

// Poll fn every ms while the App page is the one on screen. Returns a stop function.
function vpaPoll(pageId, fn, ms) {
  let stop = false;
  const loop = async () => {
    if (stop) return;
    if (vpActivePage() === pageId && document.visibilityState === 'visible') { try { await fn(); } catch (e) {} }
    setTimeout(loop, ms);
  };
  setTimeout(loop, ms);
  return () => { stop = true; };
}

// App Store: VortexPanel Apps are listed in the same table as server software.
// Mixed into modulesPage(); every name is prefixed (app*) so nothing collides
// with the App Store's own state and methods.
function vpAppsMixin() {
  return {
    apps: [], appBusy: false, appInfo: null, appRemove: null, appPurge: false,
    appJob: {show: false, title: '', lines: [], state: '', message: ''}, _appStop: null,
    async loadApps() {
      const r = await get('/api/apps');
      if (!r.ok) return;
      this.apps = r.apps;
      if (r.job_running && r.job && r.job.state === 'running' && !this.appJob.show) this.appWatch(r.job);
    },
    // App rows shaped like catalog rows, so one table renders both
    appRows() {
      return this.apps.map(a => ({
        kind: 'app', id: a.id, name: a.name, category: a.category, desc: a.summary, icon: a.icon, color: a.color,
        installed: a.installed, installedVer: a.installed_version, version: a.version, hasUpdate: a.has_update,
        status: a.status, error: a.error, page: a.page, compatible: a.compatible, requires_core: a.requires_core,
        features: a.features, engines: a.engines, description: a.description, app: a,
      }));
    },
    async appAct(a, action, purge) {
      this.appBusy = true;
      const r = await post('/api/apps/' + encodeURIComponent(a.id) + '/' + action, {purge: !!purge});
      this.appBusy = false;
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      this.appWatch({action, id: a.id, lines: ['Starting...'], state: 'running'}, a.name);
    },
    appWatch(j, name) {
      const nm = name || (this.apps.find(a => a.id === j.id) || {}).name || j.id;
      const verb = {install: 'Installing', update: 'Updating', uninstall: 'Removing'}[j.action] || 'Working on';
      this.appJob = {show: true, title: verb + ' ' + nm, lines: j.lines || [], state: 'running', message: ''};
      if (this._appStop) this._appStop();
      let misses = 0, stopped = false;
      this._appStop = () => { stopped = true; };
      const tick = async () => {
        if (stopped) return;
        const r = await get('/api/apps/job');
        if (r && r.ok && r.job) {
          misses = 0;
          this.appJob.lines = r.job.lines || [];
          this.$nextTick(() => { const el = this.$refs.appjoblog; if (el) el.scrollTop = el.scrollHeight; });
          if (r.job.state && r.job.state !== 'running') {
            this.appJob.state = r.job.state; this.appJob.message = r.job.message || '';
            this.loadApps(); return;
          }
        } else if (++misses > 150) {     // the panel restarts during the job: keep trying for ~5 min
          this.appJob.state = 'failed'; this.appJob.message = 'Lost contact with the panel. Reload the page in a minute.'; return;
        }
        setTimeout(tick, 2000);
      };
      setTimeout(tick, 1000);
    },
    closeAppJob() { this.appJob.show = false; if (this._appStop) this._appStop(); },
  };
}
