// Network Threat Detection - App page component.
function vpaNetThreat() {
  const API = '/api/app/net-threat';
  const PAGE = 'app-net-threat';
  return {
    loaded: false, busy: '', tab: 'overview', svc: '', s: {enabled: true, update_hours: 6}, ov: {}, lists: [],
    q: '', riskF: '', ev: {items: [], total: 0, page: 1, size: 50}, evf: {risk: '', direction: '', q: ''},
    lk: {ip: '', done: false, res: '', lists: [], events: []}, ids: {mem_available_mb: 0}, alerts: [], idsQ: '',
    wl: {ip: '', note: ''}, wlItems: [], sf: {update_hours: 6, retention_days: 30, notify: true},
    risks: [{k: 'critical', l: 'Critical'}, {k: 'high', l: 'High'}, {k: 'medium', l: 'Medium'}, {k: 'low', l: 'Low'}, {k: 'info', l: 'Info'}],
    tabs: [
      {id: 'overview', label: 'Threats', icon: 'alert'}, {id: 'events', label: 'Event log', icon: 'file-text'},
      {id: 'lists', label: 'Threat lists', icon: 'layers'}, {id: 'lookup', label: 'IP lookup', icon: 'search'},
      {id: 'ids', label: 'Deep inspection', icon: 'eye'}, {id: 'settings', label: 'Whitelist & settings', icon: 'settings'},
    ],
    async init() {
      if (!vpOnce(this, 'init')) return;
      await this.load();
      window.addEventListener('vp:page', e => { if (e.detail === PAGE) this.load(); });
      vpaPoll(PAGE, () => this.tab === 'overview' ? this.load(true) : (this.tab === 'ids' && this.ids.job_running ? this.loadIds() : null), 10000);
    },
    async load(quiet) {
      const r = await get(API + '/overview');
      if (!r.ok) { if (!quiet) toast(r.error || 'Could not load Threat Detection', 'error'); return; }
      this.ov = r; this.s = r.settings; this.svc = r.service; this.lists = r.lists; this.loaded = true;
      this.sf = {update_hours: r.settings.update_hours, retention_days: r.settings.retention_days, notify: r.settings.notify};
      this.$nextTick(() => this.charts());
    },
    charts() {
      if (this.tab !== 'overview') return;
      const hrs = Array.from({length: 24}, (_, i) => String(i).padStart(2, '0') + ':00');
      vpaChart(this.$refs.hourly, 'bar', hrs, [{label: 'Hits', data: this.ov.today.hourly, color: '#ea580c'}]);
      const bl = this.ov.today.by_list || {};
      const names = Object.fromEntries(this.lists.map(l => [l.id, l.name]));
      const keys = Object.keys(bl).sort((a, b) => bl[b] - bl[a]);
      vpaChart(this.$refs.bylist, 'doughnut', keys.map(k => names[k] || k), [{data: keys.map(k => bl[k]),
        backgroundColor: ['#ea580c', '#dc2626', '#f59e0b', '#2563eb', '#8b5cf6', '#94a3b8'], borderWidth: 0}],
        {options: {responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: {legend: {position: 'right', labels: {color: vpaCssVar('--text-muted', '#888'), boxWidth: 10, font: {size: 11}}}}}});
    },
    setTab(t) {
      this.tab = t;
      if (t === 'overview') this.load(true);
      if (t === 'events') this.loadEvents(1);
      if (t === 'ids') { this.loadIds(); }
      if (t === 'settings') this.loadWl();
    },
    riskTone(r) { return {critical: 'red', high: 'red', medium: 'amber', low: 'blue', info: ''}[r] || ''; },
    threatsView() { const q = this.q.trim(); return (this.ov.threats || []).filter(t => (!this.riskF || t.risk === this.riskF) && (!q || t.ip.includes(q))); },
    async toggle(on) { const r = await post(API + '/toggle', {enabled: on}); toast(r.ok ? 'Detection ' + (on ? 'on' : 'off') : (r.error || 'Failed'), r.ok ? 'success' : 'error'); this.load(true); },
    async setList(l, mode) {
      if (l.mode === mode) return;
      if (mode === 'block' && l.direction === 'in' && !confirm('Drop all traffic from ' + l.name + '? Visitors on these networks will not reach your sites.')) return;
      const r = await post(API + '/list', {id: l.id, mode});
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      this.lists = r.lists; toast(l.name + ': ' + mode, 'success');
    },
    async updateNow() {
      this.busy = 'update';
      const r = await post(API + '/update', {});
      this.busy = '';
      toast(r.ok ? 'Lists updated' : (r.error || 'Some lists failed'), r.ok ? 'success' : 'error', 8000); this.load(true);
    },
    async loadEvents(page) {
      const r = await get(API + '/events?' + new URLSearchParams(Object.assign({page: page || 1, size: this.ev.size}, this.evf)));
      if (r.ok) { this.ev.items = r.items; this.ev.total = r.total; this.ev.page = r.page; }
    },
    async lookup(ip) {
      if (!ip) return;
      this.tab = 'lookup'; this.lk.ip = ip;
      const r = await get(API + '/lookup?ip=' + encodeURIComponent(ip));
      if (!r.ok) { toast(r.error || 'Failed', 'error'); return; }
      this.lk = {ip, done: true, res: r.ip, lists: r.lists, events: r.events};
    },
    async loadIds() { const r = await get(API + '/ids'); if (r.ok) { this.ids = r; if (r.installed) this.loadAlerts(); } },
    async loadAlerts() { const r = await get(API + '/ids/alerts?q=' + encodeURIComponent(this.idsQ)); if (r.ok) this.alerts = r.items; },
    async idsAction(a) {
      if (a === 'install' && !confirm('Install Suricata and the Emerging Threats rules? This uses about 1 GB of memory while running.')) return;
      const r = await post(API + '/ids/' + a, {});
      toast(r.ok ? 'Done' : (r.error || 'Failed'), r.ok ? 'success' : 'error', 8000); this.loadIds();
    },
    async blockIp(ip) {
      if (!confirm('Block ' + ip + ' at the firewall (Network Scan Detection)?')) return;
      const r = await post('/api/app/scan-detect/block', {ip, reason: 'threat list (Network Threat Detection)'});
      toast(r.ok ? ip + ' blocked' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
    async loadWl() { const r = await get(API + '/whitelist'); if (r.ok) this.wlItems = r.items; },
    async wlAdd() { const r = await post(API + '/whitelist', this.wl); if (!r.ok) { toast(r.error || 'Failed', 'error'); return; } this.wlItems = r.items; this.wl = {ip: '', note: ''}; toast('Whitelisted', 'success'); },
    async wlDel(ip) { const r = await del(API + '/whitelist', {ip}); if (r.ok) this.wlItems = r.items; },
    async saveSettings() { const r = await post(API + '/settings', this.sf); toast(r.ok ? 'Saved' : (r.error || 'Failed'), r.ok ? 'success' : 'error'); },
    async service(action) { const r = await post(API + '/service', {action}); this.svc = r.service || this.svc; toast(r.ok ? 'Sensor ' + action + 'ed' : (r.error || 'Failed'), r.ok ? 'success' : 'error'); },
  };
}
