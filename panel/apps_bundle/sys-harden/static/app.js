// System Hardening - App page component.
function vpaSysHarden() {
  const API = '/api/app/sys-harden';
  const PAGE = 'app-sys-harden';
  return {
    loaded: false, busy: '', tab: 'overview', svc: '', ov: {}, areas: [], pauseMin: 30,
    cp: {path: '', mode: 'monitor', note: ''},
    pg: {items: [], whitelist: [], quarantine: [], auto_kill: false},
    comp: {score: null, checks: [], t: 0},
    au: {}, auItems: [], auKind: '', auQ: '', auSource: '',
    ev: {items: [], total: 0, page: 1, size: 50}, evf: {severity: '', area: '', q: ''},
    sf: {scan_minutes: 5, notify: true, auto_kill: false}, ops: [],
    fm: {show: false, area: null, label: '', items: [], total: 0, q: ''},
    tabs: [
      {id: 'overview', label: 'Overview', icon: 'grid'}, {id: 'protection', label: 'Protection', icon: 'shield'},
      {id: 'process', label: 'Process guard', icon: 'cpu'}, {id: 'compliance', label: 'Compliance', icon: 'check'},
      {id: 'audit', label: 'Log audit', icon: 'file-text'}, {id: 'events', label: 'Events', icon: 'activity'},
      {id: 'settings', label: 'Settings', icon: 'settings'},
    ],

    async init() {
      if (!vpOnce(this, 'init')) return;
      await this.load();
      if (this.ov.score == null) this.loadComp(true);
      window.addEventListener('vp:page', e => { if (e.detail === PAGE) this.load(); });
      vpaPoll(PAGE, () => (this.tab === 'overview' ? this.load(true) : null), 20000);
    },
    async load(quiet) {
      const r = await get(API + '/overview');
      if (!r.ok) { if (!quiet) toast(r.error || 'Could not load System Hardening', 'error'); return; }
      this.ov = r; this.areas = r.areas; this.svc = r.service; this.loaded = true;
      this.sf = {scan_minutes: r.config.scan_minutes, notify: r.config.notify, auto_kill: r.config.auto_kill};
      this.pg.auto_kill = r.config.auto_kill;
    },
    setTab(t) {
      this.tab = t;
      if (t === 'overview' || t === 'protection') this.load(true);
      if (t === 'process') this.loadProcs();
      if (t === 'compliance' && !this.comp.checks.length) this.loadComp();
      if (t === 'audit') { this.loadAudit(); get(API + '/audit/summary').then(r => { if (r.ok) this.au = r; }); }
      if (t === 'events') this.loadEvents(1);
      if (t === 'settings') get(API + '/oplog').then(r => { if (r.ok) this.ops = r.items; });
    },
    sevTone(s) { return {critical: 'red', high: 'red', medium: 'amber', low: 'blue'}[s] || ''; },
    areaLabel(id) { if (id === 'process') return 'Process guard'; const a = this.areas.find(x => x.id === id); return a ? a.label : id; },
    scoreTone() { const s = this.ov.score; return s == null ? 'blue' : (s >= 85 ? 'green' : (s >= 60 ? 'amber' : 'red')); },
    scoreColor() { const s = this.comp.score || 0; return s >= 85 ? 'var(--green)' : (s >= 60 ? 'var(--yellow)' : 'var(--red)'); },

    async setMode(a, mode) {
      if (mode === a.mode) return;
      if (mode === 'lock' && !confirm(a.label + ' will be locked.\n\n' + a.lock_warn + '\n\nLock now?')) return;
      const r = await post(API + '/area', {id: a.id, mode});
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      toast(a.label + ': ' + mode + (r.message ? ' (' + r.message + ')' : ''), 'success');
      this.areas = r.areas; this.load(true);
    },
    async pause(min) {
      const r = await post(API + '/pause', {minutes: min});
      toast(r.ok ? (min ? 'Locks paused for ' + min + ' minutes' : 'Locks are back on') : (r.error || 'Failed'), r.ok ? 'success' : 'error');
      this.load(true);
    },
    async rebaseline(id) {
      if (!confirm('Treat the current files as the expected state? Changes made so far will no longer be reported.')) return;
      const r = await post(API + '/rebaseline', {id});
      toast(r.ok ? 'Current state accepted' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
    async scanNow() { const r = await post(API + '/scan', {}); toast(r.message || 'Scanning', 'success'); setTimeout(() => this.load(true), 6000); },
    async showFiles(a) {
      if (this.fm.area !== a) this.fm.q = '';
      const r = await get(API + '/files?' + new URLSearchParams({id: a.id, q: this.fm.q}));
      if (!r.ok) { toast(r.error || 'Failed', 'error'); return; }
      Object.assign(this.fm, {show: true, area: a, label: a.label, items: r.items, total: r.total});
    },
    async addCustom() {
      const r = await post(API + '/custom', this.cp);
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      toast('Protected: ' + this.cp.path, 'success'); this.cp = {path: '', mode: 'monitor', note: ''}; this.load(true);
    },
    async delCustom(a) {
      if (!confirm('Stop protecting ' + a.paths[0] + '? Its locks are removed.')) return;
      const r = await del(API + '/custom', {path: a.paths[0]});
      if (r.ok) this.load(true); else toast(r.error || 'Failed', 'error');
    },
    async loadProcs() { const r = await get(API + '/processes'); if (r.ok) Object.assign(this.pg, r); },
    async killProc(p) {
      if (!confirm('Kill ' + p.name + ' (' + p.pid + ')? Its program file is moved to quarantine when it lives in a temp or website folder.')) return;
      const r = await post(API + '/processes/kill', {pid: p.pid});
      toast(r.ok ? r.message : (r.error || 'Failed'), r.ok ? 'success' : 'error', 6000); this.loadProcs();
    },
    async wlProc(exe) { const r = await post(API + '/processes/whitelist', {path: exe}); if (r.ok) { toast('Trusted', 'success'); this.loadProcs(); } },
    async unwlProc(p) { const r = await del(API + '/processes/whitelist', {path: p}); if (r.ok) this.loadProcs(); },
    async loadComp(quiet) {
      this.busy = 'comp';
      const r = await get(API + '/compliance');
      this.busy = '';
      if (r.ok) { this.comp = r; this.ov.score = r.score; this.ov.compliance_fail = r.checks.filter(c => c.status === 'fail').length; }
      else if (!quiet) toast(r.error || 'Failed', 'error');
    },
    compCats() { return [...new Set(this.comp.checks.map(c => c.category))]; },
    compCount(s) { return this.comp.checks.filter(c => c.status === s).length; },
    async fix(c) {
      if (!confirm(c.title + '\n\nThis will: ' + c.fix_text + '\n\nApply the fix?')) return;
      this.busy = 'fix-' + c.id;
      const r = await post(API + '/compliance/fix', {id: c.id});
      this.busy = '';
      if (r.checks) { this.comp = r; this.ov.score = r.score; }
      toast(r.ok ? 'Fixed: ' + c.title : (r.error || 'Failed'), r.ok ? 'success' : 'error', 8000);
    },
    async loadAudit() {
      const r = await get(API + '/audit?' + new URLSearchParams({kind: this.auKind, q: this.auQ}));
      if (r.ok) { this.auItems = r.items; this.auSource = r.source; }
    },
    async blockIp(ip) {
      if (!confirm('Block ' + ip + ' at the firewall (Network Scan Detection)?')) return;
      const r = await post('/api/app/scan-detect/block', {ip, reason: 'failed SSH sign-ins (System Hardening)'});
      toast(r.ok ? ip + ' blocked' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
    async loadEvents(page) {
      const r = await get(API + '/events?' + new URLSearchParams(Object.assign({page: page || 1, size: this.ev.size}, this.evf)));
      if (r.ok) { this.ev.items = r.items; this.ev.total = r.total; this.ev.page = r.page; }
    },
    async ackEvents() { await post(API + '/events/ack', {}); this.loadEvents(this.ev.page); this.load(true); },
    async setSetting(d) {
      const r = await post(API + '/settings', d);
      if (r.ok) { toast('Saved', 'success'); this.ov.config = r.config; this.pg.auto_kill = r.config.auto_kill; } else toast(r.error || 'Failed', 'error');
    },
    async service(action) {
      const r = await post(API + '/service', {action});
      this.svc = r.service || this.svc;
      toast(r.ok ? 'Service ' + action + 'ed' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
  };
}
