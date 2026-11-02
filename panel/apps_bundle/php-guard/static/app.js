// PHP Security - App page component.
function vpaPhpGuard() {
  const API = '/api/app/php-guard';
  const PAGE = 'app-php-guard';
  return {
    loaded: false, tab: 'overview', ov: {}, versions: [], rules: [], trusted: [], build: {}, buildLog: false,
    ev: {items: [], total: 0, page: 1, size: 50}, evf: {action: '', q: ''}, tpath: '', ops: [], rf: {show: false, path: '', text: ''},
    tabs: [
      {id: 'overview', label: 'Overview', icon: 'grid'}, {id: 'rules', label: 'Protection rules', icon: 'shield'},
      {id: 'versions', label: 'PHP versions', icon: 'code'}, {id: 'events', label: 'Events', icon: 'activity'},
      {id: 'trusted', label: 'Trusted folders', icon: 'check'},
    ],
    async init() {
      if (!vpOnce(this, 'init')) return;
      await this.load();
      window.addEventListener('vp:page', e => { if (e.detail === PAGE) this.load(); });
      vpaPoll(PAGE, async () => {
        if (this.build.state === 'running') {
          const r = await get(API + '/build');
          if (r.ok) { this.build = r.build; if (r.build.state !== 'running') { this.buildLog = true; this.load(); } }
        } else if (this.tab === 'overview') this.load(true);
      }, 3000);
    },
    async load(quiet) {
      const r = await get(API + '/overview');
      if (!r.ok) { if (!quiet) toast(r.error || 'Could not load PHP Security', 'error'); return; }
      this.ov = r; this.versions = r.versions; this.rules = r.rules; this.trusted = r.trusted;
      this.build = r.build_running ? Object.assign({state: 'running'}, r.build) : (r.build || {});
      this.loaded = true;
      this.$nextTick(() => {
        if (this.tab !== 'overview') return;
        const now = Date.now() / 1000;
        vpaChart(this.$refs.hours, 'bar', r.hours.map((_, i) => vpaClock(now - (23 - i) * 3600).slice(0, 2) + ':00'),
          [{label: 'Events', data: r.hours, color: '#4f46e5'}]);
      });
    },
    setTab(t) {
      this.tab = t;
      if (t === 'overview') this.load(true);
      if (t === 'events') this.loadEvents(1);
      if (t === 'trusted') get(API + '/oplog').then(r => { if (r.ok) this.ops = r.items; });
    },
    protectedN() { return this.versions.filter(v => v.enabled && v.loaded).length; },
    groups() { return [...new Set(this.rules.map(r => r.group))]; },
    async setRule(r, mode) {
      if (r.mode === mode) return;
      const prev = r.mode; r.mode = mode;
      const res = await post(API + '/rules', {modes: {[r.id]: mode}});
      if (!res.ok) { r.mode = prev; toast(res.error || 'Failed', 'error', 9000); return; }
      this.rules = res.rules; toast(r.title + ': ' + mode, 'success');
    },
    async preset(name) {
      const r = await post(API + '/preset', {name});
      if (!r.ok) { toast(r.error || 'Failed', 'error', 9000); return; }
      this.rules = r.rules; toast('Preset applied: ' + name, 'success');
    },
    async showRules() { const r = await get(API + '/rules-file'); if (r.ok) this.rf = {show: true, path: r.path, text: r.text}; },
    async buildVer(v) {
      if (!confirm('Build the protection module for PHP ' + v.ver + ' and turn it on? This takes one to two minutes; PHP-FPM is reloaded at the end (no downtime).')) return;
      const r = await post(API + '/version/' + v.ver + '/build', {enable: true});
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      this.build = {ver: v.ver, state: 'running', lines: ['Starting...']}; this.buildLog = true;
    },
    async verAction(v, action) {
      const r = await post(API + '/version/' + v.ver + '/' + action, {});
      if (!r.ok) { toast(r.error || 'Failed', 'error', 9000); return; }
      this.versions = r.versions; toast('PHP ' + v.ver + ': protection ' + (action === 'enable' ? 'on' : 'off'), 'success');
    },
    async loadEvents(page) {
      const r = await get(API + '/events?' + new URLSearchParams(Object.assign({page: page || 1, size: this.ev.size}, this.evf)));
      if (r.ok) { this.ev.items = r.items; this.ev.total = r.total; this.ev.page = r.page; }
    },
    trustFolderOf(file) { this.tpath = file.replace(/\/[^\/]*$/, ''); this.setTab('trusted'); },
    async addTrusted() {
      const r = await post(API + '/trusted', {path: this.tpath});
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      this.trusted = r.trusted; this.tpath = ''; toast('Folder trusted', 'success');
    },
    async delTrusted(t) {
      const r = await del(API + '/trusted', {path: t});
      if (r.ok) this.trusted = r.trusted; else toast(r.error || 'Failed', 'error');
    },
  };
}
