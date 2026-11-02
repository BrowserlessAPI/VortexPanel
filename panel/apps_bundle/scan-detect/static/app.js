// Network Scan Detection - App page component.
function vpaScanDetect() {
  const API = '/api/app/scan-detect';
  const PAGE = 'app-scan-detect';
  return {
    loaded: false, busy: '', tab: 'overview', svc: '',
    s: {enabled: true, window_min: 3, scan_count: 100, port_count: 20}, f: {}, defaults: {},
    today: {probes: 0, ips: 0, blocks: 0, hourly: []}, trend: [], live: [], liveAt: 0, scanners: [],
    blockedNow: 0, whitelistN: 0, adminIps: [], active: [],
    q: '', scanFilter: '', sel: [], batchMin: 1440,
    blk: {items: [], total: 0, page: 1, size: 50, q: '', mode: ''},
    rt: [], rtSince: 0, rtQ: '', rtPaused: false,
    wl: {ip: '', note: ''}, wlItems: [], ops: [],
    manual: {ip: '', min: 1440}, clean: {what: 'history', days: 30},
    det: {show: false, ip: '', rec: {}, hist: [], min: 1440},
    tabs: [
      {id: 'overview', label: 'Overview', icon: 'grid'},
      {id: 'scanners', label: 'Scanners today', icon: 'search'},
      {id: 'blocks', label: 'Block records', icon: 'ban'},
      {id: 'realtime', label: 'Real-time log', icon: 'activity'},
      {id: 'whitelist', label: 'Whitelist', icon: 'check'},
      {id: 'oplog', label: 'Operation logs', icon: 'file-text'},
      {id: 'settings', label: 'Settings', icon: 'settings'},
    ],
    durations: [
      {v: 30, l: '30 minutes'}, {v: 60, l: '1 hour'}, {v: 360, l: '6 hours'}, {v: 1440, l: '1 day'},
      {v: 10080, l: '7 days'}, {v: 43200, l: '30 days'}, {v: 0, l: 'Permanent'},
    ],

    async init() {
      if (!vpOnce(this, 'init')) { return; }
      await this.load();
      window.addEventListener('vp:page', e => { if (e.detail === PAGE) this.load(); });
      vpaPoll(PAGE, () => this.tab === 'realtime' ? this.loadRt() : (['overview', 'scanners', 'blocks'].includes(this.tab) ? this.load(true) : null), 4000);
    },
    async load(quiet) {
      const r = await get(API + '/overview');
      if (!r.ok) { if (!quiet) toast(r.error || 'Could not load Scan Detection', 'error'); return; }
      this.s = r.settings; this.svc = r.service; this.today = r.today; this.trend = r.trend;
      this.live = r.live; this.liveAt = r.live_at; this.scanners = r.scanners;
      this.blockedNow = r.blocked_now; this.whitelistN = r.whitelist_n; this.adminIps = r.admin_ips || [];
      if (!this.loaded) { this.f = Object.assign({}, r.settings); this.batchMin = this.manual.min = r.settings.block_minutes; }
      this.loaded = true;
      if (this.tab === 'blocks' || !this.active.length) this.loadBlocks(this.blk.page, true);
      this.$nextTick(() => this.charts());
    },
    charts() {
      if (this.tab !== 'overview') return;
      const hrs = Array.from({length: 24}, (_, i) => String(i).padStart(2, '0') + ':00');
      vpaChart(this.$refs.hourly, 'bar', hrs, [{label: 'Probes', data: this.today.hourly || [], color: '#dc2626'}]);
      vpaChart(this.$refs.trend, 'line', this.trend.map(d => d.day.slice(5)),
        [{label: 'Scanning IPs', data: this.trend.map(d => d.ips), color: '#f59e0b'},
         {label: 'Blocks', data: this.trend.map(d => d.blocks), color: '#dc2626'}]);
    },
    setTab(t) {
      this.tab = t; this.sel = [];
      if (t === 'overview') this.$nextTick(() => this.charts());
      if (t === 'blocks') this.loadBlocks(1);
      if (t === 'realtime') { this.rtSince = 0; this.rt = []; this.loadRt(); }
      if (t === 'whitelist') this.loadWl();
      if (t === 'oplog') this.loadOps();
      if (t === 'settings') { this.f = Object.assign({}, this.s); get(API + '/settings').then(r => { if (r.ok) this.defaults = r.defaults; }); }
    },

    pct(r) {
      const a = r.probes / Math.max(1, this.s.scan_count) * 100;
      const b = this.s.port_count ? r.ports / this.s.port_count * 100 : 0;
      return Math.max(a, b);
    },
    isBlocked(ip) { return this.active.some(a => a.ip === ip) || this.live.some(l => l.ip === ip && l.blocked); },
    scannersView() {
      const q = this.q.trim();
      return this.scanners.filter(r => (!q || r.ip.includes(q)) &&
        (!this.scanFilter || (this.scanFilter === 'blocked') === this.isBlocked(r.ip)));
    },
    selAll(on) { this.sel = on ? this.scannersView().map(r => r.ip) : []; },

    async toggle(on) {
      this.busy = 'toggle';
      const r = await post(API + '/toggle', {enabled: on});
      this.busy = '';
      if (!r.ok) { toast(r.error || 'Failed', 'error'); }
      else toast(on ? 'Scan detection is on' : 'Scan detection is off', 'success');
      this.load(true);
    },
    quickBlock(ip) { this.block([ip], this.s.block_minutes); },
    async block(ips, minutes) {
      ips = (ips || []).map(x => String(x || '').trim()).filter(Boolean);
      if (!ips.length) return;
      const r = await post(API + '/block', {ips, minutes});
      if (r.blocked && r.blocked.length) toast('Blocked ' + r.blocked.length + ' address(es)', 'success');
      if (r.errors && r.errors.length) toast(r.errors.join('\n'), 'error', 8000);
      this.sel = []; this.manual.ip = '';
      await this.loadBlocks(this.blk.page, true); this.load(true);
    },
    async unblock(ips) {
      const r = await post(API + '/unblock', {ips});
      if (r.ok) toast('Unblocked ' + (r.unblocked || []).length + ' address(es)', 'success'); else toast(r.error || 'Failed', 'error');
      await this.loadBlocks(this.blk.page, true); this.load(true);
    },
    async unblockAll() {
      if (!confirm('Unblock all ' + this.active.length + ' blocked address(es)?')) return;
      const r = await post(API + '/unblock-all', {});
      toast(r.ok ? 'Unblocked ' + r.count + ' address(es)' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
      await this.loadBlocks(1, true); this.load(true);
    },
    async loadBlocks(page, quiet) {
      const p = new URLSearchParams({page: page || 1, size: this.blk.size, q: this.blk.q, mode: this.blk.mode});
      const r = await get(API + '/blocks?' + p);
      if (!r.ok) { if (!quiet) toast(r.error || 'Failed', 'error'); return; }
      this.blk.items = r.items; this.blk.total = r.total; this.blk.page = r.page; this.active = r.active;
    },
    async loadRt() {
      if (this.rtPaused) return;
      const r = await get(API + '/realtime?since=' + this.rtSince);
      if (!r.ok) return;
      this.svc = r.service;
      const fresh = (r.items || []).map(e => Object.assign({_new: this.rtSince > 0}, e));
      if (fresh.length) {
        this.rtSince = Math.max(...fresh.map(e => e.t), this.rtSince);
        this.rt = fresh.concat(this.rt.map(e => Object.assign(e, {_new: false}))).slice(0, 800);
      } else if (!this.rtSince) this.rtSince = r.now - 3600;
    },
    rtView() { const q = this.rtQ.trim(); return q ? this.rt.filter(e => e.ip.includes(q) || String(e.port) === q) : this.rt; },
    async loadWl() {
      const r = await get(API + '/whitelist');
      if (r.ok) { this.wlItems = r.items; this.adminIps = r.admin_ips || []; this.whitelistN = r.items.length; }
    },
    async wlAdd() {
      const r = await post(API + '/whitelist', {ip: this.wl.ip, note: this.wl.note});
      if (!r.ok) { toast(r.error || 'Failed', 'error'); return; }
      toast('Added ' + (r.added || []).length + ' entr' + ((r.added || []).length === 1 ? 'y' : 'ies'), 'success');
      this.wl = {ip: '', note: ''}; this.loadWl(); this.loadBlocks(1, true);
    },
    async wlDel(ip) {
      const r = await del(API + '/whitelist', {ip});
      if (r.ok) { this.wlItems = r.items; this.whitelistN = r.items.length; } else toast(r.error || 'Failed', 'error');
    },
    async loadOps() { const r = await get(API + '/oplog'); if (r.ok) this.ops = r.items; },
    async saveSettings() {
      this.busy = 'settings';
      const r = await post(API + '/settings', this.f);
      this.busy = '';
      if (!r.ok) { toast(r.error || 'Failed', 'error', 8000); return; }
      this.s = r.settings; this.f = Object.assign({}, r.settings);
      toast('Settings saved and applied', 'success');
    },
    async cleanup() {
      if (!confirm('Delete this data? This cannot be undone.')) return;
      const r = await post(API + '/cleanup', {what: this.clean.what, older_than: this.clean.days});
      toast(r.ok ? 'Cleaned up' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
      this.load(true);
    },
    async service(action) {
      const r = await post(API + '/service', {action});
      this.svc = r.service || this.svc;
      toast(r.ok ? 'Service ' + action + 'ed' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
    async details(ip) {
      this.det = {show: true, ip, rec: this.scanners.find(r => r.ip === ip) || {}, hist: [], min: this.s.block_minutes};
      const r = await get(API + '/blocks?size=50&q=' + encodeURIComponent(ip));
      if (r.ok) this.det.hist = r.items.filter(x => x.ip === ip);
    },
  };
}
