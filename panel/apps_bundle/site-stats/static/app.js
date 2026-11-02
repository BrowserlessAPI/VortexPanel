// Website Statistics - App page component.
const VPSS_COUNTRIES = {US: 'United States', IN: 'India', DE: 'Germany', GB: 'United Kingdom', FR: 'France', JP: 'Japan',
  BR: 'Brazil', SG: 'Singapore', CA: 'Canada', NL: 'Netherlands', CN: 'China', RU: 'Russia', AU: 'Australia', IT: 'Italy',
  ES: 'Spain', ID: 'Indonesia', KR: 'South Korea', TR: 'Turkey', VN: 'Vietnam', PL: 'Poland', UA: 'Ukraine', MX: 'Mexico',
  PK: 'Pakistan', BD: 'Bangladesh', AE: 'United Arab Emirates', SA: 'Saudi Arabia', ZA: 'South Africa', NG: 'Nigeria',
  EG: 'Egypt', TH: 'Thailand', PH: 'Philippines', MY: 'Malaysia', HK: 'Hong Kong', TW: 'Taiwan', SE: 'Sweden', CH: 'Switzerland',
  IE: 'Ireland', FI: 'Finland', NO: 'Norway', DK: 'Denmark', BE: 'Belgium', AT: 'Austria', PT: 'Portugal', CZ: 'Czechia',
  RO: 'Romania', AR: 'Argentina', CL: 'Chile', CO: 'Colombia', IL: 'Israel', NZ: 'New Zealand', NP: 'Nepal', LK: 'Sri Lanka'};

function vpaSiteStats() {
  const API = '/api/app/site-stats';
  const PAGE = 'app-site-stats';
  return {
    loaded: false, busy: '', tab: 'overview', svc: '', lastCollect: 0,
    site: '', range: 'today', compare: 'prev', metric: 'pv',
    sites: [], sum: {totals: {}, series: [], live: [], qps: 0, step: 'hour'}, mini: {}, scanDetect: false, geoInfo: null,
    list: [], lq: '', sub: {regions: 'country', spiders: 'spider', pages: 'url', sources: 'ref', clients: 'browser', status: 'status'},
    vis: {items: [], total: 0, page: 1, size: 50, q: '', kind: '', sort: 'hits'},
    err: {path: '', lines: [], groups: [], q: ''},
    f: {sites: []}, exIps: '', exPaths: '', allSites: [], dbSize: 0, cleanSite: '', ops: [],
    ranges: [{v: 'today', l: 'Today'}, {v: 'yesterday', l: 'Yesterday'}, {v: '7d', l: '7 days'}, {v: '30d', l: '30 days'}],
    metrics: [{v: 'pv', l: 'Page views'}, {v: 'uv', l: 'Visitors'}, {v: 'ip', l: 'IPs'}, {v: 'req', l: 'Requests'}, {v: 'bytes', l: 'Traffic'}, {v: 'spider', l: 'Spiders'}],
    tabs: [
      {id: 'overview', label: 'Overview', icon: 'grid'}, {id: 'sites', label: 'Websites', icon: 'globe'},
      {id: 'visitors', label: 'Visitors', icon: 'users'}, {id: 'regions', label: 'Regions', icon: 'pin'},
      {id: 'spiders', label: 'Spiders', icon: 'bot'}, {id: 'pages', label: 'Pages', icon: 'file-text'},
      {id: 'sources', label: 'Sources', icon: 'link'}, {id: 'status', label: 'Status codes', icon: 'activity'},
      {id: 'clients', label: 'Clients', icon: 'monitor'}, {id: 'errors', label: 'Error log', icon: 'alert'},
      {id: 'settings', label: 'Settings', icon: 'settings'},
    ],
    listViews: [
      {tab: 'regions', col: 'Country', count: 'Visitors (IPs)', subs: [{kind: 'country', l: 'Countries'}], chart: false},
      {tab: 'spiders', col: 'Spider / bot', count: 'Requests', bytes: true, subs: [{kind: 'spider', l: 'Spiders'}], chart: true},
      {tab: 'pages', col: 'Page', count: 'Views', bytes: true, mono: true, search: true, subs: [{kind: 'url', l: 'Top pages'}, {kind: 'url404', l: 'Not found (404)'}], chart: false},
      {tab: 'sources', col: 'Source', count: 'Visits', subs: [{kind: 'ref', l: 'Referring sites'}, {kind: 'search', l: 'Search engines'}], chart: false, search: true},
      {tab: 'status', col: 'Code', count: 'Requests', subs: [{kind: 'status', l: 'Status codes'}, {kind: 'method', l: 'Methods'}], chart: true},
      {tab: 'clients', col: 'Name', count: 'Page views', subs: [{kind: 'browser', l: 'Browsers'}, {kind: 'os', l: 'Systems'}, {kind: 'device', l: 'Devices'}], chart: true},
    ],
    blocks: [{kind: 'url', title: 'Top pages', tab: 'pages'}, {kind: 'ref', title: 'Top sources', tab: 'sources'},
             {kind: 'country', title: 'Regions', tab: 'regions'}, {kind: 'spider', title: 'Spiders', tab: 'spiders'}],

    async init() {
      if (!vpOnce(this, 'init')) return;
      await this.loadSites();
      await this.reload();
      window.addEventListener('vp:page', e => { if (e.detail === PAGE) this.reload(); });
      vpaPoll(PAGE, () => (this.tab === 'overview' && this.range === 'today') ? this.loadSummary(true) : null, 30000);
    },
    qs(extra) { return new URLSearchParams(Object.assign({site: this.site, range: this.range}, extra || {})).toString(); },
    async loadSites() {
      const r = await get(API + '/sites?' + this.qs());
      if (!r.ok) return;
      this.sites = r.sites; this.svc = r.service; this.lastCollect = r.last_collect; this.scanDetect = r.scan_detect;
      this.geoInfo = r.geo; this.loaded = true;
    },
    async reload() {
      if (this.tab === 'overview') await this.loadSummary();
      else if (this.tab === 'sites') await this.loadSites();
      else if (this.tab === 'visitors') await this.loadVisitors(1);
      else if (this.tab === 'errors') await this.loadErrors();
      else if (this.listViews.some(l => l.tab === this.tab)) await this.loadList(this.tab);
    },
    setTab(t) {
      this.tab = t; this.lq = '';
      if (t === 'settings') this.loadSettings(); else this.reload();
    },
    async loadSummary(quiet) {
      const r = await get(API + '/summary?' + this.qs({compare: this.compare}));
      if (!r.ok) { if (!quiet) toast(r.error || 'Could not load statistics', 'error'); return; }
      this.sum = r; this.lastCollect = r.last_collect;
      const kinds = ['url', 'ref', 'country', 'spider'];
      const res = await Promise.all(kinds.map(k => get(API + '/top?' + this.qs({kind: k, limit: 6}))));
      const m = {}; kinds.forEach((k, i) => { m[k] = this.scaled(res[i].ok ? res[i].items : []); }); this.mini = m;
      this.$nextTick(() => this.charts());
    },
    pctDelta(cur, prev) {
      if (!this.sum.compare || prev == null) return null;
      if (!prev) return cur ? 100 : 0;
      return Math.round((cur - prev) / prev * 1000) / 10;
    },
    cards() {
      const t = this.sum.totals || {}, p = (this.sum.compare || {}).totals || {};
      const errs = (t.s4 || 0) + (t.s5 || 0);
      const c = [
        {k: 'pv', l: 'Page views', v: vpaNum(t.pv), d: this.pctDelta(t.pv, p.pv), h: 'by people', tone: 'blue'},
        {k: 'uv', l: 'Visitors', v: vpaNum(t.uv), d: this.pctDelta(t.uv, p.uv), h: 'unique', tone: 'green', title: 'Unique people: IP address + browser'},
        {k: 'ip', l: 'IP addresses', v: vpaNum(t.ip), d: this.pctDelta(t.ip, p.ip), h: 'distinct', tone: 'blue'},
        {k: 'req', l: 'Requests', v: vpaNum(t.req), d: this.pctDelta(t.req, p.req), h: 'all files', tone: ''},
        {k: 'bytes', l: 'Traffic', v: fmtBytes(t.bytes || 0), d: this.pctDelta(t.bytes, p.bytes), h: 'sent', tone: ''},
        {k: 'spider', l: 'Spiders', v: vpaNum(t.spider), d: this.pctDelta(t.spider, p.spider), h: 'bot requests', tone: 'amber'},
        {k: 'err', l: 'Errors', v: vpaNum(errs), d: this.pctDelta(errs, (p.s4 || 0) + (p.s5 || 0)), h: vpaNum(t.s4) + ' 4xx / ' + vpaNum(t.s5) + ' 5xx', tone: 'red'},
        {k: 'live', l: 'Live', v: this.sum.qps + ' /s', d: null, h: t.avg_ms != null ? 'avg response ' + t.avg_ms + ' ms' : 'requests per second, last 5 min', tone: 'green'},
      ];
      return c;
    },
    charts() {
      if (this.tab !== 'overview') return;
      const s = this.sum.series || [];
      const mv = d => this.metric === 'bytes' ? Math.round((d.bytes || 0) / 1048576 * 10) / 10 : (d[this.metric] || 0);
      const ml = (this.metrics.find(m => m.v === this.metric) || {}).l + (this.metric === 'bytes' ? ' (MB)' : '');
      const ds = [{label: ml, data: s.map(mv), color: '#2563eb'}];
      if (this.sum.compare) ds.push({label: 'Comparison', data: (this.sum.compare.series || []).map(mv), color: '#94a3b8', borderDash: [5, 4], fill: false});
      vpaChart(this.$refs.trend, 'line', s.map(d => d.label), ds);
      const live = this.sum.live || [];
      vpaChart(this.$refs.live, 'bar', live.map(d => vpaClock(d.t).slice(0, 5)), [{label: 'Requests', data: live.map(d => d.req), color: '#10b981'}]);
      const t = this.sum.totals || {};
      vpaChart(this.$refs.status, 'doughnut', ['2xx OK', '3xx Redirect', '4xx Client error', '5xx Server error'],
        [{data: [t.s2 || 0, t.s3 || 0, t.s4 || 0, t.s5 || 0], backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'], borderWidth: 0}],
        {options: {responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: {legend: {position: 'right', labels: {color: vpaCssVar('--text-muted', '#888'), boxWidth: 10, font: {size: 11}}}}}});
    },
    async loadList(tab) {
      const kind = this.sub[tab];
      const r = await get(API + '/top?' + this.qs({kind, limit: 200, q: this.lq}));
      this.list = this.scaled(r.ok ? r.items : []);
      if (r.geo) this.geoInfo = r.geo;
      const lv = this.listViews.find(l => l.tab === tab);
      if (lv && lv.chart) this.$nextTick(() => {
        const cv = this.$el.querySelector('canvas[data-chart="' + tab + '"]');
        const top = this.list.slice(0, 8);
        vpaChart(cv, 'doughnut', top.map(i => this.label(kind, i.k)), [{data: top.map(i => i.hits),
          backgroundColor: ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#94a3b8'], borderWidth: 0}],
          {options: {responsive: true, maintainAspectRatio: false, cutout: '60%', plugins: {legend: {position: 'bottom', labels: {color: vpaCssVar('--text-muted', '#888'), boxWidth: 10, font: {size: 11}}}}}});
      });
    },
    // bar length relative to the busiest row (the % shown stays the share of the total)
    scaled(items) { const mx = Math.max(1, ...items.map(i => i.hits)); return items.map(i => Object.assign(i, {w: Math.max(2, Math.round(i.hits / mx * 100))})); },
    label(kind, k) {
      if (kind === 'country') return k ? (VPSS_COUNTRIES[k] || k) : 'Unknown';
      if (kind === 'status') {
        const n = {'200': 'OK', '301': 'Moved permanently', '302': 'Found (redirect)', '304': 'Not modified', '400': 'Bad request',
          '401': 'Unauthorized', '403': 'Forbidden', '404': 'Not found', '429': 'Too many requests', '499': 'Client closed',
          '500': 'Internal server error', '502': 'Bad gateway', '503': 'Unavailable', '504': 'Gateway timeout'}[k];
        return n ? k + ' ' + n : k;
      }
      return k;
    },
    cname(cc) { return cc ? (VPSS_COUNTRIES[cc] || '') : ''; },
    async loadVisitors(page) {
      const r = await get(API + '/visitors?' + this.qs({q: this.vis.q, kind: this.vis.kind, sort: this.vis.sort, page: page || 1, size: this.vis.size}));
      if (r.ok) { this.vis.items = r.items; this.vis.total = r.total; this.vis.page = r.page; }
    },
    async loadErrors() {
      if (!this.site) { this.err = {path: '', lines: [], groups: [], q: this.err.q}; return; }
      const r = await get(API + '/errors?' + new URLSearchParams({site: this.site, q: this.err.q, lines: 300}));
      if (r.ok) { this.err.path = r.path; this.err.lines = r.lines; this.err.groups = r.groups; }
    },
    async blockIp(ip) {
      if (!confirm('Block ' + ip + ' at the firewall (Network Scan Detection)?')) return;
      const r = await post('/api/app/scan-detect/block', {ip, reason: 'blocked from Website Statistics'});
      toast(r.ok ? ip + ' blocked' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
    async collectNow() {
      this.busy = 'collect';
      const r = await post(API + '/collect', {});
      this.busy = '';
      if (!r.ok) { toast(r.error || 'Failed', 'error'); return; }
      await this.loadSites(); await this.reload();
    },
    async installGeo() {
      this.busy = 'geo';
      const r = await post(API + '/geo/install', {});
      this.busy = '';
      toast(r.ok ? r.message : (r.error || 'Failed'), r.ok ? 'success' : 'error', 8000);
      if (r.geo) this.geoInfo = r.geo;
    },
    async loadSettings() {
      const r = await get(API + '/settings');
      if (!r.ok) return;
      this.f = Object.assign({}, r.settings); this.exIps = (r.settings.exclude_ips || []).join('\n');
      this.exPaths = (r.settings.exclude_paths || []).join('\n'); this.allSites = r.sites; this.geoInfo = r.geo; this.dbSize = r.db_size;
      const o = await get(API + '/oplog'); this.ops = o.ok ? o.items : [];
    },
    async saveSettings() {
      this.busy = 'settings';
      const body = Object.assign({}, this.f, {exclude_ips: this.exIps.split(/\s+/).filter(Boolean), exclude_paths: this.exPaths.split(/\s+/).filter(Boolean)});
      const r = await post(API + '/settings', body);
      this.busy = '';
      if (r.ok) { toast('Settings saved', 'success'); this.loadSettings(); } else toast(r.error || 'Failed', 'error');
    },
    async cleanup() {
      if (!confirm('Delete the statistics of ' + (this.cleanSite || 'all websites') + '? This cannot be undone.')) return;
      const r = await post(API + '/cleanup', {site: this.cleanSite});
      toast(r.ok ? 'Statistics deleted' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
      this.loadSettings();
    },
    async service(action) {
      const r = await post(API + '/service', {action});
      this.svc = r.service || this.svc;
      toast(r.ok ? 'Collector ' + action + 'ed' : (r.error || 'Failed'), r.ok ? 'success' : 'error');
    },
  };
}
