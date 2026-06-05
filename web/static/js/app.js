// ── UTILITIES ─────────────────────────────────────────────────────────────────
async function api(method, url, body) {
  const opts = { method, headers: {'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  return r.json();
}
const get  = url       => api('GET', url);
const post = (url, b)  => api('POST', url, b);
const put  = (url, b)  => api('PUT', url, b);
const del  = (url, b)  => api('DELETE', url, b);

function toast(msg, type='info') {
  const c = document.getElementById('toast-container');
  const d = document.createElement('div');
  d.className = `toast toast-${type}`;
  d.textContent = (type==='success'?'✓ ':type==='error'?'✕ ':'ℹ ') + msg;
  c.appendChild(d);
  setTimeout(() => d.remove(), 3500);
}

function fmtBytes(b) {
  if (!b || b===0) return '0 B';
  const k=1024, s=['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(b)/Math.log(k));
  return (b/Math.pow(k,i)).toFixed(1)+' '+s[i];
}

function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts*1000).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
}

function fmtSize(b) {
  if (!b || b===0) return '—';
  if (b < 1024) return b+' B';
  if (b < 1024*1024) return (b/1024).toFixed(1)+' KB';
  if (b < 1024*1024*1024) return (b/1024/1024).toFixed(1)+' MB';
  return (b/1024/1024/1024).toFixed(1)+' GB';
}

// ── LOGIN ──────────────────────────────────────────────────────────────────────
function loginApp() {
  return {
    username: '', password: '', error: '', loading: false,
    get loggedIn() { return !!localStorage.getItem('vp_user'); },
    async doLogin() {
      this.loading = true; this.error = '';
      try {
        const r = await post('/api/auth/login', {username:this.username, password:this.password});
        if (r.ok) {
          localStorage.setItem('vp_user', r.username);
          location.reload();
        } else {
          this.error = r.error || 'Login failed';
        }
      } catch { this.error = 'Connection error'; }
      this.loading = false;
    }
  };
}

// ── MAIN PANEL ────────────────────────────────────────────────────────────────
function panelApp() {
  return {
    page: 'dashboard',
    sidebarOpen: false,
    online: true,
    username: localStorage.getItem('vp_user') || 'admin',
    get loggedIn() { return !!localStorage.getItem('vp_user'); },

    nav: [
      { group: 'Overview', items: [
        { id:'dashboard', icon:'▦', label:'Dashboard'    },
        { id:'websites',  icon:'🌐', label:'Websites'     },
        { id:'databases', icon:'🗄', label:'Databases'    },
        { id:'files',     icon:'📁', label:'File Manager' },
        { id:'php',       icon:'🐘', label:'PHP'          },
      ]},
      { group: 'Server', items: [
        { id:'services',  icon:'⚙', label:'Services'     },
        { id:'modules',   icon:'📦', label:'Modules'      },
        { id:'docker',    icon:'🐳', label:'Docker'       },
        { id:'firewall',  icon:'🛡', label:'Firewall'     },
        { id:'terminal',  icon:'⌨', label:'Terminal'     },
        { id:'backups',   icon:'💾', label:'Backups'      },
      ]},
      { group: 'Network', items: [
        { id:'dns',  icon:'🌍', label:'DNS Manager' },
        { id:'mail', icon:'📧', label:'Mail Server'  },
        { id:'ftp',  icon:'📂', label:'FTP / SFTP'  },
      ]},
      { group: 'System', items: [
        { id:'cron',       icon:'⏱', label:'Cron Jobs'  },
        { id:'monitoring', icon:'📊', label:'Monitoring' },
        { id:'settings',   icon:'⚙', label:'Settings'   },
      ]},
    ],

    go(id) {
      this.page = id;
      this.sidebarOpen = false;
    },
    pageTitle() {
      for (const g of this.nav) {
        const item = g.items.find(i => i.id === this.page);
        if (item) return item.label;
      }
      return 'VortexPanel';
    },
    refreshPage() { this.go(this.page); },
    logout() {
      post('/api/auth/logout');
      localStorage.removeItem('vp_user');
      location.reload();
    },
    init() {
      window.addEventListener('nav', e => this.go(e.detail.page));
    }
  };
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function dashboardPage() {
  return {
    stats: { cpu:0, ram:{used:0,total:1}, disk:{used:0,total:1}, load:[], uptime:'', services:{}, net:{rx:0,tx:0} },
    ramPct()  { return this.stats.ram?.total ? Math.round(this.stats.ram.used/this.stats.ram.total*100) : 0; },
    diskPct() { return this.stats.disk?.total ? Math.round(this.stats.disk.used/this.stats.disk.total*100) : 0; },
    fmtBytes, fmtSize,
    async init() {
      await this.load();
      setInterval(() => this.load(), 10000);
    },
    async load() {
      try {
        const r = await get('/api/dashboard/stats');
        if (r.ok) this.stats = r;
      } catch {}
    }
  };
}

// ── WEBSITES ──────────────────────────────────────────────────────────────────
function websitesPage() {
  return {
    sites: [], showAdd: false, addTab: 'create',
    form: { domain:'', path:'', php:'8.3', type:'PHP', createDb:false, createFtp:false, deploy:'' },
    confModal: { show:false, domain:'', content:'', path:'' },
    batchDomains: '',
    oneClickApps: [
      {name:'WordPress', icon:'📝', desc:'PHP CMS platform'},
      {name:'Nextcloud', icon:'☁', desc:'Self-hosted cloud'},
      {name:'Gitea',     icon:'🐱', desc:'Git server'},
      {name:'Ghost',     icon:'👻', desc:'Blogging platform'},
      {name:'Discourse', icon:'💬', desc:'Community forum'},
      {name:'Mautic',    icon:'📈', desc:'Marketing automation'},
    ],
    async init() { await this.load(); },
    async load() {
      const r = await get('/api/websites'); if (r.ok) this.sites = r.sites;
    },
    async create() {
      const r = await post('/api/websites', this.form);
      if (r.ok) { toast('Site created: '+r.domain, 'success'); this.showAdd=false; await this.load(); }
      else toast(r.error||'Failed', 'error');
    },
    async del(domain) {
      if (!confirm('Delete '+domain+'?')) return;
      const r = await del('/api/websites/'+domain);
      if (r.ok) { toast('Deleted', 'success'); await this.load(); }
    },
    async issueSSL(s) {
      toast('Issuing SSL for '+s.domain+'…', 'info');
      const r = await post(`/api/websites/${s.domain}/ssl`, {});
      toast(r.ok?'SSL issued!':'SSL failed: '+(r.error||''), r.ok?'success':'error');
      await this.load();
    },
    async editConf(s) {
      const r = await get(`/api/websites/${s.domain}/config`);
      if (r.ok) { this.confModal = {show:true, domain:s.domain, content:r.content, path:r.path}; }
      else toast('Config not found', 'error');
    },
    async saveConf() {
      const r = await put(`/api/websites/${this.confModal.domain}/config`, {content:this.confModal.content});
      if (r.ok) { toast('Config saved & Nginx reloaded', 'success'); this.confModal.show=false; }
      else toast('Save failed', 'error');
    }
  };
}

// ── DATABASES ────────────────────────────────────────────────────────────────
function databasesPage() {
  return {
    tab: 'databases', databases: [], dbUsers: [], showAdd: false,
    form: { name:'', user:'', password:'' },
    async init() { await this.loadDbs(); },
    async loadDbs() { const r = await get('/api/databases'); if (r.ok) this.databases = r.databases; },
    async loadUsers() { const r = await get('/api/databases/users'); if (r.ok) this.dbUsers = r.users; },
    async createDb() {
      const r = await post('/api/databases', this.form);
      if (r.ok) { toast('Database created', 'success'); this.showAdd=false; await this.loadDbs(); }
      else toast(r.error||'Failed', 'error');
    },
    async dropDb(name) {
      if (!confirm('Drop database "'+name+'"? This cannot be undone!')) return;
      const r = await del('/api/databases/'+name);
      if (r.ok) { toast('Dropped', 'success'); await this.loadDbs(); }
    },
    async dropUser(user) {
      if (!confirm('Drop user "'+user+'"?')) return;
      const r = await del('/api/databases/users/'+user);
      if (r.ok) { toast('User dropped', 'success'); await this.loadUsers(); }
    }
  };
}

// ── FILES ─────────────────────────────────────────────────────────────────────
function filesPage() {
  return {
    currentPath: '/www/wwwroot', items: [], editor: { show:false, path:'', content:'' },
    showMkdir: false, mkdirName: '', fmtSize, fmtDate,
    async init() { await this.load(); },
    async load() {
      const r = await get('/api/files/list?path='+encodeURIComponent(this.currentPath));
      if (r.ok) { this.currentPath = r.path; this.items = r.items; }
      else toast(r.error||'Error', 'error');
    },
    async navigateTo(path) { this.currentPath = path; await this.load(); },
    async goUp() {
      const p = this.currentPath.split('/').slice(0,-1).join('/') || '/';
      this.currentPath = p; await this.load();
    },
    breadcrumbs() {
      const parts = this.currentPath.split('/').filter(Boolean);
      const crumbs = [{name:'/', path:'/'}];
      let cur = '';
      for (const p of parts) { cur += '/'+p; crumbs.push({name:p, path:cur}); }
      return crumbs;
    },
    async openFile(f) {
      const r = await get('/api/files/read?path='+encodeURIComponent(f.path));
      if (r.ok) this.editor = {show:true, path:r.path, content:r.content};
      else toast(r.error||'Cannot open', 'error');
    },
    async saveFile() {
      const r = await post('/api/files/write', {path:this.editor.path, content:this.editor.content});
      if (r.ok) { toast('Saved', 'success'); this.editor.show=false; }
      else toast(r.error||'Save failed', 'error');
    },
    async delFile(f) {
      if (!confirm('Delete '+f.name+'?')) return;
      const r = await post('/api/files/delete', {path:f.path});
      if (r.ok) { toast('Deleted', 'success'); await this.load(); }
      else toast(r.error||'Error', 'error');
    },
    async mkdir() {
      const path = this.currentPath + '/' + this.mkdirName;
      const r = await post('/api/files/mkdir', {path});
      if (r.ok) { toast('Folder created', 'success'); this.showMkdir=false; this.mkdirName=''; await this.load(); }
    },
    async uploadFiles(e) {
      const files = e.target.files;
      for (const f of files) {
        const fd = new FormData(); fd.append('file', f); fd.append('path', this.currentPath);
        await fetch('/api/files/upload', {method:'POST', body:fd});
      }
      toast('Uploaded '+files.length+' file(s)', 'success');
      await this.load();
    }
  };
}

// ── PHP ───────────────────────────────────────────────────────────────────────
function phpPage() {
  return {
    versions: [], extensions: [], selVer: '',
    iniModal: { show:false, version:'', content:'', path:'' },
    async init() {
      const r = await get('/api/php/versions');
      if (r.ok) {
        this.versions = r.versions;
        if (r.versions.length) { this.selVer = r.versions[0].version; this.loadExt(this.selVer); }
      }
    },
    async loadExt(v) {
      this.selVer = v;
      const r = await get('/api/php/'+v+'/extensions');
      if (r.ok) this.extensions = r.extensions;
    },
    async editIni(v) {
      const r = await get('/api/php/'+v+'/ini');
      if (r.ok) this.iniModal = {show:true, version:v, content:r.content, path:r.path};
      else toast(r.error||'php.ini not found', 'error');
    },
    async saveIni() {
      const r = await put('/api/php/'+this.iniModal.version+'/ini', {path:this.iniModal.path, content:this.iniModal.content});
      if (r.ok) { toast('Saved & FPM reloaded', 'success'); this.iniModal.show=false; }
    },
    async fpmAction(v, action) {
      const r = await post('/api/php/'+v+'/fpm', {action});
      toast((r.ok?'Done: ':'Error: ')+action+' php'+v+'-fpm', r.ok?'success':'error');
      const rr = await get('/api/php/versions'); if (rr.ok) this.versions = rr.versions;
    }
  };
}

// ── SERVICES ─────────────────────────────────────────────────────────────────
function servicesPage() {
  return {
    services: [],
    async init() { await this.load(); },
    async load() { const r = await get('/api/services'); if (r.ok) this.services = r.services; },
    async ctrl(name, action) {
      toast(action+' '+name+'…', 'info');
      const r = await post('/api/services/'+name+'/'+action);
      toast(r.ok?'Done':'Failed: '+name, r.ok?'success':'error');
      await this.load();
    }
  };
}

// ── FIREWALL ─────────────────────────────────────────────────────────────────
function firewallPage() {
  return {
    rules: [], fwStatus: 'inactive', showAdd: false,
    form: { action:'allow', port:'', proto:'tcp', from:'' },
    async init() { await this.load(); },
    async load() {
      const r = await get('/api/firewall/rules');
      if (r.ok) { this.rules = r.rules; this.fwStatus = r.status; }
    },
    async toggleFW() {
      const enable = this.fwStatus !== 'active';
      await post('/api/firewall/status', {enable});
      await this.load();
    },
    async addRule() {
      const r = await post('/api/firewall/rules', this.form);
      if (r.ok) { toast('Rule added', 'success'); this.showAdd=false; await this.load(); }
    },
    async delRule(num) {
      const r = await del('/api/firewall/rules/'+num);
      if (r.ok) { toast('Rule deleted', 'success'); await this.load(); }
    },
    async preset(name) {
      await post('/api/firewall/presets', {preset:name});
      toast(name+' preset applied', 'success'); await this.load();
    }
  };
}

// ── TERMINAL ─────────────────────────────────────────────────────────────────
function terminalPage() {
  return {
    cmd: '', cwd: '/', output: '', loading: false,
    quickCmds: [
      {label:'top',      cmd:'top -bn1 | head -20'},
      {label:'df -h',    cmd:'df -h'},
      {label:'free -h',  cmd:'free -h'},
      {label:'nginx -t', cmd:'nginx -t'},
      {label:'last 20',  cmd:'last -20'},
      {label:'dmesg',    cmd:'dmesg | tail -20'},
      {label:'uptime',   cmd:'uptime'},
      {label:'who',      cmd:'who'},
    ],
    async run() {
      if (!this.cmd.trim()) return;
      this.loading = true;
      const r = await post('/api/terminal/exec', {cmd:this.cmd, cwd:this.cwd});
      if (r.ok) {
        this.output += `$ ${this.cmd}\n${r.stdout||r.stderr||'(no output)'}\n\n`;
      } else {
        this.output += `$ ${this.cmd}\nERROR: ${r.error}\n\n`;
      }
      this.loading = false;
      // Auto-scroll
      this.$nextTick(() => {
        const el = document.querySelector('.terminal-out');
        if (el) el.scrollTop = el.scrollHeight;
      });
    }
  };
}

// ── BACKUPS ───────────────────────────────────────────────────────────────────
function backupsPage() {
  return {
    backups: [], creating: '', fmtSize, fmtDate,
    async init() { await this.load(); },
    async load() { const r = await get('/api/backups'); if (r.ok) this.backups = r.backups; },
    async create(type) {
      this.creating = type;
      const r = await post('/api/backups/create', {target:type});
      if (r.ok) { toast('Backup started: '+r.name, 'info'); }
      else toast(r.error||'Failed', 'error');
      setTimeout(() => { this.creating=''; this.load(); }, 3000);
    },
    async del(name) {
      if (!confirm('Delete backup '+name+'?')) return;
      const r = await del('/api/backups/'+name);
      if (r.ok) { toast('Deleted', 'success'); await this.load(); }
    }
  };
}

// ── DNS ───────────────────────────────────────────────────────────────────────
function dnsPage() {
  return {
    zones: [], records: [], selZone: '', showAdd: false,
    form: { domain:'', ip:'' },
    async init() { await this.load(); },
    async load() { const r = await get('/api/dns/zones'); if (r.ok) this.zones = r.zones; },
    async loadRecords(domain) {
      this.selZone = domain;
      const r = await get('/api/dns/zones/'+domain+'/records');
      if (r.ok) this.records = r.records;
    },
    async addZone() {
      const r = await post('/api/dns/zones', this.form);
      if (r.ok) { toast('Zone created', 'success'); this.showAdd=false; await this.load(); }
      else toast(r.error||'Failed', 'error');
    }
  };
}

// ── MAIL ──────────────────────────────────────────────────────────────────────
function mailPage() {
  return {
    tab: 'domains', status: {postfix:'',dovecot:'',queue:0}, domains: [], accounts: [],
    showAddDomain: false, showAddAccount: false, newDomain: '',
    newAccount: { email:'', password:'' }, queueOutput: '',
    async init() { await this.loadStatus(); await this.loadDomains(); },
    async loadStatus() { const r = await get('/api/mail/status'); if (r.ok) this.status = r; },
    async loadDomains() { const r = await get('/api/mail/domains'); if (r.ok) this.domains = r.domains; },
    async loadAccounts() { const r = await get('/api/mail/accounts'); if (r.ok) this.accounts = r.accounts; },
    async loadQueue() { const r = await get('/api/mail/queue'); if (r.ok) this.queueOutput = r.output; },
    async addDomain() {
      const r = await post('/api/mail/domains', {domain:this.newDomain});
      if (r.ok) { toast('Domain added', 'success'); this.showAddDomain=false; await this.loadDomains(); }
    },
    async addAccount() {
      const r = await post('/api/mail/accounts', this.newAccount);
      if (r.ok) { toast('Account created: '+r.email, 'success'); this.showAddAccount=false; await this.loadAccounts(); }
      else toast(r.error||'Failed', 'error');
    },
    async delAccount(email) {
      if (!confirm('Delete '+email+'?')) return;
      await del('/api/mail/accounts/'+email);
      toast('Deleted', 'success'); await this.loadAccounts();
    },
    async flushQueue() { await post('/api/mail/queue/flush'); toast('Queue flushed', 'success'); await this.loadStatus(); },
    async genDkim(domain) {
      const r = await post('/api/mail/dkim/'+domain);
      return r.ok ? r.record : (toast(r.error||'Failed', 'error'), '');
    },
    async getDkim(domain) {
      const r = await get('/api/mail/dkim/'+domain);
      return r.ok ? r.record : (toast(r.error||'Not found', 'error'), '');
    }
  };
}

// ── FTP ───────────────────────────────────────────────────────────────────────
function ftpPage() {
  return {
    accounts: [], ftpStatus: {daemon:'none'}, showAdd: false,
    form: { user:'', password:'', home:'' },
    async init() {
      const [a, s] = await Promise.all([get('/api/ftp/accounts'), get('/api/ftp/status')]);
      if (a.ok) this.accounts = a.accounts;
      if (s.ok) this.ftpStatus = s;
    },
    async create() {
      const r = await post('/api/ftp/accounts', this.form);
      if (r.ok) { toast('FTP account created', 'success'); this.showAdd=false; const a=await get('/api/ftp/accounts'); if(a.ok) this.accounts=a.accounts; }
      else toast(r.error||'Failed', 'error');
    },
    async del(user) {
      if (!confirm('Delete FTP user '+user+'?')) return;
      await del('/api/ftp/accounts/'+user);
      toast('Deleted', 'success'); const a=await get('/api/ftp/accounts'); if(a.ok) this.accounts=a.accounts;
    }
  };
}

// ── CRON ──────────────────────────────────────────────────────────────────────
function cronPage() {
  return {
    jobs: [], showAdd: false, form: { schedule:'0 * * * *', command:'' },
    presets: [
      {label:'Every minute',   val:'* * * * *'},
      {label:'Every hour',     val:'0 * * * *'},
      {label:'Daily 2am',      val:'0 2 * * *'},
      {label:'Weekly Sun',     val:'0 2 * * 0'},
      {label:'Monthly 1st',    val:'0 2 1 * *'},
      {label:'Every 5 min',    val:'*/5 * * * *'},
      {label:'Every 15 min',   val:'*/15 * * * *'},
      {label:'Weekdays 8am',   val:'0 8 * * 1-5'},
    ],
    async init() { await this.load(); },
    async load() { const r = await get('/api/cron/jobs'); if (r.ok) this.jobs = r.jobs; },
    async add() {
      const r = await post('/api/cron/jobs', this.form);
      if (r.ok) { toast('Job added', 'success'); this.showAdd=false; await this.load(); }
      else toast(r.error||'Failed', 'error');
    },
    async del(id) {
      if (!confirm('Delete this cron job?')) return;
      const r = await del('/api/cron/jobs/'+id);
      if (r.ok) { toast('Deleted', 'success'); await this.load(); }
    }
  };
}

// ── DOCKER ───────────────────────────────────────────────────────────────────
function dockerPage() {
  return {
    tab: 'containers', info: {}, containers: [], images: [],
    logsModal: { show:false, name:'', content:'' },
    async init() { await this.loadInfo(); await this.loadContainers(); },
    async loadInfo() { const r = await get('/api/docker/info'); if (r.ok) this.info = r; },
    async loadContainers() { const r = await get('/api/docker/containers'); if (r.ok) this.containers = r.containers; },
    async loadImages() { const r = await get('/api/docker/images'); if (r.ok) this.images = r.images; },
    async ctrl(name, action) {
      const r = await post('/api/docker/containers/'+name+'/'+action);
      toast(r.ok?action+' '+name:'Failed', r.ok?'success':'error');
      await this.loadContainers();
    },
    async showLogs(name) {
      const r = await get('/api/docker/logs/'+name);
      if (r.ok) this.logsModal = {show:true, name, content:r.logs};
    },
    async rmImage(img) {
      if (!confirm('Remove image '+img+'?')) return;
      const r = await del('/api/docker/images/'+encodeURIComponent(img));
      toast(r.ok?'Removed':'Failed', r.ok?'success':'error');
      await this.loadImages();
    }
  };
}

// ── MONITORING ───────────────────────────────────────────────────────────────
function monitoringPage() {
  return {
    tab: 'processes', processes: [], logContent: '', logType: 'nginx_error', logSearch: '', netstat: '',
    async init() { await this.loadProcesses(); await this.loadLog(); },
    async loadProcesses() {
      const r = await get('/api/monitoring/processes');
      if (r.ok) this.processes = r.processes;
    },
    async loadLog() {
      const r = await get('/api/monitoring/logs?log='+this.logType+'&lines=200');
      if (r.ok) this.logContent = r.content;
    },
    async loadNetstat() {
      const r = await get('/api/monitoring/netstat');
      if (r.ok) this.netstat = r.output;
    },
    filteredLog() {
      if (!this.logSearch) return this.logContent;
      return this.logContent.split('\n').filter(l => l.toLowerCase().includes(this.logSearch.toLowerCase())).join('\n');
    }
  };
}

// ── MODULES ──────────────────────────────────────────────────────────────────
function modulesPage() {
  return {
    modules: [], cat: '', outModal: { show:false, title:'', content:'' },
    async init() { await this.load(); },
    async load() { const r = await get('/api/modules'); if (r.ok) this.modules = r.modules; },
    categories() { return [...new Set(this.modules.map(m=>m.category))].sort(); },
    filtered() { return this.cat ? this.modules.filter(m=>m.category===this.cat) : this.modules; },
    async install(m) {
      m.loading = true;
      toast('Installing '+m.name+'…', 'info');
      const r = await post('/api/modules/'+m.id+'/install');
      m.loading = false;
      m.installed = r.installed;
      this.outModal = {show:true, title:'Install: '+m.name, content:r.output||'Done'};
      toast(r.installed?m.name+' installed!':'Install failed', r.installed?'success':'error');
    },
    async uninstall(m) {
      if (!confirm('Uninstall '+m.name+'?')) return;
      const r = await post('/api/modules/'+m.id+'/uninstall');
      m.installed = r.installed;
      toast(m.name+' uninstalled', 'success');
    }
  };
}

// ── SETTINGS ─────────────────────────────────────────────────────────────────
function settingsPage() {
  return {
    tab: 'general', config: {panel_name:'VortexPanel',timezone:'UTC',auto_update:true},
    sysInfo: {}, pw: {new_password:'', confirm:''}, newHostname: '',
    async init() { await this.load(); },
    async load() {
      const r = await get('/api/settings');
      if (r.ok) { this.config = r.config; this.sysInfo = r.system; }
    },
    async save() {
      const r = await put('/api/settings', this.config);
      toast(r.ok?'Settings saved':'Save failed', r.ok?'success':'error');
    },
    async changePw() {
      if (this.pw.new_password !== this.pw.confirm) { toast('Passwords do not match', 'error'); return; }
      const r = await post('/api/settings/password', this.pw);
      toast(r.ok?'Password changed':'Failed: '+(r.error||''), r.ok?'success':'error');
      if (r.ok) this.pw = {new_password:'', confirm:''};
    },
    async setHostname() {
      const r = await post('/api/settings/hostname', {hostname:this.newHostname});
      toast(r.ok?'Hostname set':'Failed', r.ok?'success':'error');
    },
    async sysUpdate() {
      toast('System update started in background…', 'info');
      await post('/api/settings/update');
    },
    async sysReboot() {
      toast('Server rebooting in 3 seconds…', 'info');
      await post('/api/settings/reboot');
    }
  };
}
