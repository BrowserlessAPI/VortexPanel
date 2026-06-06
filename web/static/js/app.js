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


// ── DATABASES ────────────────────────────────────────────────────────────────
function databasesPage() {
  return {
    tab: 'databases', databases: [], dbUsers: [], showAdd: false, dbError: '',
    form: { name:'', user:'', password:'' },
    async init() { await this.loadDbs(); },
    async loadDbs() {
      const r = await get('/api/databases');
      if (r.ok) { this.databases = r.databases; this.dbError = r.databases.length===0 ? 'No databases yet' : ''; }
      else { this.dbError = r.error || 'Cannot connect to MySQL/MariaDB'; }
    },
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
    versions: [], selVer: '', selTab: 'extensions',
    extensions: [], config: {}, fpmProfile: {},
    iniModal: { show:false, version:'', content:'', path:'' },
    fpmModal: { show:false, version:'', content:'', path:'' },
    logContent: '', phpinfo: '',

    async init() {
      const r = await get('/api/php/versions');
      if (r.ok && r.versions.length) {
        this.versions = r.versions;
        await this.selectVer(r.versions[0].version);
      }
    },

    async selectVer(v) {
      this.selVer = v;
      this.selTab = 'extensions';
      await this.loadTab();
    },

    async loadTab() {
      if (!this.selVer) return;
      if (this.selTab === 'extensions') {
        const r = await get('/api/php/'+this.selVer+'/extensions');
        if (r.ok) this.extensions = r.extensions.map(e=>({...e,loading:false}));
      } else if (this.selTab === 'config') {
        const r = await get('/api/php/'+this.selVer+'/config');
        if (r.ok) this.config = r.config;
      } else if (this.selTab === 'fpm') {
        const r = await get('/api/php/'+this.selVer+'/fpmprofile');
        if (r.ok) this.fpmProfile = r.config;
      } else if (this.selTab === 'logs') {
        const r = await get('/api/php/'+this.selVer+'/logs');
        this.logContent = r.ok ? r.content : (r.error || 'Log not found');
      } else if (this.selTab === 'phpinfo') {
        const r = await get('/api/php/'+this.selVer+'/phpinfo');
        if (r.ok) this.phpinfo = r.content;
      }
    },

    async installExt(ext) {
      ext.loading = true;
      const r = await post('/api/php/'+this.selVer+'/extensions/'+ext.name+'/install');
      ext.loading = false;
      if (r.ok) { ext.installed = r.installed; toast((r.installed?'Installed: ':'Failed: ')+ext.name, r.installed?'success':'error'); }
    },

    async uninstallExt(ext) {
      if (!confirm('Uninstall '+ext.name+'?')) return;
      const r = await post('/api/php/'+this.selVer+'/extensions/'+ext.name+'/uninstall');
      if (r.ok) { ext.installed = false; toast('Uninstalled: '+ext.name, 'success'); }
    },

    async saveConfig() {
      const r = await put('/api/php/'+this.selVer+'/config', {config:this.config});
      toast(r.ok?'Config saved & FPM reloaded':'Failed', r.ok?'success':'error');
    },

    async openIni() {
      const r = await get('/api/php/'+this.selVer+'/ini');
      if (r.ok) this.iniModal = {show:true, version:this.selVer, content:r.content, path:r.path};
      else toast(r.error||'php.ini not found', 'error');
    },

    async saveIni() {
      const r = await put('/api/php/'+this.selVer+'/ini', {path:this.iniModal.path, content:this.iniModal.content});
      if (r.ok) { toast('Saved & FPM reloaded', 'success'); this.iniModal.show=false; }
    },

    async fpmAction(action) {
      const r = await post('/api/php/'+this.selVer+'/fpm', {action});
      toast((r.ok?'Done: ':'Error: ')+action, r.ok?'success':'error');
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
    modules: [], cat: '',
    jobModal: { show:false, title:'', lines:[], done:false, success:false, action:'install', installedVer:'' },

    async init() { await this.load(); },
    async load() {
      const r = await get('/api/modules');
      if (r.ok) this.modules = r.modules.map(m=>({
        ...m, loading:false,
        // Set default selected version to middle option
        selVer: m.versions && m.versions.length ? m.versions[Math.floor(m.versions.length/2)].value : ''
      }));
    },
    categories() { return [...new Set(this.modules.map(m=>m.category))].sort(); },
    filtered()   { return this.cat ? this.modules.filter(m=>m.category===this.cat) : this.modules; },

    async install(m) {
      if (m.versions && m.versions.length && !m.selVer) {
        toast('Please select a version first','error'); return;
      }
      await this._startJob(m, 'install', m.selVer||'');
    },

    async uninstall(m) {
      if (!confirm('Uninstall '+m.name+'?\nThis will remove the software from your server.')) return;
      await this._startJob(m, 'uninstall', '');
    },

    async _startJob(m, action, ver) {
      m.loading = true;
      const r = await post(`/api/modules/${m.id}/${action}`, {version:ver});
      if (!r.ok) { m.loading=false; toast(r.error||'Failed','error'); return; }
      const jobId = r.job_id;
      const label = (action==='install'?'Installing':'Removing')+': '+m.name+(ver?' v'+ver:'');
      this.jobModal = {show:true, title:label, lines:[], done:false, installed:false, installedVer:''};
      const es = new EventSource(`/api/modules/job/${jobId}`);
      es.onmessage = (e) => {
        const d = JSON.parse(e.data);
        if (d.line) this.jobModal.lines.push(d.line);
        if (d.done) {
          es.close(); m.loading=false;
          m.installed = d.installed;
          if (d.installedVer) m.installedVer = d.installedVer;
          // success = true means the action completed OK (install->installed, uninstall->removed)
          this.jobModal.done     = true;
          this.jobModal.success  = d.success;   // action-specific success flag
          this.jobModal.action   = action;
          this.jobModal.installedVer = d.installedVer || '';
          setTimeout(()=>this.load(), 1200);
        }
        if (d.error) { es.close(); m.loading=false; toast(d.error,'error'); }
        this.$nextTick(()=>{ const t=document.querySelector('.job-terminal'); if(t) t.scrollTop=t.scrollHeight; });
      };
      es.onerror=()=>{ es.close(); m.loading=false; };
    },

    async control(m, action) {
      const r = await post(`/api/modules/${m.id}/control`,{action});
      if (r.ok) { m.svcStatus=r.status; toast(action+' '+m.name,'success'); }
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

// ── WEBSITES (full drawer version) ───────────────────────────────────────────
function websitesPage() {
  return {
    sites: [], showAdd: false, addTab: 'create', webroot: '/www/wwwroot',
    form: { domain:'', path:'', php:'8.3', type:'PHP', createDb:false, createFtp:false, path_edited:false },
    batchDomains: '', deployApps: [], deployApp: '', deployDomain: '',
    drawer: {
      show:false, site:null, tab:'config',
      confContent:'', confPath:'',
      sslTab:'le', sslEmail:'', sslKey:'', sslCert:'', sslOutput:'', sslInfo:'',
      phpVer:'8.3',
      proxies:[], showAddProxy:false,
      proxyForm:{ name:'', path:'/', target:'', sent_domain:'$host' },
      redirectForm:{ target:'', mode:'301', keep_uri:'true' },
      nodejsEnabled:false, nodejsForm:{ app_path:'', startup:'index.js', port:'3000' },
      maintEnabled:false, maintMessage:'We are performing scheduled maintenance. Please check back soon.',
      loading:false,
    },
    drawerTabs: [
      {id:'config',      label:'⚙ Config'},
      {id:'ssl',         label:'🔒 SSL'},
      {id:'php',         label:'🐘 PHP Version'},
      {id:'proxy',       label:'🔀 Reverse Proxy'},
      {id:'redirect',    label:'↪ Redirect'},
      {id:'nodejs',      label:'🟢 Node.js'},
      {id:'maintenance', label:'🔧 Maintenance'},
    ],

    async init() {
      const wr = await get('/api/websites/webroot').catch(()=>({ok:false}));
      if (wr.ok) this.webroot = wr.path;
      await this.load();
    },
    async load() { const r = await get('/api/websites'); if (r.ok) this.sites = r.sites; },

    async create() {
      const r = await post('/api/websites', this.form);
      if (r.ok) { toast('Site created: '+r.domain,'success'); this.showAdd=false; await this.load(); }
      else toast(r.error||'Failed','error');
    },

    async del(domain) {
      if (!confirm('Delete '+domain+'?')) return;
      const r = await del('/api/websites/'+domain);
      if (r.ok) { toast('Deleted','success'); await this.load(); }
    },

    async loadDeployApps() {
      const r = await get('/api/websites/deploy-apps');
      if (r.ok) {
        const emojis = {wordpress:'📝',drupal:'🔵',joomla:'🔴',laravel:'🔶',opencart:'🛒'};
        this.deployApps = r.apps.map(a=>({...a, emoji:emojis[a.id]||'📦'}));
        if (!this.deployApp && this.deployApps.length) this.deployApp = this.deployApps[0].id;
      }
    },

    async deployNow() {
      if (!this.deployDomain) { toast('Enter a domain first','error'); return; }
      if (!this.deployApp) { toast('Select an app','error'); return; }
      toast('Deploying '+this.deployApp+'…','info');
      const r = await post(`/api/websites/${this.deployDomain}/deploy`, {app:this.deployApp});
      if (r.ok) { toast('Deployed successfully!','success'); this.showAdd=false; await this.load(); }
      else toast(r.error||'Deploy failed','error');
    },

    openDrawer(s) {
      this.drawer = {...this.drawer, show:true, site:s, tab:'config', loading:false,
        sslEmail:'', sslKey:'', sslCert:'', sslOutput:'', sslInfo:'',
        phpVer: s.php || '8.3',
        proxies:[], showAddProxy:false,
        proxyForm:{ name:'', path:'/', target:'', sent_domain:'$host' },
        redirectForm:{ target:'', mode:'301', keep_uri:'true' },
        nodejsEnabled:false, nodejsForm:{ app_path:s.path||'', startup:'index.js', port:'3000' },
        maintEnabled:false, maintMessage:'We are performing scheduled maintenance. Please check back soon.',
      };
      this.loadDrawerTab();
    },

    async loadDrawerTab() {
      const d = this.drawer; const domain = d.site?.domain;
      if (!domain) return;
      if (d.tab==='config') {
        const r = await get(`/api/websites/${domain}/config`);
        if (r.ok) { d.confContent=r.content; d.confPath=r.path; }
      } else if (d.tab==='ssl') {
        const r = await get(`/api/websites/${domain}/ssl/info`);
        if (r.ok) d.sslInfo = r.info;
      } else if (d.tab==='proxy') {
        const r = await get(`/api/websites/${domain}/proxy`);
        if (r.ok) d.proxies = r.proxies;
      } else if (d.tab==='nodejs') {
        const r = await get(`/api/websites/${domain}/nodejs`);
        if (r.ok) { d.nodejsEnabled=r.enabled; if(r.port) d.nodejsForm.port=r.port; }
      } else if (d.tab==='maintenance') {
        const r = await get(`/api/websites/${domain}/maintenance`);
        if (r.ok) d.maintEnabled = r.enabled;
      }
    },

    async saveConf() {
      const domain = this.drawer.site?.domain;
      const r = await put(`/api/websites/${domain}/config`, {content:this.drawer.confContent});
      toast(r.ok?'Saved & Nginx reloaded':'Save failed', r.ok?'success':'error');
    },

    async issueLetsEncrypt() {
      this.drawer.loading=true; this.drawer.sslOutput='Contacting Let\'s Encrypt...\n';
      const domain = this.drawer.site?.domain;
      const r = await post(`/api/websites/${domain}/ssl/letsencrypt`, {email:this.drawer.sslEmail});
      this.drawer.loading=false; this.drawer.sslOutput = r.output||'';
      toast(r.ok?'SSL issued!':'Failed — check output', r.ok?'success':'error');
      if(r.ok) await this.load();
    },

    async saveManualSSL() {
      if (!this.drawer.sslKey || !this.drawer.sslCert) { toast('Key and certificate required','error'); return; }
      this.drawer.loading=true;
      const domain = this.drawer.site?.domain;
      const r = await post(`/api/websites/${domain}/ssl/manual`, {key:this.drawer.sslKey, cert:this.drawer.sslCert});
      this.drawer.loading=false;
      toast(r.ok?'SSL installed!':r.error||'Failed', r.ok?'success':'error');
      if(r.ok) { this.drawer.show=false; await this.load(); }
    },

    async savePhpVer() {
      const domain = this.drawer.site?.domain;
      const r = await put(`/api/websites/${domain}/php`, {version:this.drawer.phpVer});
      toast(r.ok?`PHP ${this.drawer.phpVer} applied to ${domain}`:'Failed', r.ok?'success':'error');
      if(r.ok) await this.load();
    },

    async addProxy() {
      const domain = this.drawer.site?.domain;
      const r = await post(`/api/websites/${domain}/proxy`, this.drawer.proxyForm);
      if (r.ok) { toast('Proxy added','success'); this.drawer.showAddProxy=false; await this.loadDrawerTab(); }
      else toast(r.error||'Failed','error');
    },

    async delProxy(name) {
      const domain = this.drawer.site?.domain;
      const r = await del(`/api/websites/${domain}/proxy/${name}`);
      if (r.ok) { toast('Removed','success'); await this.loadDrawerTab(); }
    },

    async saveRedirect() {
      const domain = this.drawer.site?.domain;
      const form = {...this.drawer.redirectForm, keep_uri: this.drawer.redirectForm.keep_uri==='true'};
      const r = await post(`/api/websites/${domain}/redirect`, form);
      toast(r.ok?'Redirect set':'Failed: '+(r.error||''), r.ok?'success':'error');
    },

    async delRedirect() {
      const domain = this.drawer.site?.domain;
      const r = await del(`/api/websites/${domain}/redirect`);
      toast(r.ok?'Redirect removed':'Failed', r.ok?'success':'error');
    },

    async enableNodejs() {
      const domain = this.drawer.site?.domain;
      const r = await post(`/api/websites/${domain}/nodejs`, {...this.drawer.nodejsForm, enable:true});
      toast(r.ok?`Node.js enabled on port ${r.port}`:'Failed: '+(r.error||''), r.ok?'success':'error');
      if(r.ok) { this.drawer.nodejsEnabled=true; await this.load(); }
    },

    async disableNodejs() {
      const domain = this.drawer.site?.domain;
      const r = await post(`/api/websites/${domain}/nodejs`, {enable:false});
      if(r.ok) { toast('Node.js disabled','success'); this.drawer.nodejsEnabled=false; await this.load(); }
    },

    async toggleMaintenance(enable) {
      const domain = this.drawer.site?.domain;
      const r = await post(`/api/websites/${domain}/maintenance`, {enable, message:this.drawer.maintMessage});
      toast(r.ok?(enable?'Maintenance mode ON':'Site is now LIVE'):'Failed', r.ok?'success':'error');
      if(r.ok) this.drawer.maintEnabled = enable;
    },
  };
}

// ── BANDWIDTH ─────────────────────────────────────────────────────────────────
function bandwidthPage() {
  return {
    summary:{interface:'',total_rx:0,total_tx:0,daily:[],monthly:[]},
    rt:{rx_per_sec:0,tx_per_sec:0},
    domains:[], hasVnstat:false, fmtBytes,

    async init() {
      await this.loadSummary();
      await this.loadDomains();
      await this.loadRealtime();
      setInterval(()=>this.loadRealtime(), 3000);
    },

    async loadSummary() {
      const r = await get('/api/bandwidth/summary');
      if (r.ok) { this.summary=r; this.hasVnstat = r.source==='vnstat'; }
    },

    async loadRealtime() {
      const r = await get('/api/bandwidth/realtime');
      if (r.ok) this.rt = r;
    },

    async loadDomains() {
      const r = await get('/api/bandwidth/domains');
      if (r.ok) this.domains = r.domains;
    },

    async installVnstat() {
      toast('Installing vnstat…','info');
      const r = await post('/api/bandwidth/install-vnstat');
      toast(r.ok?'vnstat installed!':'Install failed','success');
      if(r.ok) await this.loadSummary();
    },
  };
}

// ── SECURITY ──────────────────────────────────────────────────────────────────
function securityPage() {
  return {
    tab: 'ssh',
    score: 0, checks: [],
    ssh: {port:'22',password_auth:'yes',root_login:'yes',pubkey_auth:'yes',max_auth_tries:'6'},
    f2bJails: [],
    attempts: [],
    portsOutput: '',

    async init() {
      await Promise.all([this.loadScore(), this.loadSSH()]);
    },

    async loadScore() {
      const r = await get('/api/security/score');
      if (r.ok) { this.score=r.score; this.checks=r.checks; }
    },

    async loadSSH() {
      const r = await get('/api/security/ssh');
      if (r.ok) this.ssh = r.config;
    },

    async saveSSH() {
      const r = await put('/api/security/ssh', this.ssh);
      toast(r.ok?'SSH config saved & reloaded':'Failed', r.ok?'success':'error');
      if(r.ok) await this.loadScore();
    },

    async loadFail2ban() {
      const r = await get('/api/security/fail2ban');
      if (r.ok) this.f2bJails = r.jails.map(j=>({...j,banInput:''}));
      else toast(r.error||'Fail2ban not running','error');
    },

    async unbanIP(ip, jail) {
      const r = await post('/api/security/fail2ban/unban', {ip, jail});
      toast(r.ok?`Unbanned ${ip}`:'Failed', r.ok?'success':'error');
      if(r.ok) await this.loadFail2ban();
    },

    async banIP(ip, jail) {
      if(!ip) return;
      const r = await post('/api/security/fail2ban/ban', {ip, jail});
      toast(r.ok?`Banned ${ip}`:'Failed', r.ok?'success':'error');
      if(r.ok) await this.loadFail2ban();
    },

    async loadAttempts() {
      const r = await get('/api/security/login-attempts');
      if (r.ok) this.attempts = r.attempts;
    },

    async loadPorts() {
      const r = await get('/api/security/ports');
      if (r.ok) this.portsOutput = r.output;
    },
  };
}
