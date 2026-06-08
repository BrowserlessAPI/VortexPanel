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
  if (!b) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let i=0; while(b>=1024&&i<4){b/=1024;i++;}
  return b.toFixed(i?1:0)+' '+units[i];
}
function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts*1000).toLocaleString();
}
function fmtSize(bytes) { return fmtBytes(bytes); }

// ── ROOT APP (single Alpine scope — handles auth + panel) ─────────────────────
function rootApp() {
  return {
    // Auth state
    loggedIn:  false,
    loginUser: '',
    loginPass: '',
    loginErr:  '',
    loginLoading: false,

    // Panel state
    username: '', page: 'dashboard',
    sidebarOpen: false,
    online: true,
    moduleStatus: {},
    updateAvailable: false,
    updateModal: {
      show:false, current:'v3.0.0', latest:'', name:'',
      body:'', published:'', url:'', error:'',
    },
    nav: [
      { group: 'Overview', items: [
        { id:'dashboard', icon:'▦', label:'Dashboard'    },
        { id:'websites',  icon:'🌐', label:'Websites'    },
        { id:'databases', icon:'🗄', label:'Databases'   },
        { id:'files',     icon:'📁', label:'File Manager'},
      ]},
      { group: 'Server', items: [
        { id:'services',  icon:'⚙', label:'Services'    },
        { id:'modules',   icon:'📦', label:'App Store'   },
        { id:'docker',    icon:'🐋', label:'Docker'      },
        { id:'firewall',  icon:'🛡', label:'Firewall'    },
        { id:'terminal',  icon:'⌨', label:'Terminal'    },
        { id:'backups',   icon:'💾', label:'Backups'     },
      ]},
      { group: 'Network', items: [
        { id:'dns',   icon:'🌍', label:'DNS Manager' },
        { id:'mail',  icon:'📧', label:'Mail Server' },
        { id:'ftp',   icon:'📂', label:'FTP / SFTP'  },
        { id:'cdn',   icon:'⚡', label:'CDN Manager' },
      ]},
      { group: 'System', items: [
        { id:'cron',       icon:'⏱', label:'Cron Jobs'  },
        { id:'monitoring', icon:'📊', label:'Monitoring' },
        { id:'bandwidth',  icon:'📈', label:'Bandwidth'  },
        { id:'security',   icon:'🔐', label:'Security'   },
        { id:'settings',   icon:'⚙', label:'Settings'   },
      ]},
    ],

    async init() {
      window.addEventListener('nav', e => this.go(e.detail.page));
      // Check existing session first
      try {
        const r = await get('/api/auth/check');
        if (r.ok && r.logged_in) {
          this.username = r.username || 'admin';
          this.loggedIn = true;
          await this._onLoggedIn();
        }
      } catch {}
    },

    // ── Login ────────────────────────────────────────────────────────────────
    async doLogin() {
      if (!this.loginUser || !this.loginPass) {
        this.loginErr = 'Enter username and password'; return;
      }
      this.loginLoading = true;
      this.loginErr = '';
      try {
        const r = await post('/api/auth/login', {
          username: this.loginUser,
          password: this.loginPass,
        });
        if (r.ok) {
          this.username = this.loginUser;
          this.loggedIn = true;
          this.loginPass = '';
          await this._onLoggedIn();
        } else {
          this.loginErr = r.error || 'Invalid username or password';
        }
      } catch(e) {
        this.loginErr = 'Connection error — try again';
      }
      this.loginLoading = false;
    },

    async _onLoggedIn() {
      // Restore page from URL hash (e.g. #files → go to files page)
      const hash = window.location.hash.replace('#', '');
      const validPages = ['dashboard','websites','databases','files','modules',
                          'services','firewall','terminal','backups','dns','mail','ftp',
                          'cron','monitoring','bandwidth','security','docker','caddy',
                          'cdn','settings'];
      if (hash && validPages.includes(hash)) {
        this.page = hash;
      }
      // Load module status for sidebar indicators
      try {
        const r = await get('/api/modules');
        if (r.ok) r.modules.forEach(m => { this.moduleStatus[m.id] = m.installed; });
      } catch {}
      // Silent update check after 3s
      setTimeout(() => this.silentUpdateCheck(), 3000);
    },

    // ── Panel navigation ──────────────────────────────────────────────────────
    go(id) {
      this.page = id;
      this.sidebarOpen = false;
      // Persist page in URL hash so refresh returns to same page
      if (history.replaceState) {
        history.replaceState(null, '', '#' + id);
      }
    },

    pageTitle() {
      for (const g of this.nav) {
        const item = g.items.find(i => i.id === this.page);
        if (item) return item.label;
      }
      return '';
    },

    pageAvailable(pageId) {
      const requires = {
        'ftp':  ['pure-ftpd','proftpd','vsftpd'],
        'mail': ['postfix'],
        'dns':  ['bind9'],
      };
      const req = requires[pageId];
      if (!req) return true;
      return req.some(m => this.moduleStatus[m]);
    },

    logout() {
      fetch('/api/auth/logout', {method:'POST'})
        .then(() => { this.loggedIn=false; this.loginUser=''; this.loginPass=''; this.loginErr=''; });
    },

    // ── Update ────────────────────────────────────────────────────────────────
    async silentUpdateCheck() {
      try {
        const r = await get('/api/update/check');
        if (r.current) this.updateModal.current = r.current;
        if (r.ok && r.has_update) {
          this.updateAvailable = true;
          this.updateModal.latest    = r.latest    || r.current;
          this.updateModal.name      = r.name      || 'VortexPanel';
          this.updateModal.body      = r.body      || '';
          this.updateModal.published = r.published || '';
          this.updateModal.url       = r.url       || '';
        }
      } catch {}
    },

    async openUpdateModal() {
      this.updateModal.show = true;
      this.$nextTick(() => {
        document.dispatchEvent(new CustomEvent('vortex-check-update'));
      });
    },
  };
}


// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function dashboardPage() {
  return {
    stats:{cpu:0,ram:0,disk:0,uptime:'',load:'',ramTotal:'',diskTotal:'',network:''},
    services:[], quickActions:[
      {icon:'🌐',label:'Manage Websites',page:'websites'},
      {icon:'🗄',label:'Manage Databases',page:'databases'},
      {icon:'📁',label:'File Manager',page:'files'},
      {icon:'⌨',label:'Terminal',page:'terminal'},
      {icon:'💾',label:'Create Backup',page:'backups'},
      {icon:'📦',label:'Install Modules',page:'modules'},
    ],
    async init() { await Promise.all([this.loadStats(),this.loadServices()]); setInterval(()=>this.loadStats(),5000); },
    async loadStats() {
      const r=await get('/api/dashboard/stats');
      if(r.ok) this.stats=r;
    },
    async loadServices() {
      const r=await get('/api/services');
      if(r.ok) this.services=r.services.slice(0,8);
    },
    go(page){ window.dispatchEvent(new CustomEvent('nav',{detail:{page}})); },
  };
}

// ── WEBSITES ──────────────────────────────────────────────────────────────────
function websitesPage() {
  return {
    sites:[], showAdd:false, addTab:'create', webroot:'/www/wwwroot',
    form:{domain:'',path:'',php:'8.3',type:'PHP',createDb:false,createFtp:false,path_edited:false},
    batchDomains:'', deployApps:[], deployApp:'', deployDomain:'',
    drawer:{
      show:false,site:null,tab:'config',
      confContent:'',confPath:'',
      sslTab:'le',sslEmail:'',sslKey:'',sslCert:'',sslOutput:'',sslInfo:'',
      phpVer:'8.3',
      proxies:[],showAddProxy:false,
      proxyForm:{name:'',path:'/',target:'',sent_domain:'$host'},
      redirectForm:{target:'',mode:'301',keep_uri:'true'},
      nodejsEnabled:false,nodejsForm:{app_path:'',startup:'index.js',port:'3000'},
      maintEnabled:false,maintMessage:'We are performing scheduled maintenance. Please check back soon.',
      loading:false,
    },
    drawerTabs:[
      {id:'config',label:'⚙ Config'},{id:'ssl',label:'🔒 SSL'},
      {id:'php',label:'🐘 PHP Version'},{id:'proxy',label:'🔀 Reverse Proxy'},
      {id:'redirect',label:'↪ Redirect'},{id:'nodejs',label:'🟢 Node.js'},
      {id:'maintenance',label:'🔧 Maintenance'},
    ],
    async init() {
      const wr=await get('/api/websites/webroot').catch(()=>({ok:false}));
      if(wr.ok) this.webroot=wr.path;
      await this.load();
    },
    async load() { const r=await get('/api/websites'); if(r.ok) this.sites=r.sites; },
    async create() {
      const r=await post('/api/websites',this.form);
      if(r.ok){toast('Site created: '+r.domain,'success');this.showAdd=false;await this.load();}
      else toast(r.error||'Failed','error');
    },
    async del(domain) {
      if(!confirm('Delete '+domain+'?')) return;
      const r=await del('/api/websites/'+domain);
      if(r.ok){toast('Deleted','success');await this.load();}
    },
    async loadDeployApps() {
      const r=await get('/api/websites/deploy-apps');
      if(r.ok){
        const emojis={wordpress:'📝',drupal:'🔵',joomla:'🔴',laravel:'🔶',opencart:'🛒'};
        this.deployApps=r.apps.map(a=>({...a,emoji:emojis[a.id]||'📦'}));
        if(!this.deployApp&&this.deployApps.length) this.deployApp=this.deployApps[0].id;
      }
    },
    async deployNow() {
      if(!this.deployDomain){toast('Enter a domain first','error');return;}
      if(!this.deployApp){toast('Select an app','error');return;}
      toast('Deploying '+this.deployApp+'…','info');
      const r=await post('/api/websites/'+this.deployDomain+'/deploy',{app:this.deployApp});
      if(r.ok){toast('Deployed!','success');this.showAdd=false;await this.load();}
      else toast(r.error||'Failed','error');
    },
    openDrawer(s) {
      this.drawer={...this.drawer,show:true,site:s,tab:'config',loading:false,
        phpVer:s.php||'8.3',proxies:[],showAddProxy:false,
        proxyForm:{name:'',path:'/',target:'',sent_domain:'$host'},
        redirectForm:{target:'',mode:'301',keep_uri:'true'},
        nodejsEnabled:false,nodejsForm:{app_path:s.path||'',startup:'index.js',port:'3000'},
        maintEnabled:false,maintMessage:'We are performing scheduled maintenance.',
        sslEmail:'',sslKey:'',sslCert:'',sslOutput:'',sslInfo:'',
      };
      this.loadDrawerTab();
    },
    async loadDrawerTab() {
      const d=this.drawer; const domain=d.site?.domain; if(!domain) return;
      if(d.tab==='config'){const r=await get('/api/websites/'+domain+'/config');if(r.ok){d.confContent=r.content;d.confPath=r.path;}}
      else if(d.tab==='ssl'){const r=await get('/api/websites/'+domain+'/ssl/info');if(r.ok)d.sslInfo=r.info;}
      else if(d.tab==='proxy'){const r=await get('/api/websites/'+domain+'/proxy');if(r.ok)d.proxies=r.proxies;}
      else if(d.tab==='nodejs'){const r=await get('/api/websites/'+domain+'/nodejs');if(r.ok){d.nodejsEnabled=r.enabled;if(r.port)d.nodejsForm.port=r.port;}}
      else if(d.tab==='maintenance'){const r=await get('/api/websites/'+domain+'/maintenance');if(r.ok)d.maintEnabled=r.enabled;}
    },
    async saveConf(){const r=await put('/api/websites/'+this.drawer.site?.domain+'/config',{content:this.drawer.confContent});toast(r.ok?'Saved':'Failed',r.ok?'success':'error');},
    async issueLetsEncrypt(){
      this.drawer.loading=true;
      const r=await post('/api/websites/'+this.drawer.site?.domain+'/ssl/letsencrypt',{email:this.drawer.sslEmail});
      this.drawer.loading=false; this.drawer.sslOutput=r.output||'';
      toast(r.ok?'SSL issued!':'Failed',r.ok?'success':'error');
    },
    async saveManualSSL(){
      if(!this.drawer.sslKey||!this.drawer.sslCert){toast('Key and cert required','error');return;}
      this.drawer.loading=true;
      const r=await post('/api/websites/'+this.drawer.site?.domain+'/ssl/manual',{key:this.drawer.sslKey,cert:this.drawer.sslCert});
      this.drawer.loading=false;
      toast(r.ok?'SSL installed!':r.error||'Failed',r.ok?'success':'error');
    },
    async savePhpVer(){const r=await put('/api/websites/'+this.drawer.site?.domain+'/php',{version:this.drawer.phpVer});toast(r.ok?'PHP applied':'Failed',r.ok?'success':'error');if(r.ok)await this.load();},
    async addProxy(){const r=await post('/api/websites/'+this.drawer.site?.domain+'/proxy',this.drawer.proxyForm);if(r.ok){toast('Proxy added','success');this.drawer.showAddProxy=false;await this.loadDrawerTab();}else toast(r.error||'Failed','error');},
    async delProxy(name){const r=await del('/api/websites/'+this.drawer.site?.domain+'/proxy/'+name);if(r.ok){toast('Removed','success');await this.loadDrawerTab();}},
    async saveRedirect(){const form={...this.drawer.redirectForm,keep_uri:this.drawer.redirectForm.keep_uri==='true'};const r=await post('/api/websites/'+this.drawer.site?.domain+'/redirect',form);toast(r.ok?'Redirect set':'Failed',r.ok?'success':'error');},
    async delRedirect(){const r=await del('/api/websites/'+this.drawer.site?.domain+'/redirect');toast(r.ok?'Removed':'Failed',r.ok?'success':'error');},
    async enableNodejs(){const r=await post('/api/websites/'+this.drawer.site?.domain+'/nodejs',{...this.drawer.nodejsForm,enable:true});toast(r.ok?'Node.js enabled':'Failed',r.ok?'success':'error');if(r.ok){this.drawer.nodejsEnabled=true;await this.load();}},
    async disableNodejs(){const r=await post('/api/websites/'+this.drawer.site?.domain+'/nodejs',{enable:false});if(r.ok){toast('Disabled','success');this.drawer.nodejsEnabled=false;await this.load();}},
    async toggleMaintenance(enable){const r=await post('/api/websites/'+this.drawer.site?.domain+'/maintenance',{enable,message:this.drawer.maintMessage});toast(r.ok?(enable?'Maintenance ON':'Site LIVE'):'Failed',r.ok?'success':'error');if(r.ok)this.drawer.maintEnabled=enable;},
  };
}

// ── DATABASES ─────────────────────────────────────────────────────────────────
function databasesPage() {
  return {
    dbs:[], users:[], tab:'dbs', showAdd:false, showAddUser:false,
    form:{name:'',user:'',pass:'',charset:'utf8mb4',collation:'utf8mb4_unicode_ci'},
    userForm:{name:'',pass:'',host:'%'},
    mysqlInstalled:true,
    async init(){await this.load();},
    async load(){
      const r=await get('/api/databases');
      if(r.ok){this.dbs=r.databases||[];this.mysqlInstalled=r.mysql_installed!==false;}
      const u=await get('/api/databases/users');
      if(u.ok) this.users=u.users||[];
    },
    async create(){
      const r=await post('/api/databases',this.form);
      if(r.ok){toast('Database created','success');this.showAdd=false;await this.load();}
      else toast(r.error||'Failed','error');
    },
    async drop(db){
      if(!confirm('Drop database "'+db+'"?')) return;
      const r=await del('/api/databases/'+db);
      if(r.ok){toast('Dropped','success');await this.load();}
    },
    async createUser(){
      const r=await post('/api/databases/users',this.userForm);
      if(r.ok){toast('User created','success');this.showAddUser=false;await this.load();}
      else toast(r.error||'Failed','error');
    },
    async dropUser(u){
      if(!confirm('Drop user "'+u+'"?')) return;
      const r=await del('/api/databases/users/'+u);
      if(r.ok){toast('Dropped','success');await this.load();}
    },
  };
}

// ── FILES ─────────────────────────────────────────────────────────────────────
function filesPage() {
  return {
    path: '/www/wwwroot', webroot: '/www/wwwroot',
    items: [], loading: false, sortKey: 'name', sortDir: 1,
    selected: [], clipboard: null, clipboardOp: '',

    // Search
    showSearch: false, searchQuery: '', searchInContent: false,
    searching: false, searchResults: [],

    // New file/folder
    showNewMenu: false, showNewFileModal: false, newFileIsFolder: false, newFileName: '',

    // Rename
    showRenameModal: false, renameTarget: null, renameValue: '',

    // Upload
    showUpload: false, uploadQueue: [], uploading: false,

    // Remote download
    showRemoteDl: false, remoteUrl: '', remoteDest: '',

    // Properties & chmod
    showPropsModal: false, props: null,
    showChmodModal: false, chmodTarget: null, chmodValue: '755',

    // Context menu
    ctxMenu: { show: false, x: 0, y: 0 }, ctxTarget: null,

    // ── EDITOR state ──────────────────────────────────────────────────────
    editorOpen: false,
    editorTabs: [],      // [{path, name, content, original, modified}]
    activeTab: null,
    editorContent: '',
    editorSearch: false,
    findStr: '', replaceStr: '', findCount: 0, findIdx: 0,
    cursorLine: 1, cursorCol: 1,
    lintErrors: [], showLintPanel: false,
    fontSize: 13,
    showHighlight: false, highlightedContent: '',

    get lineCount() {
      return this.editorContent.split('\n').length;
    },

    get breadcrumbs() {
      const parts = this.path.split('/').filter(Boolean);
      const crumbs = [{ name: 'Root', path: '/' }];
      let cur = '';
      for (const p of parts) {
        cur += '/' + p;
        crumbs.push({ name: p, path: cur });
      }
      return crumbs;
    },

    get sortedItems() {
      const dirs  = this.items.filter(i => i.type === 'dir');
      const files = this.items.filter(i => i.type === 'file');
      const sort  = (arr) => arr.sort((a, b) => {
        let av = a[this.sortKey] || '', bv = b[this.sortKey] || '';
        if (typeof av === 'string') av = av.toLowerCase();
        if (typeof bv === 'string') bv = bv.toLowerCase();
        return av < bv ? -this.sortDir : av > bv ? this.sortDir : 0;
      });
      return [...sort(dirs), ...sort(files)];
    },

    async init() {
      // Find first accessible webroot silently
      for (const p of ['/www/wwwroot', '/var/www/html', '/var/www', '/root', '/tmp']) {
        const r = await get('/api/files/list?path=' + encodeURIComponent(p));
        if (r.ok) { this.webroot = p; await this.loadDir(p); return; }
      }
      // Fallback: load root without toast error
      await this.loadDirSilent('/');
    },

    async loadDirSilent(p) {
      this.loading = true;
      const r = await get('/api/files/list?path=' + encodeURIComponent(p));
      this.loading = false;
      if (r.ok) {
        this.path  = r.path;
        this.items = r.items.map(i => ({ ...i, _more: false, calcSize: null }));
      }
      // No toast on silent load
    },

    async loadDir(p) {
      this.loading = true;
      const r = await get('/api/files/list?path=' + encodeURIComponent(p));
      this.loading = false;
      if (r.ok) {
        this.path       = r.path;
        this.items      = r.items.map(i => ({ ...i, _more: false, calcSize: null }));
        this.selected   = [];
        this.remoteDest = r.path;
        this.searchResults = [];
      } else {
        // Only show error if user explicitly navigated, not on auto-init
        if (p !== this.webroot) {
          toast(r.error || 'Cannot open directory', 'error');
        }
      }
    },

    goUp() {
      const parent = this.path.split('/').slice(0, -1).join('/') || '/';
      this.loadDir(parent);
    },

    sortBy(key) {
      if (this.sortKey === key) this.sortDir *= -1;
      else { this.sortKey = key; this.sortDir = 1; }
    },

    // ── File type helpers ───────────────────────────────────────────────────
    getIcon(name) {
      const ext = name.split('.').pop().toLowerCase();
      const icons = {
        php:'🐘', js:'🟨', ts:'🔷', jsx:'⚛', tsx:'⚛',
        html:'🌐', htm:'🌐', css:'🎨', scss:'🎨', sass:'🎨',
        json:'📋', xml:'📋', yaml:'📋', yml:'📋', toml:'📋',
        py:'🐍', rb:'💎', go:'🔵', rs:'🦀', java:'☕',
        sh:'⌨', bash:'⌨', zsh:'⌨',
        md:'📝', txt:'📝', log:'📋',
        jpg:'🖼', jpeg:'🖼', png:'🖼', gif:'🖼', svg:'🖼', webp:'🖼',
        zip:'📦', gz:'📦', tar:'📦', rar:'📦',
        sql:'🗄', db:'🗄',
        pdf:'📕', doc:'📘', docx:'📘', xls:'📗', xlsx:'📗',
        env:'🔐', htaccess:'⚙', htpasswd:'🔐',
        conf:'⚙', config:'⚙', ini:'⚙', cfg:'⚙',
        mp4:'🎬', mp3:'🎵', wav:'🎵',
      };
      return icons[ext] || '📄';
    },

    getLangIcon(name) {
      return this.getIcon(name);
    },

    getLang(name) {
      const ext = name.split('.').pop().toLowerCase();
      const langs = {
        php:'PHP', js:'JavaScript', ts:'TypeScript', jsx:'JSX', tsx:'TSX',
        html:'HTML', htm:'HTML', css:'CSS', scss:'SCSS', sass:'SASS',
        json:'JSON', xml:'XML', yaml:'YAML', yml:'YAML',
        py:'Python', rb:'Ruby', go:'Go', rs:'Rust', java:'Java',
        sh:'Shell', bash:'Shell', md:'Markdown', txt:'Plain Text',
        sql:'SQL', conf:'Config', ini:'INI', env:'ENV',
      };
      return langs[ext] || 'Plain Text';
    },

    isEditable(name) {
      const ext = name.split('.').pop().toLowerCase();
      const editable = ['php','js','ts','jsx','tsx','html','htm','css','scss','sass',
                        'json','xml','yaml','yml','py','rb','sh','bash','md','txt',
                        'sql','conf','ini','env','htaccess','log','toml','cfg','config'];
      return editable.includes(ext);
    },

    // ── Selection ────────────────────────────────────────────────────────────
    toggleSelect(p) {
      if (this.selected.includes(p)) this.selected = this.selected.filter(s => s !== p);
      else this.selected.push(p);
    },

    toggleAll(e) {
      if (e.target.checked) this.selected = this.items.map(i => i.path);
      else this.selected = [];
    },

    // ── Code Editor ──────────────────────────────────────────────────────────
    async openEditor(f) {
      if (!this.isEditable(f.name)) { toast('Cannot edit binary files', 'error'); return; }
      // Check if already open
      const existing = this.editorTabs.find(t => t.path === f.path);
      if (existing) { this.switchTab(existing); return; }

      const r = await get('/api/files/read?path=' + encodeURIComponent(f.path));
      if (!r.ok) { toast(r.error || 'Cannot read file', 'error'); return; }

      const tab = { path: f.path, name: f.name, content: r.content, original: r.content, modified: false };
      this.editorTabs.push(tab);
      this.switchTab(tab);
      this.editorOpen = true;
      this.$nextTick(() => {
        if (this.$refs.editor) this.$refs.editor.focus();
        document.documentElement.style.setProperty('--ed-fs', this.fontSize + 'px');
      });
    },

    switchTab(tab) {
      // Save current content to current tab
      if (this.activeTab) this.activeTab.content = this.editorContent;
      this.activeTab = tab;
      this.editorContent = tab.content;
      this.lintErrors = [];
      this.showLintPanel = false;
      this.cursorLine = 1; this.cursorCol = 1;
    },

    closeTab(tab) {
      if (tab.modified && !confirm('Close "' + tab.name + '"? Unsaved changes will be lost.')) return;
      const idx = this.editorTabs.indexOf(tab);
      this.editorTabs.splice(idx, 1);
      if (this.activeTab === tab) {
        if (this.editorTabs.length) {
          const newTab = this.editorTabs[Math.max(0, idx - 1)];
          this.switchTab(newTab);
        } else {
          this.activeTab = null; this.editorContent = ''; this.editorOpen = false;
        }
      }
    },

    onEditorInput() {
      if (this.activeTab) {
        this.activeTab.content = this.editorContent;
        this.activeTab.modified = this.editorContent !== this.activeTab.original;
      }
    },

    async saveFile() {
      if (!this.activeTab) return;
      const r = await post('/api/files/write', { path: this.activeTab.path, content: this.editorContent });
      if (r.ok) {
        this.activeTab.original = this.editorContent;
        this.activeTab.modified = false;
        toast('✓ Saved: ' + this.activeTab.name, 'success');
        // Auto-lint on save
        await this.lintCurrentFile();
      } else {
        toast('Save failed: ' + (r.error || ''), 'error');
      }
    },

    async saveAllFiles() {
      for (const tab of this.editorTabs.filter(t => t.modified)) {
        await post('/api/files/write', { path: tab.path, content: tab.content });
        tab.original = tab.content; tab.modified = false;
      }
      toast('All files saved', 'success');
    },

    async lintCurrentFile() {
      if (!this.activeTab) return;
      // Save first so lint reads latest content
      const r = await post('/api/files/lint', { path: this.activeTab.path });
      if (r.ok) {
        this.lintErrors = r.errors;
        this.showLintPanel = r.errors.length > 0;
        if (r.clean) toast('✓ No syntax errors', 'success');
        else toast('⚠ ' + r.errors.length + ' error(s) found', 'error');
      }
    },

    insertTab() {
      const ta = this.$refs.editor;
      if (!ta) return;
      const start = ta.selectionStart, end = ta.selectionEnd;
      this.editorContent = this.editorContent.substring(0, start) + '    ' + this.editorContent.substring(end);
      this.$nextTick(() => { ta.selectionStart = ta.selectionEnd = start + 4; });
    },

    syncScroll() {
      if (this.$refs.lineNums && this.$refs.editor) {
        this.$refs.lineNums.scrollTop = this.$refs.editor.scrollTop;
      }
    },

    updateCursor() {
      const ta = this.$refs.editor;
      if (!ta) return;
      const val = ta.value.substring(0, ta.selectionStart);
      const lines = val.split('\n');
      this.cursorLine = lines.length;
      this.cursorCol  = lines[lines.length - 1].length + 1;
    },

    cycleFontSize() {
      const sizes = [11, 12, 13, 14, 16, 18];
      const idx = sizes.indexOf(this.fontSize);
      this.fontSize = sizes[(idx + 1) % sizes.length];
      document.documentElement.style.setProperty('--ed-fs', this.fontSize + 'px');
    },

    jumpLine() {
      const line = prompt('Jump to line:', this.cursorLine);
      if (!line) return;
      const ta = this.$refs.editor; if (!ta) return;
      const lines = this.editorContent.split('\n');
      let pos = 0;
      for (let i = 0; i < Math.min(parseInt(line) - 1, lines.length); i++) {
        pos += lines[i].length + 1;
      }
      ta.focus(); ta.setSelectionRange(pos, pos);
      this.updateCursor();
    },

    doFind() {
      if (!this.findStr) return;
      const content = this.editorContent;
      const regex = new RegExp(this.findStr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const matches = [...content.matchAll(regex)];
      this.findCount = matches.length;
      if (!matches.length) { toast('Not found', 'info'); return; }
      this.findIdx = (this.findIdx + 1) % matches.length;
      const ta = this.$refs.editor; if (!ta) return;
      ta.focus();
      ta.setSelectionRange(matches[this.findIdx].index, matches[this.findIdx].index + this.findStr.length);
    },

    doReplace() {
      if (!this.findStr || !this.activeTab) return;
      const ta = this.$refs.editor; if (!ta) return;
      const start = ta.selectionStart, end = ta.selectionEnd;
      if (this.editorContent.substring(start, end).toLowerCase() === this.findStr.toLowerCase()) {
        this.editorContent = this.editorContent.substring(0, start) + this.replaceStr + this.editorContent.substring(end);
        ta.setSelectionRange(start, start + this.replaceStr.length);
      }
      this.doFind();
    },

    doReplaceAll() {
      if (!this.findStr || !this.activeTab) return;
      const regex = new RegExp(this.findStr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      const count = (this.editorContent.match(regex) || []).length;
      this.editorContent = this.editorContent.replace(regex, this.replaceStr);
      this.activeTab.content = this.editorContent;
      this.activeTab.modified = true;
      toast('Replaced ' + count + ' occurrence(s)', 'success');
    },

    // ── File operations ──────────────────────────────────────────────────────
    async deleteItem(f) {
      if (!confirm('Delete "' + f.name + '"?')) return;
      const r = await post('/api/files/delete', { path: f.path });
      if (r.ok) { toast('Deleted', 'success'); await this.loadDir(this.path); }
      else toast(r.error || 'Failed', 'error');
    },

    async deleteSelected() {
      if (!this.selected.length) return;
      if (!confirm('Delete ' + this.selected.length + ' selected items?')) return;
      for (const p of this.selected) {
        await post('/api/files/delete', { path: p });
      }
      toast('Deleted ' + this.selected.length + ' items', 'success');
      this.selected = [];
      await this.loadDir(this.path);
    },

    startRename(f) { this.renameTarget = f; this.renameValue = f.name; this.showRenameModal = true; },

    async doRename() {
      if (!this.renameTarget || !this.renameValue) return;
      const dir = this.renameTarget.path.split('/').slice(0, -1).join('/');
      const dst = dir + '/' + this.renameValue;
      const r = await post('/api/files/rename', { src: this.renameTarget.path, dst });
      if (r.ok) { toast('Renamed', 'success'); this.showRenameModal = false; await this.loadDir(this.path); }
      else toast(r.error || 'Failed', 'error');
    },

    copyItem(f) { this.clipboard = [f.path]; this.clipboardOp = 'copy'; toast('Copied to clipboard', 'info'); },
    cutItem(f)  { this.clipboard = [f.path]; this.clipboardOp = 'cut';  toast('Cut to clipboard', 'info');  },
    copySelected() { this.clipboard = [...this.selected]; this.clipboardOp = 'copy'; toast(this.selected.length + ' items copied', 'info'); },
    cutSelected()  { this.clipboard = [...this.selected]; this.clipboardOp = 'cut';  toast(this.selected.length + ' items cut', 'info');   },

    async pasteHere() {
      if (!this.clipboard) return;
      for (const src of this.clipboard) {
        const name = src.split('/').pop();
        const dst  = this.path + '/' + name;
        if (this.clipboardOp === 'copy') await post('/api/files/copy', { src, dst });
        else                             await post('/api/files/move', { src, dst });
      }
      toast('Pasted ' + this.clipboard.length + ' item(s)', 'success');
      if (this.clipboardOp === 'cut') this.clipboard = null;
      await this.loadDir(this.path);
    },

    copyPath(f) {
      navigator.clipboard.writeText(f.path).then(() => toast('Path copied', 'success'));
    },

    async compressItem(f) {
      const name = f.name + '.zip';
      const out  = this.path + '/' + name;
      const r    = await post('/api/files/compress', { paths: [f.path], output: out, format: 'zip' });
      if (r.ok) { toast('Compressed: ' + name, 'success'); await this.loadDir(this.path); }
      else toast(r.error || 'Failed', 'error');
    },

    async compressSelected() {
      if (!this.selected.length) return;
      const name = 'archive_' + Date.now() + '.zip';
      const out  = this.path + '/' + name;
      const r    = await post('/api/files/compress', { paths: this.selected, output: out, format: 'zip' });
      if (r.ok) { toast('Archive created: ' + name, 'success'); this.selected = []; await this.loadDir(this.path); }
      else toast(r.error || 'Failed', 'error');
    },

    async extractItem(f) {
      const r = await post('/api/files/extract', { path: f.path, dest: this.path });
      if (r.ok) { toast('Extracted', 'success'); await this.loadDir(this.path); }
      else toast(r.error || 'Failed', 'error');
    },

    openNewFile()   { this.newFileIsFolder = false; this.newFileName = ''; this.showNewMenu = false; this.showNewFileModal = true; this.$nextTick(() => this.$refs.newFileInput?.focus()); },
    openNewFolder() { this.newFileIsFolder = true;  this.newFileName = ''; this.showNewMenu = false; this.showNewFileModal = true; this.$nextTick(() => this.$refs.newFileInput?.focus()); },

    async createNew() {
      if (!this.newFileName) return;
      const p = this.path + '/' + this.newFileName;
      if (this.newFileIsFolder) {
        const r = await post('/api/files/mkdir', { path: p });
        if (r.ok) { toast('Folder created', 'success'); this.showNewFileModal = false; await this.loadDir(this.path); }
      } else {
        const r = await post('/api/files/write', { path: p, content: '' });
        if (r.ok) {
          toast('File created', 'success');
          this.showNewFileModal = false;
          await this.loadDir(this.path);
          // Open in editor
          await this.openEditor({ path: p, name: this.newFileName, type: 'file' });
        }
      }
    },

    async showProps(f) {
      const r = await get('/api/files/properties?path=' + encodeURIComponent(f.path));
      if (r.ok) { this.props = r.props; this.showPropsModal = true; }
    },

    chmodItem(f) { this.chmodTarget = f; this.chmodValue = f.perms || '755'; this.showChmodModal = true; },

    async doChmod() {
      if (!this.chmodTarget) return;
      const r = await post('/api/files/chmod', { path: this.chmodTarget.path, mode: this.chmodValue });
      if (r.ok) { toast('Permissions set to ' + this.chmodValue, 'success'); this.showChmodModal = false; await this.loadDir(this.path); }
      else toast(r.error || 'Failed', 'error');
    },

    async calcSize(f) {
      f.calcSize = '...';
      const r = await get('/api/files/size?path=' + encodeURIComponent(f.path));
      f.calcSize = r.ok ? fmtBytes(r.size) : '?';
    },

    async doSearch() {
      if (!this.searchQuery) return;
      this.searching = true; this.searchResults = [];
      const r = await get('/api/files/search?path=' + encodeURIComponent(this.path) +
                          '&q=' + encodeURIComponent(this.searchQuery) +
                          '&content=' + (this.searchInContent ? 'true' : 'false'));
      this.searching = false;
      if (r.ok) this.searchResults = r.results;
      if (!r.results?.length) toast('No files found', 'info');
    },

    // ── Upload ────────────────────────────────────────────────────────────────
    handleFileUpload(e) {
      this.uploadQueue = [...e.target.files].map(f => ({ name: f.name, size: f.size, file: f, status: '' }));
    },

    handleDropUpload(e) {
      this.uploadQueue = [...e.dataTransfer.files].map(f => ({ name: f.name, size: f.size, file: f, status: '' }));
    },

    async doUpload() {
      this.uploading = true;
      for (const item of this.uploadQueue) {
        const fd = new FormData();
        fd.append('file', item.file);
        fd.append('path', this.path);
        item.status = 'uploading...';
        try {
          const r = await fetch('/api/files/upload', { method: 'POST', body: fd });
          const j = await r.json();
          item.status = j.ok ? 'done' : 'error';
        } catch { item.status = 'error'; }
      }
      this.uploading = false;
      const done = this.uploadQueue.filter(i => i.status === 'done').length;
      toast('Uploaded ' + done + '/' + this.uploadQueue.length + ' files', 'success');
      await this.loadDir(this.path);
    },

    async doRemoteDownload() {
      if (!this.remoteUrl) { toast('Enter a URL', 'error'); return; }
      const r = await post('/api/files/remote-download', { url: this.remoteUrl, dest: this.remoteDest || this.path });
      if (r.ok) { toast('Download started: ' + r.filename, 'success'); this.showRemoteDl = false; }
      else toast(r.error || 'Failed', 'error');
    },

    // ── Context menu ──────────────────────────────────────────────────────────
    openCtx(e, f) {
      this.ctxTarget = f;
      this.ctxMenu = { show: true, x: Math.min(e.clientX, window.innerWidth - 200), y: Math.min(e.clientY, window.innerHeight - 300) };
    },
    ctxOpen()     { if (!this.ctxTarget) return; this.ctxTarget.type === 'dir' ? this.loadDir(this.ctxTarget.path) : this.openEditor(this.ctxTarget); this.ctxMenu.show = false; },
    ctxEdit()     { if (this.ctxTarget) this.openEditor(this.ctxTarget); this.ctxMenu.show = false; },
    ctxCopy()     { if (this.ctxTarget) this.copyItem(this.ctxTarget); this.ctxMenu.show = false; },
    ctxCut()      { if (this.ctxTarget) this.cutItem(this.ctxTarget); this.ctxMenu.show = false; },
    ctxRename()   { if (this.ctxTarget) this.startRename(this.ctxTarget); this.ctxMenu.show = false; },
    ctxCompress() { if (this.ctxTarget) this.compressItem(this.ctxTarget); this.ctxMenu.show = false; },
    ctxExtract()  { if (this.ctxTarget) this.extractItem(this.ctxTarget); this.ctxMenu.show = false; },
    ctxChmod()    { if (this.ctxTarget) this.chmodItem(this.ctxTarget); this.ctxMenu.show = false; },
    ctxProps()    { if (this.ctxTarget) this.showProps(this.ctxTarget); this.ctxMenu.show = false; },
    ctxDelete()   { if (this.ctxTarget) this.deleteItem(this.ctxTarget); this.ctxMenu.show = false; },

    fmtSize: fmtBytes, fmtDate,
  };
}

// ── NEONCODEX AI ASSISTANT ────────────────────────────────────────────────────
function aiAssistant() {
  return {
    open:        false,
    configured:  false,
    modelName:   'NeonCodex',
    messages:    [],   // [{role:'user'|'assistant', content}]
    input:       '',
    thinking:    false,
    unread:      0,
    inputFocus:  false,
    activeContexts: [],

    quickActions: [
      { icon:'🔍', label:'Diagnose server',    action:'diagnose',     prompt:'Check my server health and identify any issues. Give me a quick overview.' },
      { icon:'🔐', label:'Security tips',      action:'security',     prompt:'Give me the top 5 server hardening tips for a VPS running Nginx + PHP.' },
      { icon:'⚙',  label:'Nginx config',       action:'nginx',        prompt:'Generate a production Nginx server block for a PHP WordPress site with SSL, gzip, and security headers.' },
      { icon:'🐘', label:'PHP optimize',       action:'php',          prompt:'What are the optimal php.ini settings for a production WordPress site with 2GB RAM?' },
      { icon:'🗄',  label:'MySQL tune',         action:'mysql',        prompt:'Give me MySQL/MariaDB performance tuning settings for a server with 4GB RAM.' },
      { icon:'📋', label:'Cron examples',      action:'cron',         prompt:'Show me common cron job examples for a web server: SSL renewal, backup, log rotation, WordPress cron.' },
    ],

    contextOptions: [
      { id:'server',   icon:'🖥', label:'Server Info' },
      { id:'nginx',    icon:'🌐', label:'Nginx Logs' },
      { id:'php',      icon:'🐘', label:'PHP Errors' },
      { id:'mysql',    icon:'🗄', label:'MySQL Status' },
    ],

    async init() {
      // Listen for sidebar button toggle
      document.addEventListener('vortex-toggle-ai', () => {
        this.open = !this.open;
        if (this.open) { this.unread = 0; this.$nextTick(() => this.$refs.chatInput?.focus()); }
      });
      const r = await get('/api/ai/config').catch(()=>({ok:false}));
      if (r.ok) {
        this.configured = r.config.enabled && !!r.config.api_key && r.config.api_key !== '***';
        this.modelName  = r.config.model || 'NeonCodex';
      }
    },

    toggleContext(id) {
      if (this.activeContexts.includes(id)) {
        this.activeContexts = this.activeContexts.filter(c => c !== id);
      } else {
        this.activeContexts.push(id);
      }
    },

    async gatherContext() {
      let ctx = '';
      if (this.activeContexts.includes('server')) {
        try {
          const r = await get('/api/dashboard/stats');
          if (r.ok) ctx += `Server Stats: CPU ${r.cpu}%, RAM ${r.ram}, Disk ${r.disk}\n`;
        } catch {}
      }
      if (this.activeContexts.includes('nginx')) {
        try {
          const r = await fetch('/api/terminal/exec', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:'tail -50 /var/log/nginx/error.log 2>/dev/null || echo "No nginx error log"',cwd:'/'})});
          const d = await r.json();
          if (d.ok) ctx += `\nNginx Error Log (last 50 lines):\n${d.output}\n`;
        } catch {}
      }
      if (this.activeContexts.includes('php')) {
        try {
          const r = await fetch('/api/terminal/exec', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:'find /var/log -name "php*error*" 2>/dev/null | head -1 | xargs tail -30 2>/dev/null || echo "No PHP error log found"',cwd:'/'})});
          const d = await r.json();
          if (d.ok) ctx += `\nPHP Error Log:\n${d.output}\n`;
        } catch {}
      }
      return ctx;
    },

    async send() {
      const text = this.input.trim();
      if (!text || this.thinking) return;
      if (!this.configured) {
        toast('Set your NeonCodex API key in Settings → AI Assistant first', 'error');
        return;
      }
      this.input = '';
      this.$nextTick(() => { if (this.$refs.chatInput) this.$refs.chatInput.style.height = 'auto'; });
      this.messages.push({ role: 'user', content: text });
      await this._doChat();
    },

    async sendQuick(q) {
      if (!this.configured) {
        toast('Set your NeonCodex API key in Settings first', 'error');
        return;
      }
      this.messages.push({ role: 'user', content: q.label });
      this.input = '';
      // Use the full prompt internally
      const actualMsg = this.messages[this.messages.length - 1];
      actualMsg._fullPrompt = q.prompt;
      await this._doChat(q.prompt);
    },

    async _doChat(overridePrompt) {
      this.thinking = true;
      this.$nextTick(() => {
        const box = this.$refs.chatBox;
        if (box) box.scrollTop = box.scrollHeight;
      });

      // Build messages array for API
      const apiMessages = this.messages.slice(-20).map((m, i) => {
        // If last user message has override prompt, use it
        if (overridePrompt && i === this.messages.length - 1 && m.role === 'user') {
          return { role: 'user', content: overridePrompt };
        }
        return { role: m.role, content: m.content };
      });

      const context = await this.gatherContext();
      try {
        const r = await post('/api/ai/chat', { messages: apiMessages, context });
        this.thinking = false;
        if (r.ok) {
          this.messages.push({ role: 'assistant', content: r.content });
          if (!this.open) this.unread++;
        } else {
          this.messages.push({ role: 'assistant', content: '⚠ Error: ' + (r.error || 'Failed to get response.') });
        }
      } catch (e) {
        this.thinking = false;
        this.messages.push({ role: 'assistant', content: '⚠ Network error: ' + e.message });
      }

      this.$nextTick(() => {
        const box = this.$refs.chatBox;
        if (box) box.scrollTop = box.scrollHeight;
        if (this.open) { this.unread = 0; }
        else { this.unread++; }
      });
    },

    clearChat() {
      if (this.messages.length && !confirm('Clear conversation?')) return;
      this.messages = [];
      this.unread = 0;
    },

    // Format assistant messages with basic markdown
    formatMsg(content) {
      if (!content) return '';
      return content
        // Code blocks
        .replace(/```(\w+)?\n?([\s\S]*?)```/g, (_, lang, code) =>
          `<pre style="background:#0f1117;border:1px solid #2a2b3a;border-radius:6px;padding:10px;font-family:monospace;font-size:12px;overflow-x:auto;margin:6px 0;white-space:pre-wrap;color:#e2e8f0">${code.trim().replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>`)
        // Inline code
        .replace(/`([^`]+)`/g, '<code style="background:rgba(88,101,242,.15);border:1px solid rgba(88,101,242,.3);border-radius:3px;padding:1px 5px;font-family:monospace;font-size:11px;color:#7c8af7">$1</code>')
        // Bold
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        // Bullet points
        .replace(/^[•\-\*]\s(.+)$/gm, '<div style="padding-left:12px;margin:2px 0">• $1</div>')
        // Numbered lists
        .replace(/^\d+\.\s(.+)$/gm, '<div style="padding-left:12px;margin:2px 0">$1</div>')
        // Line breaks
        .replace(/\n\n/g, '<br><br>')
        .replace(/\n/g, '<br>');
    },

    // Expose sendToAI for use from other pages (file editor, etc.)
    async askAboutCode(code, instruction) {
      this.open = true;
      const prompt = (instruction || 'Review this code and explain any issues:') + '\n\n```\n' + code + '\n```';
      this.messages.push({ role: 'user', content: instruction || 'Review this code' });
      await this._doChat(prompt);
    },
  };
}

// ── PHP ───────────────────────────────────────────────────────────────────────
function phpPage() {
  return {
    versions:[], selVer:'',
    // selTab drives the right panel; also keep 'tab' as alias for HTML compatibility
    selTab:'extensions', config:{}, fpmProfile:{}, logContent:'', phpinfo:'',
    extensions:[],
    iniModal:{show:false, version:'', content:''},

    get tab() { return this.selTab; },
    set tab(v) { this.selTab = v; },

    async init() {
      const r = await get('/api/php/versions');
      if (r.ok && r.versions?.length) {
        this.versions = r.versions;
        this.selVer   = r.versions[0].version;
        await this.loadTab();
      }
    },

    async selectVer(v) { this.selVer = v; await this.loadTab(); },

    async loadTab() {
      if      (this.selTab==='extensions')  await this.loadExts();
      else if (this.selTab==='config')      await this.loadConfig();
      else if (this.selTab==='fpm')         await this.loadFpm();
      else if (this.selTab==='logs')        await this.loadLogs();
      else if (this.selTab==='phpinfo')     await this.loadPhpinfo();
    },

    async loadExts() {
      const r = await get(`/api/php/${this.selVer}/extensions`);
      if (r.ok) this.extensions = r.extensions.map(e=>({...e,loading:false}));
    },

    async installExt(e) {
      e.loading = true;
      const r = await post(`/api/php/${this.selVer}/extensions/${e.name}/install`);
      e.loading = false;
      if (r.ok) { e.installed = true; toast(e.name+' installed','success'); }
      else toast(r.error||'Failed','error');
    },

    async uninstallExt(e) {
      if (!confirm('Uninstall '+e.name+'?')) return;
      const r = await post(`/api/php/${this.selVer}/extensions/${e.name}/uninstall`);
      if (r.ok) { e.installed = false; toast(e.name+' removed','success'); }
      else toast(r.error||'Failed','error');
    },

    async loadConfig() {
      const r = await get(`/api/php/${this.selVer}/ini`);
      if (r.ok) this.config = r.config || r.ini || {};
    },

    async saveConfig() {
      const r = await post(`/api/php/${this.selVer}/ini`, {config: this.config});
      if (r.ok) { toast('Saved & FPM reloaded','success'); }
      else toast(r.error||'Failed','error');
    },

    async loadFpm() {
      const r = await get(`/api/php/${this.selVer}/fpm`);
      if (r.ok) {
        this.fpmProfile = r.profile || {};
        // Update the version status
        const v = this.versions.find(v=>v.version===this.selVer);
        if (v && r.status) v.status = r.status;
      }
    },

    // Called from HTML button: fpmAction('start') etc
    async fpmAction(action) {
      const r = await post(`/api/php/${this.selVer}/fpm`, {action});
      if (!r.ok) {
        toast(r.error || `Failed to ${action} PHP ${this.selVer}-FPM`, 'error');
        return;
      }
      // Update version status immediately from backend response
      const v = this.versions.find(v => v.version === this.selVer);
      if (v && r.status) v.status = r.status;

      if (r.success) {
        const statusLabel = r.status === 'active' ? 'running' : r.status;
        toast(`PHP ${this.selVer}-FPM ${action}ed — ${statusLabel}`, 'success');
      } else {
        // Action ran but service still not in expected state
        const errMsg = r.output
          ? `${action} ran but PHP-FPM is ${r.status}. ${r.output}`
          : `PHP-FPM is ${r.status} after ${action}. Check if the service exists.`;
        toast(errMsg, 'error');
        // Still refresh to get accurate state
        const vr = await get('/api/php/versions');
        if (vr.ok) this.versions = vr.versions;
      }
    },

    async loadLogs() {
      const r = await get(`/api/php/${this.selVer}/logs`);
      if (r.ok) this.logContent = r.logs || r.content || '';
    },

    async loadPhpinfo() {
      const r = await get(`/api/php/${this.selVer}/phpinfo`);
      if (r.ok) this.phpinfo = r.output || '';
    },

    // Opens the raw php.ini editor modal
    async openIni() {
      const r = await get(`/api/php/${this.selVer}/ini/raw`);
      if (r.ok) {
        this.iniModal = {show:true, version:this.selVer, content: r.content||''};
      } else {
        // fallback: stringify config object
        const entries = Object.entries(this.config).map(([k,v])=>k+' = '+v).join('\n');
        this.iniModal = {show:true, version:this.selVer, content: entries};
      }
    },

    async saveIni() {
      const r = await post(`/api/php/${this.selVer}/ini/raw`, {content: this.iniModal.content});
      if (r.ok) { toast('php.ini saved & FPM reloaded','success'); this.iniModal.show=false; }
      else toast(r.error||'Failed','error');
    },
  };
}

// ── SERVICES ──────────────────────────────────────────────────────────────────
function servicesPage() {
  return {
    services: [],

    async init() { await this.load(); },

    async load() {
      const r = await get('/api/services');
      if (r.ok) this.services = r.services || [];
    },

    async control(name, action) {
      const r = await post(`/api/services/${name}/${action}`);
      if (r.ok) { toast(`${action} ${name}`,'success'); await this.load(); }
      else toast(r.error||'Failed','error');
    },

    statusColor(s) {
      return s==='active'?'var(--green)':s==='inactive'?'var(--red)':'var(--yellow)';
    },
  };
}

// ── MODULES ───────────────────────────────────────────────────────────────────
function modulesPage() {
  return {
    modules: [], cat: '',
    verModal:  {show:false, mod:null, selVer:'', action:'install'},
    phpUninstallModal: {show:false, versions:[], selVer:''},
    jobModal:  {show:false, title:'', lines:[], done:false, success:false, action:'install', installedVer:''},

    async init() { await this.load(); },

    async load() {
      const r = await get('/api/modules');
      if (r.ok) this.modules = r.modules.map(m=>({
        ...m,
        loading:   false,
        // Normalize svcStatus: 'active (running)' → 'active'
        svcStatus: m.svcStatus ? (m.svcStatus.startsWith('active') ? 'active' : m.svcStatus) : m.svcStatus,
        // Pre-select the middle version in dropdown (best default)
        selVer:    m.versions?.length ? m.versions[Math.floor(m.versions.length/2)].value : '',
      }));
    },

    categories() { return [...new Set(this.modules.map(m=>m.category))].sort(); },
    filtered()   { return this.cat ? this.modules.filter(m=>m.category===this.cat) : this.modules; },

    async uninstall(m) {
      // For multi-version modules (PHP, Python), ask WHICH version to remove
      if (m.id==='php') {
        const r = await get('/api/php/installed');
        const installed = r.versions || [];
        if (installed.length > 0) {
          this.phpUninstallModal = {show:true, versions:installed, selVer:installed[0]};
          return;
        }
      }
      if (m.id==='python' && m.versions?.length) {
        this.verModal = {show:true, mod:m, selVer:m.versions[0].value, action:'uninstall'};
        return;
      }
      // Single-version: confirm then remove directly
      if (!confirm(`Uninstall ${m.name}? This cannot be undone.`)) return;
      await this._startJob(m, 'uninstall', '');
    },

    async install(m) {
      // PHP: always install directly with selected version (multi-version support)
      if (m.id === 'php') {
        if (!m.selVer) { toast('Select a PHP version first', 'error'); return; }
        await this._startJob(m, 'install', m.selVer);
        return;
      }
      // If user already selected a version from the inline dropdown → install directly
      // Only show the version picker modal if NO version is selected yet
      if (m.versions?.length > 1 && !m.selVer) {
        this.verModal = {show:true, mod:m, selVer:m.versions[0].value, action:'install'};
        return;
      }
      // Use selected version directly (from dropdown or single-version)
      await this._startJob(m, 'install', m.selVer||'');
    },

    async installWithVer() {
      const {mod, selVer, action} = this.verModal;
      this.verModal.show = false;
      await this._startJob(mod, action||'install', selVer);
    },

    async _startJob(m, action, ver) {
      m.loading = true;
      const r = await post(`/api/modules/${m.id}/${action}`, {version: ver});
      if (!r.ok) { m.loading=false; toast(r.error||'Failed','error'); return; }
      const label = `${action==='install'?'Installing':'Removing'}: ${m.name}${ver?' v'+ver:''}`;
      this.jobModal = {show:true, title:label, lines:[], done:false, success:false, action, installedVer:''};
      const es = new EventSource(`/api/modules/job/${r.job_id}`);
      es.onmessage = (e) => {
        const d = JSON.parse(e.data);
        if (d.line) this.jobModal.lines.push(d.line);
        if (d.done) {
          es.close(); m.loading=false; m.installed=d.installed;
          if (d.installedVer) m.installedVer=d.installedVer;
          this.jobModal.done=true; this.jobModal.success=d.success;
          this.jobModal.installedVer=d.installedVer||'';
          setTimeout(()=>this.load(), 1200);
        }
        if (d.error) { es.close(); m.loading=false; toast(d.error,'error'); }
        this.$nextTick(()=>{
          const t=document.querySelector('.job-terminal');
          if(t) t.scrollTop=t.scrollHeight;
        });
      };
      es.onerror = () => { es.close(); m.loading=false; };
    },

    async control(m, action) {
      const r = await post(`/api/modules/${m.id}/control`, {action});
      if (r.ok) { m.svcStatus=r.status; toast(`${action} ${m.name}`,'success'); }
    },

    // ── App Settings Modal ────────────────────────────────────────────────────
    settingsModal: {
      show: false, mod: null, tab: 'service',
      loading: false, saving: false,
      status: '', version: '', confPath: '', confContent: '',
      logs: '', logPath: '',
      optimization: {},
      port: '', maxConnections: '',
      phpVersions: [], currentPhp: '',
      pmaUrl: '',
      dockerInfo: '',
      confChanged: false,
    },

    async openSettings(m) {
      // For pages that have dedicated full pages, navigate there

      // For all other apps — show the settings modal
      this.settingsModal = {
        ...this.settingsModal,
        show: true, mod: m, tab: 'service',
        loading: true, confContent: '', logs: '', status: '',
      };
      const r = await get('/api/modules/'+m.id+'/settings');
      this.settingsModal.loading = false;
      if (r.ok) {
        this.settingsModal.status         = r.status  || '';
        this.settingsModal.version        = r.version || '';
        this.settingsModal.confPath       = r.conf_path || '';
        this.settingsModal.confContent    = r.conf_content || '';
        this.settingsModal.logs           = r.logs    || '';
        this.settingsModal.logPath        = r.log_path || '';
        this.settingsModal.optimization   = r.optimization || {};
        this.settingsModal.port           = r.port    || '';
        this.settingsModal.maxConnections = r.max_connections || '';
        this.settingsModal.phpVersions    = r.php_versions || [];
        this.settingsModal.currentPhp     = r.current_php  || '';
        this.settingsModal.pmaUrl         = r.url          || '';
        this.settingsModal.dockerInfo     = r.info         || '';
        this.settingsModal.versions       = r.versions       || [];
        this.settingsModal.switchVer      = r.versions?.[0]?.value || '';
        this.settingsModal.currentStatus  = r.current_status || {};
        this.settingsModal.slowLog        = r.slow_log       || '';
        this.settingsModal.persistence    = r.persistence    || {};
        this.settingsModal.phpConfig      = r.config         || {};
        this.settingsModal.fpmProfile     = r.fpm_profile    || {};
        this.settingsModal.extensions     = r.extensions     || [];
        this.settingsModal.iniContent     = r.ini_content    || '';
        this.settingsModal.iniPath        = r.ini_path       || '';
        this.settingsModal.fpmConf        = r.fpm_conf       || '';
        this.settingsModal.fpmContent     = r.fpm_content    || '';
        this.settingsModal.selPhpVer      = r.sel_ver        || '';
        this.settingsModal.phpinfo        = r.phpinfo        || {};
        this.settingsModal.ftpUsers       = r.users          || [];
        this.settingsModal.ftpAddr        = r.ftp_addr       || '';
        this.settingsModal.jails          = r.jails          || [];
        this.settingsModal.blackIps       = r.black_ips      || '';
        this.settingsModal.whiteIps       = r.white_ips      || '';
        this.settingsModal.confChanged    = false;
        this.settingsModal.caddyOpts      = r.global_opts     || {};
        this.settingsModal.caddyCerts     = r.tls_certs       || '';
        this.settingsModal.phpServiceName  = m.id==='php' ? 'php'+(r.sel_ver||'')+ '-fpm' : '';
      } else {
        toast(r.error || 'Failed to load settings', 'error');
      }
    },

    async settingsControl(action) {
      const m = this.settingsModal.mod;
      if (!m) return;
      const r = await post('/api/modules/'+m.id+'/control', {action});
      if (r.ok) {
        this.settingsModal.status = r.status || '';
        // Also update the modules list status
        const mod = this.modules.find(x => x.id === m.id);
        if (mod) mod.svcStatus = r.status || '';
        toast(action+' '+m.name, 'success');
      } else toast(r.error||'Failed','error');
    },

    async settingsSaveConfig() {
      const sm = this.settingsModal;
      if (!sm.confPath || !sm.confContent) return;
      sm.saving = true;
      const r = await post('/api/modules/'+sm.mod.id+'/settings', {
        action: 'save_config',
        conf_path: sm.confPath,
        content: sm.confContent,
      });
      sm.saving = false;
      if (r.ok) { sm.confChanged=false; toast('Saved & reloaded','success'); }
      else toast(r.error||'Save failed','error');
    },

    async settingsSaveOptimization() {
      const sm = this.settingsModal;
      sm.saving = true;
      const r = await post('/api/modules/'+sm.mod.id+'/settings', {
        action: 'save_optimization',
        optimization: sm.optimization,
      });
      sm.saving = false;
      toast(r.ok?'Optimization saved':'Failed: '+(r.error||''), r.ok?'success':'error');
    },

    async settingsPmaSetPort() {
      const sm = this.settingsModal;
      const r = await post('/api/modules/phpmyadmin/settings', {
        action: 'pma_set_port', port: sm.port,
      });
      toast(r.ok?'Port updated. Access: http://YOUR-IP:'+sm.port:'Failed: '+(r.error||''), r.ok?'success':'error');
    },

    async settingsPmaSetPhp() {
      const sm = this.settingsModal;
      const r = await post('/api/modules/phpmyadmin/settings', {
        action: 'pma_set_php', php_version: sm.currentPhp,
      });
      toast(r.ok?'PHP version updated':'Failed: '+(r.error||''), r.ok?'success':'error');
    },

    settingsTabs(modId) {
      const tabs = {
        nginx:      ['service','config','optimization','switch_version','logs'],
        caddy:      ['service','caddyfile','global_opts','auto_https','logs'],
        nodejs:     ['service','info'],
        apache2:    ['service','config','optimization','logs'],
        openlitespeed:['service','config','optimization','switch_version','logs'],
        mysql:      ['service','config','storage','port','current_status','optimization','logs','slow_log'],
        mariadb:    ['service','config','port','optimization','logs','slow_log'],
        postgresql: ['service','config','logs'],
        mongodb:    ['service','config','logs'],
        redis:      ['service','switch_version','optimization','config','current_status','persistence','logs'],
        php:        ['service','extensions','config','ini','fpm','upload_limit','timeout_limit','disabled_functions','load_average','session_config','slow_log','logs','phpinfo'],
        'pure-ftpd':['service','switch_version','users','port','config','logs'],
        fail2ban:   ['service','website_protection','server_protection','black_ip','white_ip','logs'],
        supervisor: ['service','config','logs'],
        clamav:     ['service','logs'],
        phpmyadmin: ['service','php_version','security'],
        docker:     ['service','info'],
      };
      const labels = {
        service:'Service', config:'Config File', optimization:'Optimization',
        logs:'Error Log', php_version:'PHP Version', security:'Security',
        info:'Info', storage:'Storage Location', port:'Port',
        current_status:'Current Status', slow_log:'Slow Log',
        switch_version:'Switch Version', persistence:'Set Persistence',
        extensions:'Install Extensions', ini:'Configuration File',
        fpm:'FPM Profile', phpinfo:'phpinfo',
        caddyfile:'Caddyfile', global_opts:'Global Options', auto_https:'Auto HTTPS',
        upload_limit:'Limit of Upload', timeout_limit:'Limit of Timeout',
        disabled_functions:'Disabled Functions', load_average:'Load Average',
        session_config:'Session Config', slow_log:'Slow Log',
        users:'User Management', website_protection:'Website Protection',
        server_protection:'Server Protection', black_ip:'Black IP', white_ip:'White IP',
      };
      return (tabs[modId]||['service']).map(t => ({id:t, label:labels[t]||t}));
    },
  };
}

// ── FIREWALL ──────────────────────────────────────────────────────────────────
function firewallPage() {
  return {
    rules: [], status: '', showAdd: false,
    form: {port:'', protocol:'tcp', action:'allow', comment:''},

    async init() { await this.load(); },

    async load() {
      const [rs, st] = await Promise.all([
        get('/api/firewall/rules'),
        get('/api/firewall/status'),
      ]);
      if (rs.ok) this.rules  = rs.rules  || [];
      if (st.ok) this.status = st.status || '';
    },

    async add() {
      if (!this.form.port) { toast('Port required','error'); return; }
      const r = await post('/api/firewall/rules', this.form);
      if (r.ok) { toast('Rule added','success'); this.showAdd=false; await this.load(); }
      else toast(r.error||'Failed','error');
    },

    async del(num) {
      if (!confirm('Delete this rule?')) return;
      const r = await del(`/api/firewall/rules/${num}`);
      if (r.ok) { toast('Rule removed','success'); await this.load(); }
    },

    async toggleFirewall(enable) {
      const r = await post('/api/firewall/toggle', {enable});
      if (r.ok) { toast(enable?'Firewall enabled':'Firewall disabled','success'); await this.load(); }
      else toast(r.error||'Failed','error');
    },
  };
}

// ── TERMINAL ──────────────────────────────────────────────────────────────────
function terminalPage() {
  return {
    output: [], input: '', history: [], histIdx: -1, cwd: '/',

    async init() {
      this.output = [
        {text: '╔═══════════════════════════════════╗', cls:'system'},
        {text: '║  VortexPanel Terminal  v3.0       ║', cls:'system'},
        {text: '╚═══════════════════════════════════╝', cls:'system'},
        {text: 'Type commands below. Use ↑↓ for history.', cls:'system'},
      ];
    },

    async run() {
      const cmd = this.input.trim();
      if (!cmd) return;
      this.history.unshift(cmd);
      this.histIdx = -1;
      this.output.push({text: `[${this.cwd}]$ ${cmd}`, cls:'cmd'});
      this.input = '';
      if (cmd === 'clear') { this.output = []; return; }
      const r = await post('/api/terminal/exec', {cmd, cwd: this.cwd});
      if (r.ok) {
        if (r.cwd)    this.cwd = r.cwd;
        if (r.output) this.output.push({text: r.output, cls:'out'});
        if (r.error)  this.output.push({text: r.error,  cls:'err'});
      }
      this.$nextTick(() => {
        const t = this.$refs.term;
        if (t) t.scrollTop = t.scrollHeight;
      });
    },

    keyUp()   { if (this.histIdx < this.history.length-1) { this.histIdx++; this.input=this.history[this.histIdx]; } },
    keyDown() { if (this.histIdx > 0) { this.histIdx--; this.input=this.history[this.histIdx]; } else { this.histIdx=-1; this.input=''; } },
  };
}

// ── BACKUPS ───────────────────────────────────────────────────────────────────
function backupsPage() {
  return {
    backups: [], info: {websites:[], databases:[], mysql:false, webroot:'/www/wwwroot'},
    creating: '',
    jobModal:     {show:false, title:'', lines:[], done:false, success:false, error:''},
    restoreModal: {show:false, name:'', type:'', target:'', customPath:''},
    showUpload:   false, uploadFile:null, uploadType:'website', uploadTarget:'',
    uploading:    false,

    async init() { await Promise.all([this.load(), this.loadInfo()]); },

    async load() {
      const r = await get('/api/backups');
      if (r.ok) this.backups = r.backups || [];
    },

    async loadInfo() {
      const r = await get('/api/backups/info');
      if (r.ok) this.info = r;
    },

    async createBackup(type, domain, dbName) {
      this.creating = type;
      const r = await post('/api/backups/create', {type, domain, database:dbName});
      if (!r.ok) { this.creating=''; toast(r.error||'Failed','error'); return; }
      this.jobModal = {show:true, title:`Creating ${type} backup…`, lines:[], done:false, success:false, error:''};
      const poll = async () => {
        const j = await get(`/api/backups/job/${r.job_id}`);
        if (!j.ok) { this.creating=''; return; }
        this.jobModal.lines = j.lines || [];
        if (j.done) {
          this.creating='';
          this.jobModal = {...this.jobModal, done:true, success:j.success, error:j.error||''};
          if (j.success) await this.load();
        } else setTimeout(poll, 800);
      };
      setTimeout(poll, 500);
    },

    downloadBackup(name) {
      window.location.href = `/api/backups/download/${encodeURIComponent(name)}`;
    },

    openRestore(b) {
      let type = b.name.includes('database')||b.name.endsWith('.sql.gz') ? 'database' : 'website';
      this.restoreModal = {show:true, name:b.name, type, target:'', customPath:''};
    },

    async doRestore() {
      const target = this.restoreModal.customPath || this.restoreModal.target;
      if (this.restoreModal.type==='database' && !target) { toast('Enter a database name','error'); return; }
      if (!confirm(`Restore "${this.restoreModal.name}"? This will overwrite existing data.`)) return;
      this.restoreModal.show = false;
      const r = await post('/api/backups/restore', {name:this.restoreModal.name, type:this.restoreModal.type, target});
      if (!r.ok) { toast(r.error||'Failed','error'); return; }
      this.jobModal = {show:true, title:'Restoring…', lines:[], done:false, success:false, error:''};
      const poll = async () => {
        const j = await get(`/api/backups/job/${r.job_id}`);
        if (!j.ok) return;
        this.jobModal.lines = j.lines||[];
        if (j.done) {
          this.jobModal = {...this.jobModal, done:true, success:j.success, error:j.error||''};
          if (j.success) toast('Restored!','success');
        } else setTimeout(poll, 800);
      };
      setTimeout(poll, 500);
    },

    handleDrop(e) {
      const f = e.dataTransfer.files[0];
      if (f) { this.uploadFile=f; this.uploadType=f.name.includes('.sql')?'database':'website'; }
    },

    async doUpload() {
      if (!this.uploadFile) { toast('Select a file','error'); return; }
      const fd = new FormData();
      fd.append('file', this.uploadFile);
      fd.append('type', this.uploadType);
      fd.append('target', this.uploadTarget);
      this.uploading = true;
      try {
        const resp = await fetch('/api/backups/upload', {method:'POST', body:fd});
        const r = await resp.json();
        if (r.ok) { toast('Upload started!','success'); this.showUpload=false; }
        else toast(r.error||'Failed','error');
      } catch(e) { toast('Upload failed: '+e.message,'error'); }
      this.uploading = false;
    },

    async del(name) {
      if (!confirm(`Delete backup "${name}"?`)) return;
      const r = await del(`/api/backups/${name}`);
      if (r.ok) { toast('Deleted','success'); await this.load(); }
    },

    fmtSize: fmtBytes, fmtDate,
  };
}

// ── DNS ───────────────────────────────────────────────────────────────────────
function dnsPage() {
  return {
    zones: [], selZone: null, records: [],
    showAddZone: false, showAddRecord: false,
    zoneForm:  {domain:'', ip:''},
    recForm:   {type:'A', name:'', value:'', ttl:'3600'},

    async init() { await this.loadZones(); },

    async loadZones() {
      const r = await get('/api/dns/zones');
      if (r.ok) this.zones = r.zones || [];
    },

    async addZone() {
      const r = await post('/api/dns/zones', this.zoneForm);
      if (r.ok) { toast('Zone created','success'); this.showAddZone=false; await this.loadZones(); }
      else toast(r.error||'Failed','error');
    },

    async delZone(z) {
      if (!confirm(`Delete zone ${z.name}?`)) return;
      const r = await del(`/api/dns/zones/${z.name}`);
      if (r.ok) { toast('Deleted','success'); this.selZone=null; await this.loadZones(); }
    },

    async selectZone(z) {
      this.selZone = z;
      const r = await get(`/api/dns/zones/${z.name}/records`);
      if (r.ok) this.records = r.records || [];
    },

    async addRecord() {
      const r = await post(`/api/dns/zones/${this.selZone.name}/records`, this.recForm);
      if (r.ok) { toast('Record added','success'); this.showAddRecord=false; await this.selectZone(this.selZone); }
      else toast(r.error||'Failed','error');
    },

    async delRecord(rec) {
      const r = await del(`/api/dns/zones/${this.selZone.name}/records/${rec.id}`);
      if (r.ok) { toast('Deleted','success'); await this.selectZone(this.selZone); }
    },
  };
}

// ── MAIL ──────────────────────────────────────────────────────────────────────
function mailPage() {
  return {
    status: {postfix:'', dovecot:''},
    domains: [], accounts: [],
    selDomain: '', showAddDomain: false, showAddAccount: false,
    domainForm:  {domain:''},
    accountForm: {user:'', pass:''},

    async init() { await this.loadStatus(); await this.loadDomains(); },

    async loadStatus() {
      const r = await get('/api/mail/status');
      if (r.ok) this.status = r;
    },

    async loadDomains() {
      const r = await get('/api/mail/domains');
      if (r.ok) this.domains = r.domains || [];
    },

    async addDomain() {
      const r = await post('/api/mail/domains', this.domainForm);
      if (r.ok) { toast('Domain added','success'); this.showAddDomain=false; await this.loadDomains(); }
      else toast(r.error||'Failed','error');
    },

    async loadAccounts(domain) {
      this.selDomain = domain;
      const r = await get(`/api/mail/accounts?domain=${domain}`);
      if (r.ok) this.accounts = r.accounts || [];
    },

    async addAccount() {
      const r = await post('/api/mail/accounts', {...this.accountForm, domain:this.selDomain});
      if (r.ok) { toast('Account created','success'); this.showAddAccount=false; await this.loadAccounts(this.selDomain); }
      else toast(r.error||'Failed','error');
    },

    async delAccount(email) {
      if (!confirm(`Delete ${email}?`)) return;
      const r = await del(`/api/mail/accounts/${email}`);
      if (r.ok) { toast('Deleted','success'); await this.loadAccounts(this.selDomain); }
    },

    async control(svc, action) {
      const r = await post('/api/mail/control', {service:svc, action});
      if (r.ok) { toast(`${action} ${svc}`,'success'); await this.loadStatus(); }
      else toast(r.error||'Failed','error');
    },
  };
}

// ── FTP ───────────────────────────────────────────────────────────────────────
function ftpPage() {
  return {
    accounts: [], ftpStatus: {installed:false, daemon:'', status:'', accounts_count:0},
    showAdd: false, sites: [],
    form:    {user:'', password:'', home:'', selectedDomain:''},
    pwModal: {show:false, user:'', password:''},

    async init() {
      await this.load();
      const ws = await get('/api/websites');
      if (ws.ok) this.sites = ws.sites || [];
    },

    async load() {
      const s = await get('/api/ftp/status');
      if (s.ok) this.ftpStatus = s;
      if (s.ok && s.installed) {
        const a = await get('/api/ftp/accounts');
        if (a.ok) this.accounts = a.accounts || [];
      }
    },

    onDomainChange() {
      if (this.form.selectedDomain) this.form.home = `/www/wwwroot/${this.form.selectedDomain}`;
    },

    async create() {
      if (!this.form.user)     { toast('Username required','error'); return; }
      if (!this.form.password) { toast('Password required','error'); return; }
      const r = await post('/api/ftp/accounts', {
        user:     this.form.user,
        password: this.form.password,
        home:     this.form.home || `/www/wwwroot/${this.form.user}`,
      });
      if (r.ok) { toast('FTP account created','success'); this.showAdd=false; this.form={user:'',password:'',home:'',selectedDomain:''}; await this.load(); }
      else toast(r.error||'Failed','error');
    },

    async del(user) {
      if (!confirm(`Delete FTP account "${user}"?`)) return;
      const r = await del(`/api/ftp/accounts/${user}`);
      if (r.ok) { toast('Deleted','success'); await this.load(); }
    },

    changePw(user) { this.pwModal = {show:true, user, password:''}; },

    async savePw() {
      if (this.pwModal.password.length < 6) { toast('Min 6 characters','error'); return; }
      const r = await put(`/api/ftp/accounts/${this.pwModal.user}/password`, {password:this.pwModal.password});
      if (r.ok) { toast('Password changed','success'); this.pwModal.show=false; }
      else toast(r.error||'Failed','error');
    },
  };
}

// ── SETTINGS ──────────────────────────────────────────────────────────────────
function settingsPage() {
  return {
    stab: 'general',
    panelVersion: 'v3.0.0',
    pwForm: {current:'', newpw:'', confirm:''},
    aiConfig: {enabled:true, api_key:'', base_url:'https://neoncodex.io/api/v1', model:'neoncodex-default', max_tokens:2048},
    aiModels: [], showApiKey: false,
    aiTesting: false, aiTestResult: '', aiTestOk: false,

    async init() {
      const uv = await get('/api/update/version').catch(()=>({ok:false}));
      if (uv.ok) this.panelVersion = uv.version;
    },

    async loadAiConfig() {
      const r = await get('/api/ai/config');
      if (r.ok) {
        this.aiConfig = {...this.aiConfig, ...r.config};
        if (this.aiConfig.api_key === '***') this.aiConfig.api_key = '';
      }
    },

    async saveAiConfig() {
      const r = await put('/api/ai/config', this.aiConfig);
      if (r.ok) toast('AI settings saved','success');
      else toast(r.error||'Failed','error');
    },

    async fetchModels() {
      const r = await get('/api/ai/models');
      if (r.ok && r.models.length) { this.aiModels=r.models; toast(`${r.models.length} models loaded`,'success'); }
      else toast(r.error||'Could not fetch models','error');
    },

    async testAiConnection() {
      this.aiTesting=true; this.aiTestResult='';
      await put('/api/ai/config', this.aiConfig);
      const r = await post('/api/ai/chat', {messages:[{role:'user',content:'Reply with just: "NeonCodex AI connected ✓"'}]});
      this.aiTesting=false;
      this.aiTestOk    = r.ok;
      this.aiTestResult = r.ok ? '✓ '+r.content?.substring(0,80) : '✗ '+(r.error||'Connection failed');
    },

    async changePw() {
      if (this.pwForm.newpw !== this.pwForm.confirm) { toast('Passwords do not match','error'); return; }
      if (this.pwForm.newpw.length < 6) { toast('Minimum 6 characters','error'); return; }
      const r = await post('/api/settings/password', this.pwForm);
      if (r.ok) { toast('Password changed','success'); this.pwForm={current:'',newpw:'',confirm:''}; }
      else toast(r.error||'Failed','error');
    },
  };
}

// ── MONITORING ────────────────────────────────────────────────────────────────
function monitoringPage() {
  return {
    stats: {cpu:0,ram:'',ramPct:0,disk:0,diskStr:'',uptime:'',load:''},
    processes: [],

    async init() { await this.load(); setInterval(()=>this.load(), 5000); },

    async load() {
      // Get processes
      const r = await get('/api/monitoring/processes');
      if (r.ok) this.processes = r.processes || [];

      // Get overall stats from dashboard
      const s = await get('/api/dashboard/stats');
      if (s.ok) {
        this.stats.cpu    = s.cpu || 0;
        this.stats.uptime = s.uptime || '';
        this.stats.load   = Array.isArray(s.load) ? s.load.join(' ') : (s.load||'');
        // ram comes as {used, total} — format as string
        if (s.ram && typeof s.ram === 'object') {
          const used  = s.ram.used  || 0;
          const total = s.ram.total || 1;
          this.stats.ramPct = Math.round(used/total*100);
          this.stats.ram    = fmtBytes(used) + ' / ' + fmtBytes(total);
        } else {
          this.stats.ram    = s.ram || '—';
          this.stats.ramPct = 0;
        }
        // disk comes as {used, total} — compute percentage
        if (s.disk && typeof s.disk === 'object') {
          const used  = s.disk.used  || 0;
          const total = s.disk.total || 1;
          this.stats.disk    = Math.round(used/total*100);
          this.stats.diskStr = fmtBytes(used) + ' / ' + fmtBytes(total);
        } else {
          this.stats.disk    = s.disk || 0;
          this.stats.diskStr = '';
        }
      }
    },
  };
}

// ── BANDWIDTH ─────────────────────────────────────────────────────────────────
function bandwidthPage() {
  return {
    summary: {interface:'', total_rx:0, total_tx:0, daily:[], monthly:[]},
    rt: {rx_per_sec:0, tx_per_sec:0},
    domains: [], hasVnstat: false,

    async init() {
      await this.loadSummary();
      await this.loadDomains();
      setInterval(()=>this.loadRealtime(), 3000);
    },

    async loadSummary() {
      const r = await get('/api/bandwidth/summary');
      if (r.ok) { this.summary=r; this.hasVnstat=(r.source==='vnstat'); }
    },

    async loadRealtime() {
      const r = await get('/api/bandwidth/realtime');
      if (r.ok) this.rt = r;
    },

    async loadDomains() {
      const r = await get('/api/bandwidth/domains');
      if (r.ok) this.domains = r.domains || [];
    },

    async installVnstat() {
      toast('Installing vnstat…','info');
      const r = await post('/api/bandwidth/install-vnstat');
      toast(r.ok?'vnstat installed!':'Failed', r.ok?'success':'error');
      if (r.ok) await this.loadSummary();
    },

    fmtBytes,
  };
}

// ── SECURITY ──────────────────────────────────────────────────────────────────
function securityPage() {
  return {
    tab: 'ssh', score: 0, checks: [],
    ssh: {port:'22', password_auth:'yes', root_login:'yes', pubkey_auth:'yes', max_auth_tries:'6'},
    f2bJails: [], attempts: [], portsOutput: '',
    modsec: {installed:false, enabled:false, rules:0},
    lb: {configured:false, method:'roundrobin', domain:'_', port:'80',
         servers:[{address:'127.0.0.1:8001',weight:1},{address:'127.0.0.1:8002',weight:1}]},

    async init() { await Promise.all([this.loadScore(), this.loadSSH()]); },

    async loadScore() {
      const r = await get('/api/security/score');
      if (r.ok) { this.score=r.score; this.checks=r.checks||[]; }
    },

    async loadSSH() {
      const r = await get('/api/security/ssh');
      if (r.ok) this.ssh = {...this.ssh, ...r.config};
    },

    async saveSSH() {
      const r = await put('/api/security/ssh', this.ssh);
      toast(r.ok?'SSH config saved':'Failed', r.ok?'success':'error');
      if (r.ok) await this.loadScore();
    },

    async loadFail2ban() {
      const r = await get('/api/security/fail2ban');
      if (r.ok) this.f2bJails = (r.jails||[]).map(j=>({...j,banInput:''}));
      else toast(r.error||'Fail2ban not running','error');
    },

    async unbanIP(ip, jail) {
      const r = await post('/api/security/fail2ban/unban', {ip, jail});
      if (r.ok) { toast(`Unbanned ${ip}`,'success'); await this.loadFail2ban(); }
      else toast('Failed','error');
    },

    async banIP(ip, jail) {
      if (!ip) return;
      const r = await post('/api/security/fail2ban/ban', {ip, jail});
      if (r.ok) { toast(`Banned ${ip}`,'success'); await this.loadFail2ban(); }
      else toast('Failed','error');
    },

    async loadAttempts() {
      const r = await get('/api/security/login-attempts');
      if (r.ok) this.attempts = r.attempts||[];
    },

    async loadPorts() {
      const r = await get('/api/security/ports');
      if (r.ok) this.portsOutput = r.output;
    },

    async loadModsec() {
      const r = await get('/api/security/modsecurity');
      if (r.ok) this.modsec = r;
    },

    async toggleModsec(enable) {
      const r = await post('/api/security/modsecurity/toggle', {enable});
      if (r.ok) { this.modsec.enabled=enable; toast(enable?'WAF Blocking Mode ON':'Detection Only','success'); }
      else toast(r.error||'Failed','error');
    },

    async loadLB() {
      const r = await get('/api/security/loadbalancer');
      if (r.ok && r.configured) {
        this.lb.configured=true;
        this.lb.servers=r.servers?.length?r.servers:this.lb.servers;
        this.lb.method=r.method||'roundrobin';
      }
    },

    async saveLB() {
      if (!this.lb.servers.length) { toast('Add at least one server','error'); return; }
      const r = await put('/api/security/loadbalancer', {
        servers: this.lb.servers,
        method:  this.lb.method,
        domain:  this.lb.domain||'_',
        port:    this.lb.port||'80',
      });
      if (r.ok) { toast('Load balancer configured!','success'); this.lb.configured=true; }
      else toast(r.error||'Failed','error');
    },

    async deleteLB() {
      if (!confirm('Remove load balancer config?')) return;
      const r = await del('/api/security/loadbalancer');
      if (r.ok) { toast('Removed','success'); this.lb.configured=false; }
    },
  };
}

// ── DOCKER ────────────────────────────────────────────────────────────────────
function dockerPage() {
  return {
    status: {installed:false, running:false, version:''},
    containers: [], images: [], volumes: [], networks: [],
    tab: 'catalog',
    catalogFilter: 'All', search: '',
    showRun: false, runTarget: null,
    runForm: {name:'', ports:[], envs:[], volumes:[], restart:'unless-stopped', cmd:''},
    jobModal:   {show:false, title:'', lines:[], done:false, success:false},
    logsModal:  {show:false, name:'', content:''},
    statsModal: {show:false, name:'', stats:{}},

    async init() {
      await this.loadStatus();
      if (this.status.running) await Promise.all([this.loadContainers(), this.loadImages()]);
    },

    async loadStatus()     { const r=await get('/api/docker/status');     if(r.ok) this.status=r; },
    async loadContainers() { const r=await get('/api/docker/containers'); if(r.ok) this.containers=r.containers||[]; },
    async loadImages()     { const r=await get('/api/docker/images');     if(r.ok) this.images=r.images||[]; },
    async loadVolumes()    {
      const [v,n] = await Promise.all([get('/api/docker/volumes'),get('/api/docker/networks')]);
      if(v.ok) this.volumes=v.volumes||[];
      if(n.ok) this.networks=n.networks||[];
    },

    get categories() { return ['All',...new Set(DOCKER_CATALOG.map(i=>i.cat))]; },

    get filteredCatalog() {
      return DOCKER_CATALOG.filter(img => {
        const mc = this.catalogFilter==='All' || img.cat===this.catalogFilter;
        const ms = !this.search ||
          img.name.toLowerCase().includes(this.search.toLowerCase()) ||
          img.image.toLowerCase().includes(this.search.toLowerCase());
        return mc && ms;
      });
    },

    isInstalled(img) {
      return this.images.some(i =>
        i.repository===img.image || i.repository.includes(img.image.split('/').pop())
      );
    },

    openRun(img) {
      this.runTarget = img;
      this.runForm = {
        name:    img.id+'_1',
        ports:   img.ports.map(p=>({...p})),
        envs:    img.envs.map(e=>({...e})),
        volumes: img.volumes.map(v=>({...v})),
        restart: 'unless-stopped',
        cmd:     img.cmd||'',
      };
      this.showRun = true;
    },

    async pullAndRun() {
      if (!this.runTarget) return;
      const image = `${this.runTarget.image}:${this.runTarget.tag||'latest'}`;
      this.showRun = false;
      this.jobModal = {show:true, title:'Deploying: '+this.runTarget.name, lines:[], done:false, success:false};
      const r = await post('/api/docker/run', {
        image,
        name:    this.runForm.name,
        ports:   this.runForm.ports.filter(p=>p.host&&p.container),
        envs:    this.runForm.envs.filter(e=>e.key),
        volumes: this.runForm.volumes.filter(v=>v.host&&v.container),
        restart: this.runForm.restart,
        cmd:     this.runForm.cmd||'',
      });
      if (!r.ok) { this.jobModal.lines=[r.error||'Failed']; this.jobModal.done=true; return; }
      const poll = async () => {
        const j = await get(`/api/docker/job/${r.job_id}`);
        if (!j.ok) return;
        this.jobModal.lines = j.lines||[];
        if (j.done) {
          this.jobModal.done=true; this.jobModal.success=j.success;
          if (j.success) { toast(this.runTarget.name+' deployed!','success'); await Promise.all([this.loadContainers(),this.loadImages()]); }
        } else setTimeout(poll, 600);
      };
      setTimeout(poll, 400);
    },

    async containerAction(ct, action) {
      if (action==='remove' && !confirm(`Remove container ${ct.name}?`)) return;
      const r = await post(`/api/docker/containers/${ct.id}/action`, {action});
      if (r.ok) { toast(`${action} ${ct.name}`,'success'); await this.loadContainers(); }
      else toast(r.error||'Failed','error');
    },

    async showLogs(ct) {
      const r = await get(`/api/docker/containers/${ct.id}/logs`);
      if (r.ok) this.logsModal = {show:true, name:ct.name, content:r.logs};
    },

    async showStats(ct) {
      const r = await get(`/api/docker/containers/${ct.id}/stats`);
      if (r.ok) this.statsModal = {show:true, name:ct.name, stats:r};
    },

    async removeImage(img) {
      if (!confirm(`Remove ${img.repository}:${img.tag}?`)) return;
      const r = await del(`/api/docker/images/${img.id}`);
      if (r.ok) { toast('Removed','success'); await this.loadImages(); }
      else toast(r.error||'Failed (may be in use)','error');
    },

    async prune() {
      if (!confirm('Remove stopped containers + unused images and networks?')) return;
      const r = await post('/api/docker/system/prune');
      if (r.ok) { toast('System pruned','success'); await Promise.all([this.loadContainers(),this.loadImages()]); }
    },
  };
}

// ── CRON ─────────────────────────────────────────────────────────────────────
function cronPage() {
  return {
    jobs: [], templates: [], schedulePresets: [],
    showForm: false, editTarget: null,
    schedulePreset: '0 0 * * *', scheduleHuman: 'Daily at 00:00',
    showCustom: false, selectedTemplate: null,
    form: {name:'', schedule:'0 0 * * *', command:'', type:'shell', user:'root'},
    runModal: {show:false, name:'', cmd:'', lines:[], done:false, exit:null},
    logModal: {show:false, name:'', log:'', last_run:'', last_exit:''},
    _pollTimer: null,

    typeIcon(t) {
      return {shell:'⌨',php:'🐘',python:'🐍',node:'🟢',url:'🌐',
              backup:'💾',db_backup:'🗄',certbot:'🔒',log_clear:'🧹',custom:'⚙'}[t]||'⚙';
    },

    async init() {
      const r = await get('/api/cron/presets');
      if (r.ok) { this.templates=r.templates||[]; this.schedulePresets=r.schedules||[]; }
      this.selectedTemplate = this.templates.find(t=>t.id==='shell')||null;
      await this.load();
    },

    async load() {
      const r = await get('/api/cron/jobs');
      if (r.ok) this.jobs = r.jobs||[];
    },

    openAdd() {
      this.editTarget=null;
      this.form={name:'',schedule:'0 0 * * *',command:'',type:'shell',user:'root'};
      this.schedulePreset='0 0 * * *'; this.scheduleHuman='Daily at 00:00';
      this.showCustom=false;
      this.selectedTemplate=this.templates.find(t=>t.id==='shell')||null;
      this.showForm=true;
    },

    openEdit(j) {
      this.editTarget=j;
      this.form={name:j.name, schedule:j.schedule, command:j.command, type:j.type||'shell', user:j.user||'root'};
      const match=this.schedulePresets.find(p=>p.value===j.schedule);
      this.schedulePreset=match?match.value:'custom';
      this.showCustom=!match;
      this.scheduleHuman=j.schedule_human||j.schedule;
      this.selectedTemplate=this.templates.find(t=>t.id===j.type)||this.templates[0]||null;
      this.showForm=true;
    },

    selectType(t) {
      this.form.type=t.id; this.selectedTemplate=t;
      if (t.cmd && !this.editTarget) this.form.command=t.cmd;
    },

    onPresetChange() {
      if (this.schedulePreset==='custom') { this.showCustom=true; return; }
      this.showCustom=false; this.form.schedule=this.schedulePreset;
      this.updateScheduleHuman();
    },

    updateScheduleHuman() {
      const p=this.schedulePresets.find(p=>p.value===this.form.schedule);
      if (p&&p.value!=='custom') { this.scheduleHuman=p.label; return; }
      const parts=this.form.schedule.split(' ');
      if (parts.length!==5) { this.scheduleHuman=this.form.schedule; return; }
      const [mn,hr,dom,mon,dow]=parts;
      if (mn==='*'&&hr==='*') this.scheduleHuman='Every minute';
      else if (hr==='*') this.scheduleHuman=`Every hour at :${mn.padStart(2,'0')}`;
      else if (dom==='*'&&mon==='*'&&dow==='*') this.scheduleHuman=`Daily at ${hr.padStart(2,'0')}:${mn.padStart(2,'0')}`;
      else this.scheduleHuman=this.form.schedule;
    },

    async save() {
      if (!this.form.command)                  { toast('Command required','error'); return; }
      if (this.form.schedule.split(' ').length!==5) { toast('Invalid schedule','error'); return; }
      const r = this.editTarget
        ? await put(`/api/cron/jobs/${this.editTarget.id}`, this.form)
        : await post('/api/cron/jobs', this.form);
      if (r.ok) { toast(this.editTarget?'Task updated':'Task added','success'); this.showForm=false; await this.load(); }
      else toast(r.error||'Failed','error');
    },

    async toggleJob(j, enable) {
      const r = await post(`/api/cron/jobs/${j.id}/toggle`, {enable});
      if (r.ok) { j.enabled=enable; toast(enable?'Enabled':'Disabled','success'); }
      else toast('Failed','error');
    },

    async del(j) {
      if (!confirm(`Delete task "${j.name||j.command}"?`)) return;
      const r = await del(`/api/cron/jobs/${j.id}`);
      if (r.ok) { toast('Deleted','success'); await this.load(); }
    },

    async runNow(j) {
      this.runModal = {show:true, name:j.name||'Task', cmd:j.command, lines:[], done:false, exit:null};
      const r = await post(`/api/cron/jobs/${j.id}/run`);
      if (!r.ok) { this.runModal.lines=['✗ '+(r.error||'Failed')]; this.runModal.done=true; return; }
      this._pollTimer = setInterval(async ()=>{
        const s = await get(`/api/cron/run/${r.run_id}`);
        if (!s.ok) return;
        this.runModal.lines=s.lines||[];
        this.$nextTick(()=>{ if(this.$refs.runTerminal) this.$refs.runTerminal.scrollTop=this.$refs.runTerminal.scrollHeight; });
        if (s.done) {
          clearInterval(this._pollTimer);
          this.runModal.done=true; this.runModal.exit=s.exit_code;
          await this.load();
        }
      }, 500);
    },

    async openLogs(j) {
      const r = await get(`/api/cron/jobs/${j.id}/logs`);
      if (r.ok) this.logModal={show:true, name:j.name||j.command, log:r.log, last_run:r.last_run, last_exit:r.last_exit};
    },
  };
}

// ── CADDY ─────────────────────────────────────────────────────────────────────
function caddyPage() {
  return {
    status: {installed:false, version:'', status:'inactive'},
    sites: [], webroot: '/www/wwwroot',
    showAdd: false, showCaddyfile: false,
    caddyfileContent: '', caddyfilePath: '/etc/caddy/Caddyfile',
    logContent: '',
    form: {domain:'', path:'', type:'static', php:'8.3', proxy_target:''},
    drawerShow: false, drawerSite: null, drawerConf: '',

    async init() { await Promise.all([this.loadStatus(), this.loadSites()]); },

    async loadStatus() {
      const r = await get('/api/caddy/status');
      if (r.ok) this.status=r;
    },

    async loadSites() {
      const r = await get('/api/caddy/sites');
      if (r.ok) { this.sites=r.sites||[]; this.webroot=r.webroot||'/www/wwwroot'; }
    },

    async create() {
      if (!this.form.domain) { toast('Domain required','error'); return; }
      const r = await post('/api/caddy/sites', this.form);
      if (r.ok) {
        toast('Site created!'+(r.note?' '+r.note:''),'success');
        this.showAdd=false;
        this.form={domain:'',path:'',type:'static',php:'8.3',proxy_target:''};
        await this.loadSites();
      } else toast(r.error||'Failed','error');
    },

    async del(domain) {
      if (!confirm(`Delete site ${domain}?`)) return;
      const r = await del(`/api/caddy/sites/${domain}`);
      if (r.ok) { toast('Deleted','success'); await this.loadSites(); }
    },

    async openDrawer(s) {
      this.drawerSite=s; this.drawerShow=true;
      const r = await get(`/api/caddy/sites/${s.domain}/config`);
      if (r.ok) this.drawerConf=r.content;
    },

    async saveDrawerConf() {
      const r = await put(`/api/caddy/sites/${this.drawerSite.domain}/config`, {content:this.drawerConf});
      toast(r.ok?'Saved & reloaded':('Error: '+(r.error||'')), r.ok?'success':'error');
    },

    async openCaddyfile() {
      const r = await get('/api/caddy/caddyfile');
      if (r.ok) { this.caddyfileContent=r.content; this.caddyfilePath=r.path; this.showCaddyfile=true; }
    },

    async saveCaddyfile() {
      const r = await put('/api/caddy/caddyfile', {content:this.caddyfileContent});
      if (r.ok) { toast('Saved & Caddy reloaded','success'); this.showCaddyfile=false; await this.loadSites(); }
      else toast('Error: '+(r.error||''),'error');
    },

    async control(action) {
      const r = await post('/api/caddy/control', {action});
      if (r.ok) { this.status.status=r.status; toast(`${action} Caddy`,'success'); }
    },

    async loadLogs() {
      const r = await get('/api/caddy/logs?lines=150');
      if (r.ok) this.logContent=r.logs;
    },
  };
}

// ── CDN ───────────────────────────────────────────────────────────────────────
function cdnPage() {
  return {
    providers: [], activeCdn: '',
    selectedProvider: null, view: 'grid',
    form: {}, showPw: {},
    testing: false, testResult: null, saving: false,
    cf:     {zones:[], selZone:'', settings:{}, dns:[], analytics:{}, purgeUrl:'', loading:false},
    bunny:  {zones:[], selZone:'', stats:{}, purgeUrl:'', loading:false},
    generic:{testUrl:'', domain:'', applyResult:''},
    sites:  [],

    async init() {
      await this.load();
      const ws = await get('/api/websites');
      if (ws.ok) this.sites=ws.sites||[];
    },

    async load() {
      const r = await get('/api/cdn/providers');
      if (r.ok) { this.providers=r.providers||[]; this.activeCdn=r.active||''; }
    },

    selectProvider(p) {
      this.selectedProvider=p; this.form={}; this.showPw={}; this.testResult=null; this.view='settings';
    },

    async testConnection() {
      this.testing=true; this.testResult=null;
      let r;
      if (this.selectedProvider.id==='cloudflare')     r=await post('/api/cdn/cloudflare/test', this.form);
      else if (this.selectedProvider.id==='bunnycdn')  r=await post('/api/cdn/bunnycdn/test', this.form);
      else r=await post('/api/cdn/generic/test', {...this.form, provider:this.selectedProvider.id, test_url:this.generic.testUrl});
      this.testing=false; this.testResult=r;
      toast(r.ok?'Connection successful!':'Failed: '+(r.error||''), r.ok?'success':'error');
    },

    async saveConfig() {
      this.saving=true;
      const r = await put('/api/cdn/config', {...this.form, provider:this.selectedProvider.id});
      this.saving=false;
      if (r.ok) { toast(this.selectedProvider.name+' connected!','success'); this.activeCdn=this.selectedProvider.id; await this.load(); this.openDashboard(this.selectedProvider); }
      else toast(r.error||'Failed','error');
    },

    async disconnect(p) {
      if (!confirm(`Disconnect ${p.name}?`)) return;
      await del('/api/cdn/config', {provider:p.id});
      toast('Disconnected','success');
      if (this.activeCdn===p.id) { this.activeCdn=''; this.view='grid'; }
      await this.load();
    },

    async openDashboard(p) {
      this.selectedProvider=p; this.view='dashboard';
      if (p.id==='cloudflare') await this.loadCfZones();
      if (p.id==='bunnycdn')   await this.loadBunnyZones();
    },

    async loadCfZones() {
      this.cf.loading=true;
      const r=await get('/api/cdn/cloudflare/zones');
      this.cf.loading=false;
      if (r.ok) { this.cf.zones=r.zones||[]; if(r.zones?.length){this.cf.selZone=r.zones[0].id; await this.loadCfSettings();} }
      else toast(r.error||'Failed','error');
    },

    async loadCfSettings() {
      if (!this.cf.selZone) return;
      this.cf.loading=true;
      const [s,a]=await Promise.all([
        get(`/api/cdn/cloudflare/zone/${this.cf.selZone}/settings`),
        get(`/api/cdn/cloudflare/zone/${this.cf.selZone}/analytics`),
      ]);
      this.cf.loading=false;
      if (s.ok) this.cf.settings=s.settings||{};
      if (a.ok) this.cf.analytics=a.totals||{};
    },

    async cfUpdateSetting(key, val) {
      const r=await put(`/api/cdn/cloudflare/zone/${this.cf.selZone}/settings`, {settings:{[key]:val}});
      if (r.ok) { toast(`${key} updated`,'success'); this.cf.settings[key]=val; }
      else toast('Failed','error');
    },

    async cfPurge() {
      const urls=this.cf.purgeUrl?[this.cf.purgeUrl]:[];
      const r=await post(`/api/cdn/cloudflare/zone/${this.cf.selZone}/purge`, {urls});
      if (r.ok) { toast(urls.length?'URL purged':'All cache purged!','success'); this.cf.purgeUrl=''; }
      else toast(r.errors?.join(',')||'Failed','error');
    },

    async loadCfDns() {
      const r=await get(`/api/cdn/cloudflare/zone/${this.cf.selZone}/dns`);
      if (r.ok) this.cf.dns=r.records||[];
    },

    async loadBunnyZones() {
      this.bunny.loading=true;
      const r=await get('/api/cdn/bunnycdn/zones');
      this.bunny.loading=false;
      if (r.ok) { this.bunny.zones=r.zones||[]; if(r.zones?.length){this.bunny.selZone=r.zones[0].id; await this.loadBunnyStats();} }
      else toast(r.error||'Failed','error');
    },

    async loadBunnyStats() {
      if (!this.bunny.selZone) return;
      const r=await get(`/api/cdn/bunnycdn/stats/${this.bunny.selZone}`);
      if (r.ok) this.bunny.stats=r;
    },

    async bunnyPurge() {
      const r=await post(`/api/cdn/bunnycdn/purge/${this.bunny.selZone}`, {url:this.bunny.purgeUrl});
      if (r.ok) { toast(this.bunny.purgeUrl?'URL purged':'Zone purged!','success'); this.bunny.purgeUrl=''; }
      else toast('Failed','error');
    },

    async applyNginxHeaders() {
      if (!this.generic.domain) { toast('Select a domain','error'); return; }
      const r=await post('/api/cdn/nginx-headers', {domain:this.generic.domain, provider:this.selectedProvider.id});
      if (r.ok) { toast('Cache headers applied!','success'); this.generic.applyResult=r.snippet||''; }
      else toast(r.error||'Failed','error');
    },

    fmtBytes,
  };
}

// ── UPDATE MODAL ──────────────────────────────────────────────────────────────
function updateModalData() {
  return {
    checkState: 'checking',
    updating: false, updateDone: false, updateSuccess: false,
    updateError: '', updateLines: [], updateProgress: 0,
    errorMsg: '', _pollTimer: null,

    async init() {
      document.addEventListener('vortex-check-update', ()=>this.checkForUpdates());
      await this.checkForUpdates();
    },

    async checkForUpdates() {
      this.checkState='checking'; this.updating=false; this.errorMsg='';
      try {
        const r = await get('/api/update/check');

        // Sync version to parent rootApp
        try {
          const appEl = document.querySelector('[x-data="rootApp()"]');
          const app   = appEl ? Alpine.$data(appEl) : null;
          if (app) {
            app.updateModal.current   = r.current   || 'v3.0.0';
            app.updateModal.latest    = r.latest    || r.current || 'v3.0.0';
            app.updateModal.name      = r.name      || 'VortexPanel';
            app.updateModal.body      = r.body      || '';
            app.updateModal.published = r.published || '';
            if (r.has_update) app.updateAvailable = true;
          }
        } catch {}

        if (r.error && !r.current) { this.errorMsg=r.error; this.checkState='error'; return; }
        if (r.note || (!r.has_update && !r.error)) { this.checkState='uptodate'; return; }
        this.checkState = r.has_update ? 'available' : 'uptodate';
      } catch(e) {
        this.errorMsg = 'Network error: '+(e.message||'Cannot reach server');
        this.checkState = 'error';
      }
    },

    async startUpdate() {
      let version = '';
      try {
        const appEl = document.querySelector('[x-data="rootApp()"]');
        if (appEl) version = Alpine.$data(appEl).updateModal.latest || '';
      } catch {}
      this.updating=true; this.updateDone=false; this.updateSuccess=false;
      this.updateLines=[`🚀 Starting update to ${version}…`]; this.updateProgress=5;
      const r = await post('/api/update/start', {version});
      if (!r.ok) { this.updateLines.push('✗ Failed: '+(r.error||'')); this.updateDone=true; this.updateSuccess=false; return; }
      this._pollTimer = setInterval(async ()=>{
        try {
          const s = await get('/api/update/status');
          if (!s.ok) return;
          this.updateLines=s.lines||[];
          this.updateProgress=Math.min(90, 5+(s.lines||[]).length*5);
          this.$nextTick(()=>{ if(this.$refs.terminal) this.$refs.terminal.scrollTop=this.$refs.terminal.scrollHeight; });
          if (s.done) {
            clearInterval(this._pollTimer);
            this.updateProgress=100; this.updateDone=true;
            this.updateSuccess=s.success; this.updateError=s.error||'';
            if (s.success) {
              try { const appEl=document.querySelector('[x-data="rootApp()"]'); if(appEl) Alpine.$data(appEl).updateAvailable=false; } catch {}
            }
          }
        } catch {}
      }, 600);
    },
  };
}
