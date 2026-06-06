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


// ── PANEL APP ─────────────────────────────────────────────────────────────────
function panelApp() {
  return {
    username: '', page: 'dashboard',
    sidebarOpen: false,
    moduleStatus: {},
    updateAvailable: false,
    updateModal: {
      show:false, current:'v3.0.0', latest:'', name:'',
      body:'', published:'', url:'', error:'',
    },
    nav: [
      { group: 'Overview', items: [
        { id:'dashboard', icon:'▦', label:'Dashboard'   },
        { id:'websites',  icon:'🌐', label:'Websites'   },
        { id:'databases', icon:'🗄', label:'Databases'  },
        { id:'files',     icon:'📁', label:'File Manager'},
        { id:'php',       icon:'🐘', label:'PHP'        },
      ]},
      { group: 'Server', items: [
        { id:'services',  icon:'⚙', label:'Services'   },
        { id:'modules',   icon:'📦', label:'Modules'    },
        { id:'caddy',     icon:'🟩', label:'Caddy'      },
        { id:'docker',    icon:'🐋', label:'Docker'     },
        { id:'firewall',  icon:'🛡', label:'Firewall'   },
        { id:'terminal',  icon:'⌨', label:'Terminal'   },
        { id:'backups',   icon:'💾', label:'Backups'    },
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
      try {
        const r = await get('/api/modules');
        if (r.ok) r.modules.forEach(m => { this.moduleStatus[m.id] = m.installed; });
      } catch {}
      setTimeout(() => this.silentUpdateCheck(), 3000);
    },

    async silentUpdateCheck() {
      try {
        const r = await get('/api/update/check');
        // Always update current version display
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

    go(id) { this.page = id; this.sidebarOpen = false; },

    pageTitle() {
      for (const g of this.nav) {
        const item = g.items.find(i => i.id===this.page);
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
      fetch('/api/auth/logout', {method:'POST'}).then(() => { location.href='/'; });
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
    go(page){ document.dispatchEvent(new CustomEvent('nav',{detail:{page}})); },
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
    path:'/', files:[], selected:[], loading:false,
    showUpload:false, showNewFolder:false, showNewFile:false, showEditor:false,
    newFolderName:'', newFileName:'', editorContent:'', editorFile:'',
    async init(){await this.load('/');},
    async load(p){
      this.loading=true;
      const r=await get('/api/files?path='+encodeURIComponent(p||this.path));
      this.loading=false;
      if(r.ok){this.path=r.path;this.files=r.files;this.selected=[];}
      else toast(r.error||'Failed','error');
    },
    async nav(f){
      if(f.type==='dir') await this.load(f.path);
    },
    async navUp(){
      const parent=this.path.split('/').slice(0,-1).join('/')||'/';
      await this.load(parent);
    },
    async del(f){
      if(!confirm('Delete '+f.name+'?')) return;
      const r=await del('/api/files?path='+encodeURIComponent(f.path));
      if(r.ok){toast('Deleted','success');await this.load(this.path);}
    },
    async createFolder(){
      const r=await post('/api/files/mkdir',{path:this.path+'/'+this.newFolderName});
      if(r.ok){toast('Created','success');this.showNewFolder=false;this.newFolderName='';await this.load(this.path);}
    },
    async openEditor(f){
      const r=await get('/api/files/content?path='+encodeURIComponent(f.path));
      if(r.ok){this.editorContent=r.content;this.editorFile=f.path;this.showEditor=true;}
    },
    async saveEditor(){
      const r=await post('/api/files/content',{path:this.editorFile,content:this.editorContent});
      if(r.ok){toast('Saved','success');this.showEditor=false;}
    },
    fmtSize:fmtBytes, fmtDate,
  };
}

// ── PHP ───────────────────────────────────────────────────────────────────────
function phpPage() {
  return {
    versions:[], selVer:'', tab:'extensions',
    extensions:[], config:{}, logs:'',
    async init(){
      const r=await get('/api/php/versions');
      if(r.ok&&r.versions.length){this.versions=r.versions;this.selVer=r.versions[0].version;await this.loadTab();}
    },
    async selectVer(v){this.selVer=v;await this.loadTab();},
    async loadTab(){
      if(this.tab==='extensions') await this.loadExts();
      else if(this.tab==='config') await this.loadConfig();
      else if(this.tab==='logs') await this.loadLogs();
    },
    async loadExts(){
      const r=await get('/api/php/'+this.selVer+'/extensions');
      if(r.ok) this.extensions=r.extensions.map(e=>({...e,loading:false}));
    },
    async installExt(e){
      e.loading=true;
      const r=await post('/api/php/'+this.selVer+'/extensions/'+e.name+'/install');
      e.loading=false; if(r.ok){e.installed=true;toast(e.name+' installed','success');}
    },
    async uninstallExt(e){
      e.loading=true;
      const r=await post('/api/php/'+this.selVer+'/extensions/'+e.name+'/uninstall');
      e.loading=false; if(r.ok){e.installed=false;toast(e.name+' removed','success');}
    },
    async loadConfig(){const r=await get('/api/php/'+this.selVer+'/config');if(r.ok)this.config=r.config;},
    async saveConfig(key,val){await post('/api/php/'+this.selVer+'/config',{key,value:val});toast('Saved','success');},
    async control(action){const r=await post('/api/php/'+this.selVer+'/control',{action});toast(action+' php'+this.selVer+'-fpm',r.ok?'success':'error');},
    async loadLogs(){const r=await get('/api/php/'+this.selVer+'/logs');if(r.ok)this.logs=r.logs;},
  };
}

// ── SERVICES ──────────────────────────────────────────────────────────────────
function servicesPage() {
  return {
    services:[],
    async init(){await this.load();},
    async load(){const r=await get('/api/services');if(r.ok)this.services=r.services;},
    async control(svc,action){
      const r=await post('/api/services/'+svc+'/'+action);
      if(r.ok){toast(action+' '+svc,'success');await this.load();}
      else toast('Failed','error');
    },
  };
}

// ── MODULES ───────────────────────────────────────────────────────────────────
function modulesPage() {
  return {
    modules:[], cat:'',
    verModal:{show:false,mod:null,selVer:'',action:'install'},
    jobModal:{show:false,title:'',lines:[],done:false,success:false,action:'install',installedVer:''},
    async init(){await this.load();},
    async load(){
      const r=await get('/api/modules');
      if(r.ok) this.modules=r.modules.map(m=>({...m,loading:false,selVer:m.versions&&m.versions.length?m.versions[Math.floor(m.versions.length/2)].value:''}));
    },
    categories(){return[...new Set(this.modules.map(m=>m.category))].sort();},
    filtered(){return this.cat?this.modules.filter(m=>m.category===this.cat):this.modules;},
    async install(m){
      if(m.versions&&m.versions.length&&!m.selVer){toast('Select a version first','error');return;}
      await this._startJob(m,'install',m.selVer||'');
    },
    async uninstall(m){
      if(!confirm('Uninstall '+m.name+'?')) return;
      if((m.id==='php'||m.id==='python')&&m.versions&&m.versions.length){
        this.verModal={show:true,mod:m,selVer:m.versions[0].value,action:'uninstall'};return;
      }
      await this._startJob(m,'uninstall','');
    },
    async installWithVer(){
      const m=this.verModal.mod,ver=this.verModal.selVer,action=this.verModal.action||'install';
      this.verModal.show=false;
      await this._startJob(m,action,ver);
    },
    async _startJob(m,action,ver){
      m.loading=true;
      const r=await post('/api/modules/'+m.id+'/'+action,{version:ver});
      if(!r.ok){m.loading=false;toast(r.error||'Failed','error');return;}
      const jobId=r.job_id;
      const label=(action==='install'?'Installing':'Removing')+': '+m.name+(ver?' v'+ver:'');
      this.jobModal={show:true,title:label,lines:[],done:false,success:false,action,installedVer:''};
      const es=new EventSource('/api/modules/job/'+jobId);
      es.onmessage=(e)=>{
        const d=JSON.parse(e.data);
        if(d.line) this.jobModal.lines.push(d.line);
        if(d.done){
          es.close();m.loading=false;m.installed=d.installed;
          if(d.installedVer)m.installedVer=d.installedVer;
          this.jobModal.done=true;this.jobModal.success=d.success;
          this.jobModal.action=action;this.jobModal.installedVer=d.installedVer||'';
          setTimeout(()=>this.load(),1200);
        }
        if(d.error){es.close();m.loading=false;toast(d.error,'error');}
        this.$nextTick(()=>{const t=document.querySelector('.job-terminal');if(t)t.scrollTop=t.scrollHeight;});
      };
      es.onerror=()=>{es.close();m.loading=false;};
    },
    async control(m,action){
      const r=await post('/api/modules/'+m.id+'/control',{action});
      if(r.ok){m.svcStatus=r.status;toast(action+' '+m.name,'success');}
    },
  };
}

// ── FIREWALL ──────────────────────────────────────────────────────────────────
function firewallPage() {
  return {
    status:'',rules:[],showAdd:false,
    form:{port:'',protocol:'tcp',action:'allow',comment:''},
    async init(){await this.load();},
    async load(){
      const r=await get('/api/firewall');
      if(r.ok){this.rules=r.rules;this.status=r.status;}
    },
    async add(){
      const r=await post('/api/firewall',this.form);
      if(r.ok){toast('Rule added','success');this.showAdd=false;await this.load();}
      else toast(r.error||'Failed','error');
    },
    async del(rule){
      const r=await del('/api/firewall/'+encodeURIComponent(rule));
      if(r.ok){toast('Rule removed','success');await this.load();}
    },
    async toggle(action){
      const r=await post('/api/firewall/toggle',{action});
      if(r.ok){toast('Firewall '+action,'success');await this.load();}
    },
  };
}

// ── TERMINAL ──────────────────────────────────────────────────────────────────
function terminalPage() {
  return {
    output:[], input:'', history:[], histIdx:-1, cwd:'/',
    async init(){this.output=[{text:'VortexPanel Terminal — type commands below',cls:'system'}];},
    async run(){
      const cmd=this.input.trim(); if(!cmd) return;
      this.history.unshift(cmd); this.histIdx=-1;
      this.output.push({text:'$ '+cmd,cls:'cmd'});
      this.input='';
      if(cmd==='clear'){this.output=[];return;}
      const r=await post('/api/terminal/exec',{cmd,cwd:this.cwd});
      if(r.ok){
        if(r.cwd) this.cwd=r.cwd;
        if(r.output) this.output.push({text:r.output,cls:'out'});
        if(r.error)  this.output.push({text:r.error,cls:'err'});
      }
      this.$nextTick(()=>{const t=this.$refs.term;if(t)t.scrollTop=t.scrollHeight;});
    },
    keyUp(){if(this.histIdx<this.history.length-1){this.histIdx++;this.input=this.history[this.histIdx];}},
    keyDown(){if(this.histIdx>0){this.histIdx--;this.input=this.history[this.histIdx];}else{this.histIdx=-1;this.input='';}},
  };
}

// ── BACKUPS ───────────────────────────────────────────────────────────────────
function backupsPage() {
  return {
    backups:[],info:{websites:[],databases:[],mysql:false,webroot:'/www/wwwroot'},
    creating:'',
    form:{website:{domain:''},db:{name:''}},
    jobModal:{show:false,title:'',lines:[],done:false,success:false,name:'',size:0,error:''},
    restoreModal:{show:false,name:'',type:'',target:'',customPath:''},
    showUpload:false,uploadFile:null,uploadType:'website',uploadTarget:'',
    fmtSize,fmtDate,
    async init(){await Promise.all([this.load(),this.loadInfo()]);},
    async load(){const r=await get('/api/backups');if(r.ok)this.backups=r.backups;},
    async loadInfo(){const r=await get('/api/backups/info');if(r.ok)this.info=r;},
    async createBackup(type,domain,dbName){
      this.creating=type;
      const r=await post('/api/backups/create',{type,domain,database:dbName});
      if(!r.ok){this.creating='';toast(r.error||'Failed','error');return;}
      const jobId=r.job_id;
      this.jobModal={show:true,title:'Creating '+type+' backup...',lines:[],done:false,success:false,name:'',size:0,error:''};
      const poll=async()=>{
        const j=await get('/api/backups/job/'+jobId);
        if(!j.ok){this.creating='';return;}
        this.jobModal.lines=j.lines||[];
        if(j.done){this.creating='';this.jobModal={...this.jobModal,done:true,success:j.success,name:j.name||'',size:j.size||0,error:j.error||''};await this.load();}
        else setTimeout(poll,800);
      };
      setTimeout(poll,500);
    },
    downloadBackup(name){window.location.href='/api/backups/download/'+encodeURIComponent(name);},
    openRestore(b){
      let type=b.type||'website';
      if(b.name.includes('database')||b.name.endsWith('.sql.gz'))type='database';
      else if(b.name.includes('full'))type='full';
      this.restoreModal={show:true,name:b.name,type,target:'',customPath:''};
    },
    async doRestore(){
      const target=this.restoreModal.customPath||this.restoreModal.target;
      if(this.restoreModal.type==='database'&&!target){toast('Enter a database name','error');return;}
      if(!confirm('Restore "'+this.restoreModal.name+'"? This will overwrite existing data.')) return;
      this.restoreModal.show=false;
      const r=await post('/api/backups/restore',{name:this.restoreModal.name,type:this.restoreModal.type,target});
      if(!r.ok){toast(r.error||'Failed','error');return;}
      this.jobModal={show:true,title:'Restoring...',lines:[],done:false,success:false,name:'',size:0,error:''};
      const poll=async()=>{
        const j=await get('/api/backups/job/'+r.job_id);
        if(!j.ok) return;
        this.jobModal.lines=j.lines||[];
        if(j.done){this.jobModal={...this.jobModal,done:true,success:j.success,error:j.error||''};if(j.success)toast('Restored!','success');}
        else setTimeout(poll,800);
      };
      setTimeout(poll,500);
    },
    handleDrop(e){const f=e.dataTransfer.files[0];if(f){this.uploadFile=f;if(f.name.includes('.sql'))this.uploadType='database';}},
    async uploadAndRestore(){
      if(!this.uploadFile){toast('Select a file','error');return;}
      const fd=new FormData();fd.append('file',this.uploadFile);fd.append('type',this.uploadType);fd.append('target',this.uploadTarget);
      this.showUpload=false;
      try{const resp=await fetch('/api/backups/upload',{method:'POST',body:fd});const r=await resp.json();if(r.ok)toast('Upload started!','success');else toast(r.error||'Failed','error');}
      catch(e){toast('Upload failed: '+e.message,'error');}
    },
    async del(name){
      if(!confirm('Delete backup "'+name+'"?')) return;
      const r=await del('/api/backups/'+name);
      if(r.ok){toast('Deleted','success');await this.load();}
    },
  };
}

// ── DNS ───────────────────────────────────────────────────────────────────────
function dnsPage() {
  return {
    zones:[],selZone:null,records:[],showAddZone:false,showAddRecord:false,
    zoneForm:{domain:'',ip:''},
    recForm:{type:'A',name:'',value:'',ttl:'3600'},
    async init(){await this.loadZones();},
    async loadZones(){const r=await get('/api/dns/zones');if(r.ok)this.zones=r.zones;},
    async addZone(){
      const r=await post('/api/dns/zones',this.zoneForm);
      if(r.ok){toast('Zone created','success');this.showAddZone=false;await this.loadZones();}
      else toast(r.error||'Failed','error');
    },
    async selectZone(z){
      this.selZone=z;
      const r=await get('/api/dns/zones/'+z.name+'/records');
      if(r.ok)this.records=r.records;
    },
    async delZone(z){
      if(!confirm('Delete zone '+z.name+'?')) return;
      const r=await del('/api/dns/zones/'+z.name);
      if(r.ok){toast('Deleted','success');this.selZone=null;await this.loadZones();}
    },
    async addRecord(){
      const r=await post('/api/dns/zones/'+this.selZone.name+'/records',this.recForm);
      if(r.ok){toast('Record added','success');this.showAddRecord=false;await this.selectZone(this.selZone);}
      else toast(r.error||'Failed','error');
    },
    async delRecord(rec){
      const r=await del('/api/dns/zones/'+this.selZone.name+'/records/'+rec.id);
      if(r.ok){toast('Deleted','success');await this.selectZone(this.selZone);}
    },
  };
}

// ── MAIL ──────────────────────────────────────────────────────────────────────
function mailPage() {
  return {
    status:{postfix:'',dovecot:'',_notInstalled:false},
    domains:[],accounts:[],
    selDomain:'',showAddDomain:false,showAddAccount:false,
    domainForm:{domain:''},
    accountForm:{user:'',pass:'',domain:''},
    async init(){await this.loadStatus();await this.loadDomains();},
    async loadStatus(){
      const r=await get('/api/mail/status');
      if(r.ok){this.status=r;this.status._notInstalled=(r.postfix==='inactive'||!r.postfix)&&(r.dovecot==='inactive'||!r.dovecot);}
    },
    async loadDomains(){const r=await get('/api/mail/domains');if(r.ok)this.domains=r.domains;},
    async addDomain(){const r=await post('/api/mail/domains',this.domainForm);if(r.ok){toast('Domain added','success');this.showAddDomain=false;await this.loadDomains();}else toast(r.error||'Failed','error');},
    async loadAccounts(domain){
      this.selDomain=domain;
      const r=await get('/api/mail/accounts?domain='+domain);
      if(r.ok)this.accounts=r.accounts;
    },
    async addAccount(){
      const r=await post('/api/mail/accounts',{...this.accountForm,domain:this.selDomain});
      if(r.ok){toast('Account created','success');this.showAddAccount=false;await this.loadAccounts(this.selDomain);}
      else toast(r.error||'Failed','error');
    },
    async delAccount(acct){
      if(!confirm('Delete '+acct+'?')) return;
      const r=await del('/api/mail/accounts/'+acct);
      if(r.ok){toast('Deleted','success');await this.loadAccounts(this.selDomain);}
    },
    async control(svc,action){const r=await post('/api/mail/control',{service:svc,action});if(r.ok){toast(action+' '+svc,'success');await this.loadStatus();}},
  };
}

// ── FTP ───────────────────────────────────────────────────────────────────────
function ftpPage() {
  return {
    accounts:[],ftpStatus:{installed:false,daemon:'none',status:'inactive',accounts_count:0},
    showAdd:false,sites:[],
    form:{user:'',password:'',home:'',selectedDomain:''},
    pwModal:{show:false,user:'',password:''},
    async init(){await this.load();const ws=await get('/api/websites');if(ws.ok)this.sites=ws.sites||[];},
    async load(){
      const s=await get('/api/ftp/status');
      if(s.ok)this.ftpStatus=s;
      if(s.ok&&s.installed){const a=await get('/api/ftp/accounts');if(a.ok)this.accounts=a.accounts;}
    },
    onDomainChange(){if(this.form.selectedDomain)this.form.home=this.form.selectedDomain;},
    async create(){
      if(!this.form.user){toast('Username required','error');return;}
      if(!this.form.password){toast('Password required','error');return;}
      const r=await post('/api/ftp/accounts',{user:this.form.user,password:this.form.password,home:this.form.home||'/www/wwwroot/'+this.form.user});
      if(r.ok){toast('FTP account created','success');this.showAdd=false;this.form={user:'',password:'',home:'',selectedDomain:''};await this.load();}
      else toast(r.error||'Failed','error');
    },
    async del(user){if(!confirm('Delete FTP account "'+user+'"?')) return;const r=await del('/api/ftp/accounts/'+user);if(r.ok){toast('Deleted','success');await this.load();}},
    changePw(user){this.pwModal={show:true,user,password:''};},
    async savePw(){
      if(this.pwModal.password.length<6){toast('Min 6 characters','error');return;}
      const r=await put('/api/ftp/accounts/'+this.pwModal.user+'/password',{password:this.pwModal.password});
      if(r.ok){toast('Password changed','success');this.pwModal.show=false;}else toast(r.error||'Failed','error');
    },
  };
}

// ── SETTINGS ──────────────────────────────────────────────────────────────────
function settingsPage() {
  return {
    stab: 'general',
    settings: {}, panelVersion: 'v3.0.0',
    pwForm: {current:'',newpw:'',confirm:''},
    // AI config
    aiConfig: {enabled:true,api_key:'',base_url:'https://neoncodex.io/api/v1',model:'neoncodex-default',max_tokens:2048},
    aiModels: [], showApiKey: false,
    aiTesting: false, aiTestResult: '', aiTestOk: false,

    async init() {
      const r = await get('/api/settings').catch(()=>({ok:false}));
      if (r.ok) this.settings = r.settings || {};
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
      if (r.ok) {
        toast('AI settings saved','success');
        // Reload AI assistant config
        document.dispatchEvent(new CustomEvent('vortex-ai-config-changed'));
      } else {
        toast(r.error||'Failed','error');
      }
    },

    async fetchModels() {
      const r = await get('/api/ai/models');
      if (r.ok && r.models.length) {
        this.aiModels = r.models;
        toast('Models loaded: '+r.models.length,'success');
      } else {
        toast(r.error||'Could not fetch models','error');
      }
    },

    async testAiConnection() {
      this.aiTesting = true; this.aiTestResult = '';
      // Save first then test
      await put('/api/ai/config', this.aiConfig);
      const r = await post('/api/ai/chat', {
        messages: [{role:'user',content:'Reply with just: "NeonCodex AI connected successfully ✓"'}]
      });
      this.aiTesting = false;
      if (r.ok) {
        this.aiTestOk    = true;
        this.aiTestResult = '✓ ' + r.content.substring(0, 100);
      } else {
        this.aiTestOk    = false;
        this.aiTestResult = '✗ ' + (r.error || 'Connection failed');
      }
    },

    async changePw() {
      if (this.pwForm.newpw !== this.pwForm.confirm) { toast('Passwords do not match','error'); return; }
      const r = await post('/api/settings/password', this.pwForm);
      if (r.ok) { toast('Password changed','success'); this.pwForm = {current:'',newpw:'',confirm:''}; }
      else toast(r.error||'Failed','error');
    },
  };
}

// ── MONITORING ────────────────────────────────────────────────────────────────
function monitoringPage() {
  return {
    stats:{},processes:[],
    async init(){await this.load();setInterval(()=>this.load(),5000);},
    async load(){
      const r=await get('/api/monitoring');
      if(r.ok){this.stats=r;this.processes=r.processes||[];}
    },
  };
}

// ── DOCKER IMAGE CATALOG (Docker Hardened Images + Official) ─────────────────
const DOCKER_CATALOG = [
  // ── Web Servers ──────────────────────────────────────────────────────────
  {id:'nginx',name:'Nginx',icon:'🌐',cat:'Web Server',image:'dhi/nginx',tag:'latest',hardened:true,
   desc:'Hardened Nginx HTTP server, reverse proxy, load balancer — zero-known CVEs, signed SBOM.',
   ports:[{host:'80',container:'80'},{host:'443',container:'443'}],
   volumes:[{host:'/opt/docker/nginx/html',container:'/usr/share/nginx/html'},{host:'/opt/docker/nginx/conf',container:'/etc/nginx/conf.d'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/nginx'},
  {id:'caddy',name:'Caddy',icon:'🟩',cat:'Web Server',image:'dhi/caddy',tag:'latest',hardened:true,
   desc:'Hardened Caddy web server with automatic HTTPS, HTTP/3, zero-config TLS.',
   ports:[{host:'80',container:'80'},{host:'443',container:'443'}],
   volumes:[{host:'/opt/docker/caddy/data',container:'/data'},{host:'/opt/docker/caddy/config',container:'/config'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/caddy'},
  {id:'traefik',name:'Traefik',icon:'🔀',cat:'Web Server',image:'dhi/traefik',tag:'latest',hardened:true,
   desc:'Hardened Traefik cloud-native edge router and reverse proxy with auto SSL.',
   ports:[{host:'80',container:'80'},{host:'443',container:'443'},{host:'8080',container:'8080'}],
   volumes:[{host:'/var/run/docker.sock',container:'/var/run/docker.sock'},{host:'/opt/docker/traefik',container:'/etc/traefik'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/traefik'},
  {id:'envoy',name:'Envoy Proxy',icon:'🔵',cat:'Web Server',image:'dhi/envoy',tag:'latest',hardened:true,
   desc:'Hardened Envoy high-performance L7 proxy for cloud-native service mesh.',
   ports:[{host:'10000',container:'10000'},{host:'9901',container:'9901'}],
   volumes:[{host:'/opt/docker/envoy',container:'/etc/envoy'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/envoy'},

  // ── Databases ────────────────────────────────────────────────────────────
  {id:'postgres',name:'PostgreSQL',icon:'🐘',cat:'Database',image:'dhi/postgres',tag:'17',hardened:true,
   desc:'Hardened PostgreSQL 17 — zero-CVE object-relational database with signed provenance.',
   ports:[{host:'5432',container:'5432'}],
   volumes:[{host:'/opt/docker/postgres/data',container:'/var/lib/postgresql/data'}],
   envs:[{key:'POSTGRES_PASSWORD',value:'',placeholder:'Superuser password (required)'},{key:'POSTGRES_USER',value:'postgres',placeholder:'postgres'},{key:'POSTGRES_DB',value:'',placeholder:'Initial DB name'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/postgres'},
  {id:'mysql',name:'MySQL',icon:'🐬',cat:'Database',image:'dhi/mysql',tag:'8.0',hardened:true,
   desc:'Hardened MySQL 8.0 — widely used open-source relational database.',
   ports:[{host:'3306',container:'3306'}],
   volumes:[{host:'/opt/docker/mysql/data',container:'/var/lib/mysql'}],
   envs:[{key:'MYSQL_ROOT_PASSWORD',value:'',placeholder:'Root password (required)'},{key:'MYSQL_DATABASE',value:'',placeholder:'Initial DB'},{key:'MYSQL_USER',value:'',placeholder:'DB user'},{key:'MYSQL_PASSWORD',value:'',placeholder:'DB user password'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/mysql'},
  {id:'mongodb',name:'MongoDB',icon:'🍃',cat:'Database',image:'dhi/mongodb',tag:'latest',hardened:true,
   desc:'Hardened MongoDB document-oriented database — zero-known CVEs, SBOM included.',
   ports:[{host:'27017',container:'27017'}],
   volumes:[{host:'/opt/docker/mongodb/data',container:'/data/db'}],
   envs:[{key:'MONGO_INITDB_ROOT_USERNAME',value:'admin',placeholder:'admin'},{key:'MONGO_INITDB_ROOT_PASSWORD',value:'',placeholder:'Root password (required)'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/mongodb'},
  {id:'mariadb',name:'MariaDB',icon:'🦭',cat:'Database',image:'dhi/mariadb',tag:'latest',hardened:true,
   desc:'Hardened MariaDB — drop-in MySQL replacement with enhanced security.',
   ports:[{host:'3307',container:'3306'}],
   volumes:[{host:'/opt/docker/mariadb/data',container:'/var/lib/mysql'}],
   envs:[{key:'MARIADB_ROOT_PASSWORD',value:'',placeholder:'Root password (required)'},{key:'MARIADB_DATABASE',value:'',placeholder:'Initial DB'},{key:'MARIADB_USER',value:'',placeholder:'DB user'},{key:'MARIADB_PASSWORD',value:'',placeholder:'DB user password'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/mariadb'},

  // ── Cache / Messaging ─────────────────────────────────────────────────────
  {id:'redis',name:'Redis',icon:'🔴',cat:'Cache',image:'dhi/redis',tag:'7.2',hardened:true,
   desc:'Hardened Redis 7.2 — world fastest data platform for caching, vectors and NoSQL.',
   ports:[{host:'6379',container:'6379'}],
   volumes:[{host:'/opt/docker/redis/data',container:'/data'}],
   envs:[],cmd:'redis-server --save 60 1 --loglevel warning',
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/redis'},
  {id:'valkey',name:'Valkey',icon:'🗝',cat:'Cache',image:'dhi/valkey',tag:'latest',hardened:true,
   desc:'Hardened Valkey — Redis-compatible high-performance key/value datastore.',
   ports:[{host:'6380',container:'6379'}],
   volumes:[{host:'/opt/docker/valkey/data',container:'/data'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/valkey'},
  {id:'kafka',name:'Apache Kafka',icon:'📨',cat:'Messaging',image:'dhi/kafka',tag:'latest',hardened:true,
   desc:'Hardened Apache Kafka — distributed event streaming for data pipelines.',
   ports:[{host:'9092',container:'9092'},{host:'9093',container:'9093'}],
   volumes:[{host:'/opt/docker/kafka/data',container:'/var/lib/kafka/data'}],
   envs:[{key:'KAFKA_BROKER_ID',value:'1',placeholder:'1'},{key:'KAFKA_ZOOKEEPER_CONNECT',value:'',placeholder:'zookeeper:2181'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/kafka'},
  {id:'rabbitmq',name:'RabbitMQ',icon:'🐰',cat:'Messaging',image:'rabbitmq',tag:'3-management-alpine',hardened:false,
   desc:'Official RabbitMQ 3 with Management UI — reliable message broker.',
   ports:[{host:'5672',container:'5672'},{host:'15672',container:'15672'}],
   volumes:[{host:'/opt/docker/rabbitmq/data',container:'/var/lib/rabbitmq'}],
   envs:[{key:'RABBITMQ_DEFAULT_USER',value:'admin',placeholder:'admin'},{key:'RABBITMQ_DEFAULT_PASS',value:'',placeholder:'Password (required)'}],
   docs:'https://hub.docker.com/_/rabbitmq'},

  // ── Runtimes ─────────────────────────────────────────────────────────────
  {id:'python',name:'Python',icon:'🐍',cat:'Runtime',image:'dhi/python',tag:'3.13',hardened:true,
   desc:'Hardened Python 3.13 — near-zero CVEs, distroless-based, production-ready.',
   ports:[{host:'8000',container:'8000'}],
   volumes:[{host:'/opt/docker/python/app',container:'/app'}],
   envs:[{key:'PYTHONUNBUFFERED',value:'1',placeholder:'1'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/python'},
  {id:'node',name:'Node.js',icon:'🟢',cat:'Runtime',image:'dhi/node',tag:'22',hardened:true,
   desc:'Hardened Node.js 22 LTS (Jod) — minimal secure JS runtime with signed SBOM.',
   ports:[{host:'3000',container:'3000'}],
   volumes:[{host:'/opt/docker/node/app',container:'/app'}],
   envs:[{key:'NODE_ENV',value:'production',placeholder:'production'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/node'},
  {id:'php',name:'PHP',icon:'🐘',cat:'Runtime',image:'dhi/php',tag:'8.3',hardened:true,
   desc:'Hardened PHP 8.3 — general-purpose scripting language for web development.',
   ports:[{host:'9000',container:'9000'}],
   volumes:[{host:'/opt/docker/php/app',container:'/var/www/html'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/php'},
  {id:'ruby',name:'Ruby',icon:'💎',cat:'Runtime',image:'dhi/ruby',tag:'latest',hardened:true,
   desc:'Hardened Ruby — programming language focused on simplicity and productivity.',
   ports:[{host:'3001',container:'3000'}],
   volumes:[{host:'/opt/docker/ruby/app',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/ruby'},
  {id:'golang',name:'Go (golang)',icon:'🔵',cat:'Runtime',image:'dhi/golang',tag:'latest',hardened:true,
   desc:'Hardened Go runtime — general purpose, fast compiled programming language.',
   ports:[{host:'8080',container:'8080'}],
   volumes:[{host:'/opt/docker/go/app',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/golang'},
  {id:'rust',name:'Rust',icon:'🦀',cat:'Runtime',image:'dhi/rust',tag:'latest',hardened:true,
   desc:'Hardened Rust — systems language focused on safety, speed, and concurrency.',
   ports:[],volumes:[{host:'/opt/docker/rust/app',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/rust'},
  {id:'dotnet',name:'.NET',icon:'🔷',cat:'Runtime',image:'dhi/dotnet',tag:'latest',hardened:true,
   desc:'Hardened .NET — free, open-source cross-platform framework by Microsoft.',
   ports:[{host:'5000',container:'5000'}],
   volumes:[{host:'/opt/docker/dotnet/app',container:'/app'}],
   envs:[{key:'ASPNETCORE_URLS',value:'http://+:5000',placeholder:'http://+:5000'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/dotnet'},
  {id:'eclipse-temurin',name:'Eclipse Temurin',icon:'☕',cat:'Runtime',image:'dhi/eclipse-temurin',tag:'21',hardened:true,
   desc:'Hardened Eclipse Temurin OpenJDK 21 — enterprise-caliber Java runtime.',
   ports:[{host:'8080',container:'8080'}],
   volumes:[{host:'/opt/docker/java/app',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/eclipse-temurin'},
  {id:'amazoncorretto',name:'Amazon Corretto',icon:'☕',cat:'Runtime',image:'dhi/amazoncorretto',tag:'21',hardened:true,
   desc:'Hardened Amazon Corretto OpenJDK — production-ready Java from AWS.',
   ports:[{host:'8081',container:'8080'}],
   volumes:[{host:'/opt/docker/corretto/app',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/amazoncorretto'},
  {id:'tomcat',name:'Apache Tomcat',icon:'🐱',cat:'Runtime',image:'dhi/tomcat',tag:'latest',hardened:true,
   desc:'Hardened Apache Tomcat — Java Servlet and JavaServer Pages implementation.',
   ports:[{host:'8082',container:'8080'}],
   volumes:[{host:'/opt/docker/tomcat/webapps',container:'/usr/local/tomcat/webapps'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/tomcat'},

  // ── Monitoring ───────────────────────────────────────────────────────────
  {id:'grafana',name:'Grafana',icon:'📊',cat:'Monitoring',image:'dhi/grafana',tag:'latest',hardened:true,
   desc:'Hardened Grafana — query, visualize, alert on metrics, logs, and traces.',
   ports:[{host:'3001',container:'3000'}],
   volumes:[{host:'/opt/docker/grafana/data',container:'/var/lib/grafana'}],
   envs:[{key:'GF_SECURITY_ADMIN_PASSWORD',value:'',placeholder:'Admin password (required)'},{key:'GF_USERS_ALLOW_SIGN_UP',value:'false',placeholder:'false'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/grafana'},
  {id:'prometheus',name:'Prometheus',icon:'🔥',cat:'Monitoring',image:'dhi/prometheus',tag:'latest',hardened:true,
   desc:'Hardened Prometheus — systems monitoring with time series database.',
   ports:[{host:'9090',container:'9090'}],
   volumes:[{host:'/opt/docker/prometheus/config',container:'/etc/prometheus'},{host:'/opt/docker/prometheus/data',container:'/prometheus'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/prometheus'},
  {id:'loki',name:'Grafana Loki',icon:'📋',cat:'Monitoring',image:'dhi/loki',tag:'latest',hardened:true,
   desc:'Hardened Grafana Loki — cloud native log aggregation system.',
   ports:[{host:'3100',container:'3100'}],
   volumes:[{host:'/opt/docker/loki/data',container:'/loki'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/loki'},
  {id:'node-exporter',name:'Node Exporter',icon:'📈',cat:'Monitoring',image:'dhi/node-exporter',tag:'latest',hardened:true,
   desc:'Hardened Prometheus Node Exporter — hardware and OS metrics for Prometheus.',
   ports:[{host:'9100',container:'9100'}],volumes:[],envs:[],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/node-exporter'},
  {id:'filebeat',name:'Filebeat',icon:'📤',cat:'Monitoring',image:'dhi/filebeat',tag:'latest',hardened:true,
   desc:'Hardened Filebeat — ships log files to Logstash or Elasticsearch.',
   ports:[],volumes:[{host:'/var/log',container:'/var/log/host'},{host:'/opt/docker/filebeat',container:'/usr/share/filebeat/data'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/filebeat'},
  {id:'opentelemetry',name:'OpenTelemetry Collector',icon:'🔭',cat:'Monitoring',image:'dhi/opentelemetry-collector',tag:'latest',hardened:true,
   desc:'Hardened OpenTelemetry Collector — vendor-agnostic telemetry pipeline.',
   ports:[{host:'4317',container:'4317'},{host:'4318',container:'4318'},{host:'8888',container:'8888'}],
   volumes:[{host:'/opt/docker/otel',container:'/etc/otelcol'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/opentelemetry-collector'},

  // ── Security ─────────────────────────────────────────────────────────────
  {id:'vault',name:'HashiCorp Vault',icon:'🔐',cat:'Security',image:'dhi/vault',tag:'latest',hardened:true,
   desc:'Hardened HashiCorp Vault — tool for securely storing and accessing secrets.',
   ports:[{host:'8200',container:'8200'}],
   volumes:[{host:'/opt/docker/vault/data',container:'/vault/data'},{host:'/opt/docker/vault/config',container:'/vault/config'}],
   envs:[{key:'VAULT_DEV_ROOT_TOKEN_ID',value:'',placeholder:'Dev mode root token'},{key:'VAULT_DEV_LISTEN_ADDRESS',value:'0.0.0.0:8200',placeholder:'0.0.0.0:8200'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/vault'},
  {id:'keycloak',name:'Keycloak',icon:'🔑',cat:'Security',image:'dhi/keycloak',tag:'latest',hardened:true,
   desc:'Hardened Keycloak — identity and access management with SSO.',
   ports:[{host:'8180',container:'8080'}],
   volumes:[],
   envs:[{key:'KEYCLOAK_ADMIN',value:'admin',placeholder:'Admin username'},{key:'KEYCLOAK_ADMIN_PASSWORD',value:'',placeholder:'Admin password (required)'},{key:'KC_DB',value:'postgres',placeholder:'postgres or mysql'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/keycloak'},
  {id:'trivy',name:'Trivy Scanner',icon:'🔍',cat:'Security',image:'dhi/trivy',tag:'latest',hardened:true,
   desc:'Hardened Trivy — comprehensive vulnerability scanner for containers and code.',
   ports:[{host:'4954',container:'4954'}],
   volumes:[{host:'/var/run/docker.sock',container:'/var/run/docker.sock'},{host:'/opt/docker/trivy',container:'/root/.cache/trivy'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/trivy'},
  {id:'cosign',name:'Cosign',icon:'✍',cat:'Security',image:'dhi/cosign',tag:'latest',hardened:true,
   desc:'Hardened Cosign — container image signing and verification tool.',
   ports:[],volumes:[],envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/cosign'},
  {id:'openscap',name:'OpenSCAP',icon:'🛡',cat:'Security',image:'dhi/openscap',tag:'latest',hardened:true,
   desc:'Hardened OpenSCAP — security compliance scanning and SCAP document processing.',
   ports:[],volumes:[{host:'/opt/docker/openscap',container:'/results'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/openscap'},
  {id:'vaultwarden',name:'Vaultwarden',icon:'🔒',cat:'Security',image:'vaultwarden/server',tag:'latest',hardened:false,
   desc:'Unofficial Bitwarden-compatible self-hosted password manager server.',
   ports:[{host:'8091',container:'80'}],
   volumes:[{host:'/opt/docker/vaultwarden/data',container:'/data'}],
   envs:[{key:'DOMAIN',value:'',placeholder:'https://vault.yourdomain.com'},{key:'ADMIN_TOKEN',value:'',placeholder:'Secure random token for /admin'}],
   docs:'https://hub.docker.com/r/vaultwarden/server'},

  // ── Applications ─────────────────────────────────────────────────────────
  {id:'wordpress',name:'WordPress',icon:'📝',cat:'Application',image:'dhi/wordpress',tag:'latest',hardened:true,
   desc:'Hardened WordPress — open-source CMS with PHP runtime and extensions.',
   ports:[{host:'8080',container:'80'}],
   volumes:[{host:'/opt/docker/wordpress/html',container:'/var/www/html'}],
   envs:[{key:'WORDPRESS_DB_HOST',value:'',placeholder:'mysql container or host:3306'},{key:'WORDPRESS_DB_USER',value:'wordpress',placeholder:'wordpress'},{key:'WORDPRESS_DB_PASSWORD',value:'',placeholder:'DB password (required)'},{key:'WORDPRESS_DB_NAME',value:'wordpress',placeholder:'wordpress'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/wordpress'},
  {id:'phpmyadmin',name:'phpMyAdmin',icon:'🗄',cat:'Application',image:'phpmyadmin',tag:'latest',hardened:false,
   desc:'Official phpMyAdmin — web-based MySQL/MariaDB administration interface.',
   ports:[{host:'8085',container:'80'}],volumes:[],
   envs:[{key:'PMA_HOST',value:'',placeholder:'MySQL host (container name)'},{key:'PMA_PORT',value:'3306',placeholder:'3306'},{key:'PMA_ARBITRARY',value:'1',placeholder:'1'}],
   docs:'https://hub.docker.com/_/phpmyadmin'},
  {id:'nextcloud',name:'Nextcloud',icon:'☁',cat:'Application',image:'nextcloud',tag:'stable-apache',hardened:false,
   desc:'Nextcloud — self-hosted file sync, sharing and collaboration platform.',
   ports:[{host:'8090',container:'80'}],
   volumes:[{host:'/opt/docker/nextcloud/html',container:'/var/www/html'},{host:'/opt/docker/nextcloud/data',container:'/var/www/html/data'}],
   envs:[{key:'MYSQL_HOST',value:'',placeholder:'DB host'},{key:'MYSQL_DATABASE',value:'nextcloud',placeholder:'nextcloud'},{key:'MYSQL_USER',value:'nextcloud',placeholder:'nextcloud'},{key:'MYSQL_PASSWORD',value:'',placeholder:'DB password'}],
   docs:'https://hub.docker.com/_/nextcloud'},
  {id:'gitea',name:'Gitea',icon:'🐙',cat:'Application',image:'gitea/gitea',tag:'latest',hardened:false,
   desc:'Gitea — lightweight self-hosted Git service with web UI, CI/CD, packages.',
   ports:[{host:'3000',container:'3000'},{host:'222',container:'22'}],
   volumes:[{host:'/opt/docker/gitea/data',container:'/data'}],
   envs:[{key:'GITEA__database__DB_TYPE',value:'sqlite3',placeholder:'sqlite3 | mysql | postgres'},{key:'GITEA__server__DOMAIN',value:'',placeholder:'your-domain.com'}],
   docs:'https://hub.docker.com/r/gitea/gitea'},
  {id:'grist',name:'Grist',icon:'📊',cat:'Application',image:'dhi/grist',tag:'latest',hardened:true,
   desc:'Hardened Grist — modern relational spreadsheet for structured data.',
   ports:[{host:'8484',container:'8484'}],
   volumes:[{host:'/opt/docker/grist/data',container:'/persist'}],
   envs:[{key:'GRIST_DOMAIN',value:'',placeholder:'grist.yourdomain.com'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/grist'},

  // ── DevOps / CI-CD ────────────────────────────────────────────────────────
  {id:'jenkins',name:'Jenkins',icon:'🔧',cat:'DevOps',image:'dhi/jenkins',tag:'latest',hardened:true,
   desc:'Hardened Jenkins — open-source automation server for CI/CD pipelines.',
   ports:[{host:'8180',container:'8080'},{host:'50000',container:'50000'}],
   volumes:[{host:'/opt/docker/jenkins/home',container:'/var/jenkins_home'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/jenkins'},
  {id:'argocd',name:'Argo CD',icon:'🚀',cat:'DevOps',image:'dhi/argocd',tag:'latest',hardened:true,
   desc:'Hardened Argo CD — declarative GitOps continuous delivery for Kubernetes.',
   ports:[{host:'8443',container:'8080'}],volumes:[],envs:[],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/argocd'},
  {id:'helm',name:'Helm',icon:'⎈',cat:'DevOps',image:'dhi/helm',tag:'latest',hardened:true,
   desc:'Hardened Helm — package manager for Kubernetes applications.',
   ports:[],volumes:[{host:'/root/.kube',container:'/root/.kube'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/helm'},

  // ── Data / AI ─────────────────────────────────────────────────────────────
  {id:'airflow',name:'Apache Airflow',icon:'🌬',cat:'Data',image:'dhi/airflow',tag:'latest',hardened:true,
   desc:'Hardened Apache Airflow — programmatically author, schedule and monitor workflows.',
   ports:[{host:'8280',container:'8080'}],
   volumes:[{host:'/opt/docker/airflow/dags',container:'/opt/airflow/dags'},{host:'/opt/docker/airflow/logs',container:'/opt/airflow/logs'}],
   envs:[{key:'AIRFLOW__CORE__EXECUTOR',value:'SequentialExecutor',placeholder:'SequentialExecutor'},{key:'AIRFLOW__CORE__FERNET_KEY',value:'',placeholder:'Fernet encryption key'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/airflow'},
  {id:'spark',name:'Apache Spark',icon:'✨',cat:'Data',image:'dhi/spark',tag:'latest',hardened:true,
   desc:'Hardened Apache Spark — unified analytics engine for large-scale data processing.',
   ports:[{host:'8181',container:'8080'},{host:'7077',container:'7077'}],
   volumes:[{host:'/opt/docker/spark/data',container:'/opt/spark/data'}],
   envs:[{key:'SPARK_MODE',value:'master',placeholder:'master | worker'}],
   docs:'https://hub.docker.com/hardened-images/catalog/dhi/spark'},
  {id:'pytorch',name:'PyTorch',icon:'🤖',cat:'Data',image:'dhi/pytorch',tag:'latest',hardened:true,
   desc:'Hardened PyTorch — Python machine learning framework with GPU acceleration.',
   ports:[{host:'8888',container:'8888'}],
   volumes:[{host:'/opt/docker/pytorch/work',container:'/workspace'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/pytorch'},

  // ── Dev Tools ─────────────────────────────────────────────────────────────
  {id:'gradle',name:'Gradle',icon:'🐘',cat:'Dev',image:'dhi/gradle',tag:'latest',hardened:true,
   desc:'Hardened Gradle — build automation tool with multi-language support.',
   ports:[],volumes:[{host:'/opt/docker/gradle/project',container:'/home/gradle/project'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/gradle'},
  {id:'maven',name:'Maven',icon:'📦',cat:'Dev',image:'dhi/maven',tag:'latest',hardened:true,
   desc:'Hardened Apache Maven — software project management and build tool.',
   ports:[],volumes:[{host:'/opt/docker/maven/project',container:'/usr/src/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/maven'},
  {id:'composer',name:'Composer',icon:'🎼',cat:'Dev',image:'dhi/composer',tag:'latest',hardened:true,
   desc:'Hardened Composer — dependency manager for PHP projects.',
   ports:[],volumes:[{host:'/opt/docker/composer/app',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/composer'},
  {id:'uv',name:'uv (Python)',icon:'⚡',cat:'Dev',image:'dhi/uv',tag:'latest',hardened:true,
   desc:'Hardened uv — extremely fast Python package installer and resolver, written in Rust.',
   ports:[],volumes:[{host:'/opt/docker/uv/project',container:'/app'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/uv'},
  {id:'bash',name:'Bash',icon:'💻',cat:'Dev',image:'dhi/bash',tag:'latest',hardened:true,
   desc:'Hardened Bash — interactive command interpreter for automation scripts.',
   ports:[],volumes:[{host:'/opt/docker/bash/scripts',container:'/scripts'}],
   envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/bash'},

  // ── Base Images ───────────────────────────────────────────────────────────
  {id:'alpine',name:'Alpine Linux',icon:'🏔',cat:'Base Image',image:'dhi/alpine',tag:'latest',hardened:true,
   desc:'Hardened Alpine Linux — ultra-minimal base image under 5MB, near-zero CVEs.',
   ports:[],volumes:[],envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/alpine'},
  {id:'alpine-base',name:'Alpine Base',icon:'🏔',cat:'Base Image',image:'dhi/alpine-base',tag:'latest',hardened:true,
   desc:'Hardened Alpine base with essential system utilities for building lightweight apps.',
   ports:[],volumes:[],envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/alpine-base'},
  {id:'debian-base',name:'Debian Base',icon:'🐧',cat:'Base Image',image:'dhi/debian-base',tag:'latest',hardened:true,
   desc:'Hardened minimal Debian base with essential utilities for containerized apps.',
   ports:[],volumes:[],envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/debian-base'},
  {id:'busybox',name:'BusyBox',icon:'📦',cat:'Base Image',image:'dhi/busybox',tag:'latest',hardened:true,
   desc:'Hardened BusyBox — Swiss Army Knife of embedded Linux, ~1MB footprint.',
   ports:[],volumes:[],envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/busybox'},
  {id:'static',name:'Static (Distroless)',icon:'📄',cat:'Base Image',image:'dhi/static',tag:'latest',hardened:true,
   desc:'Hardened distroless static image — for Golang/Rust binaries, minimal attack surface.',
   ports:[],volumes:[],envs:[],docs:'https://hub.docker.com/hardened-images/catalog/dhi/static'},
];

// ── DOCKER PAGE ───────────────────────────────────────────────────────────────
function dockerPage() {
  return {
    status:{installed:false,running:false,version:''},
    containers:[],images:[],volumes:[],networks:[],
    tab:'catalog',
    catalog:DOCKER_CATALOG,
    catalogFilter:'All',search:'',
    showRun:false,runTarget:null,
    runForm:{name:'',ports:[],envs:[],volumes:[],restart:'unless-stopped',cmd:''},
    jobModal:{show:false,title:'',lines:[],done:false,success:false},
    logsModal:{show:false,name:'',content:''},
    statsModal:{show:false,name:'',stats:{}},
    async init(){await this.loadStatus();if(this.status.running)await Promise.all([this.loadContainers(),this.loadImages()]);},
    async loadStatus(){const r=await get('/api/docker/status');if(r.ok)this.status=r;},
    async loadContainers(){const r=await get('/api/docker/containers');if(r.ok)this.containers=r.containers;},
    async loadImages(){const r=await get('/api/docker/images');if(r.ok)this.images=r.images;},
    async loadVolumes(){const r=await get('/api/docker/volumes');if(r.ok)this.volumes=r.volumes;const n=await get('/api/docker/networks');if(n.ok)this.networks=n.networks;},
    get categories(){return['All',...new Set(DOCKER_CATALOG.map(i=>i.cat))];},
    get filteredCatalog(){return DOCKER_CATALOG.filter(i=>{const matchCat=this.catalogFilter==='All'||i.cat===this.catalogFilter;const matchSearch=!this.search||i.name.toLowerCase().includes(this.search.toLowerCase())||i.image.toLowerCase().includes(this.search.toLowerCase());return matchCat&&matchSearch;});},
    isInstalled(img){return this.images.some(i=>i.repository.includes(img.image.split('/').pop())||i.repository===img.image);},
    openRun(img){
      this.runTarget=img;
      this.runForm={name:img.id+'_1',ports:img.ports.map(p=>({...p})),envs:img.envs.map(e=>({...e})),volumes:img.volumes.map(v=>({...v})),restart:'unless-stopped',cmd:img.cmd||''};
      this.showRun=true;
    },
    async pullAndRun(){
      if(!this.runTarget) return;
      const image=this.runTarget.image+':'+(this.runTarget.tag||'latest');
      this.showRun=false;
      this.jobModal={show:true,title:'Deploying: '+this.runTarget.name,lines:[],done:false,success:false};
      const r=await post('/api/docker/run',{image,name:this.runForm.name,ports:this.runForm.ports.filter(p=>p.host&&p.container),envs:this.runForm.envs.filter(e=>e.key),volumes:this.runForm.volumes.filter(v=>v.host&&v.container),restart:this.runForm.restart,cmd:this.runForm.cmd||''});
      if(!r.ok){this.jobModal.lines=[r.error||'Failed'];this.jobModal.done=true;return;}
      const poll=async()=>{
        const j=await get('/api/docker/job/'+r.job_id);if(!j.ok)return;
        this.jobModal.lines=j.lines||[];
        if(j.done){this.jobModal.done=true;this.jobModal.success=j.success;if(j.success){toast(this.runTarget.name+' deployed!','success');await Promise.all([this.loadContainers(),this.loadImages()]);}}
        else setTimeout(poll,600);
      };
      setTimeout(poll,400);
    },
    async containerAction(c,action){
      if(action==='remove'&&!confirm('Remove container '+c.name+'?')) return;
      const r=await post('/api/docker/containers/'+c.id+'/action',{action});
      if(r.ok){toast(action+' '+c.name,'success');await this.loadContainers();}else toast(r.error||'Failed','error');
    },
    async showLogs(c){const r=await get('/api/docker/containers/'+c.id+'/logs');if(r.ok)this.logsModal={show:true,name:c.name,content:r.logs};},
    async showStats(c){const r=await get('/api/docker/containers/'+c.id+'/stats');if(r.ok)this.statsModal={show:true,name:c.name,stats:r};},
    async removeImage(img){if(!confirm('Remove image '+img.repository+':'+img.tag+'?')) return;const r=await del('/api/docker/images/'+img.id);if(r.ok){toast('Removed','success');await this.loadImages();}else toast(r.error||'Failed (may be in use)','error');},
    async prune(){if(!confirm('Remove stopped containers + unused images?')) return;const r=await post('/api/docker/system/prune');if(r.ok){toast('System pruned','success');await Promise.all([this.loadContainers(),this.loadImages()]);}},
  };
}

// ── CRON ─────────────────────────────────────────────────────────────────────
function cronPage() {
  return {
    jobs:[],templates:[],schedulePresets:[],
    showForm:false,editTarget:null,
    schedulePreset:'0 0 * * *',scheduleHuman:'Daily at 00:00',showCustom:false,selectedTemplate:null,
    form:{name:'',schedule:'0 0 * * *',command:'',type:'shell',user:'root'},
    runModal:{show:false,name:'',cmd:'',lines:[],done:false,exit:null},
    logModal:{show:false,name:'',log:'',last_run:'',last_exit:''},
    _pollTimer:null,
    typeIcon(t){return{shell:'⌨',php:'🐘',python:'🐍',node:'🟢',url:'🌐',backup:'💾',db_backup:'🗄',certbot:'🔒',log_clear:'🧹',custom:'⚙'}[t]||'⚙';},
    async init(){const r=await get('/api/cron/presets');if(r.ok){this.templates=r.templates;this.schedulePresets=r.schedules;}this.selectedTemplate=this.templates.find(t=>t.id==='shell')||null;await this.load();},
    async load(){const r=await get('/api/cron/jobs');if(r.ok)this.jobs=r.jobs;},
    openAdd(){this.editTarget=null;this.form={name:'',schedule:'0 0 * * *',command:'',type:'shell',user:'root'};this.schedulePreset='0 0 * * *';this.scheduleHuman='Daily at 00:00';this.showCustom=false;this.selectedTemplate=this.templates.find(t=>t.id==='shell');this.showForm=true;},
    openEdit(j){this.editTarget=j;this.form={name:j.name,schedule:j.schedule,command:j.command,type:j.type||'shell',user:j.user||'root'};const match=(this.schedulePresets||[]).find(p=>p.value===j.schedule);this.schedulePreset=match?match.value:'custom';this.showCustom=!match;this.scheduleHuman=j.schedule_human||j.schedule;this.selectedTemplate=this.templates.find(t=>t.id===j.type)||this.templates[0];this.showForm=true;},
    selectType(t){this.form.type=t.id;this.selectedTemplate=t;if(t.cmd&&!this.editTarget)this.form.command=t.cmd;},
    onPresetChange(){if(this.schedulePreset==='custom'){this.showCustom=true;return;}this.showCustom=false;this.form.schedule=this.schedulePreset;this.updateScheduleHuman();},
    updateScheduleHuman(){const p=this.schedulePresets.find(p=>p.value===this.form.schedule);if(p&&p.value!=='custom'){this.scheduleHuman=p.label;return;}const parts=this.form.schedule.split(' ');if(parts.length!==5){this.scheduleHuman=this.form.schedule;return;}const[mn,hr,dom,mon,dow]=parts;if(mn==='*'&&hr==='*')this.scheduleHuman='Every minute';else if(hr==='*'&&mn!=='*')this.scheduleHuman=`Every hour at :${mn.padStart(2,'0')}`;else if(dom==='*'&&mon==='*'&&dow==='*')this.scheduleHuman=`Daily at ${hr.padStart(2,'0')}:${mn.padStart(2,'0')}`;else this.scheduleHuman=this.form.schedule;},
    async save(){
      if(!this.form.command){toast('Command required','error');return;}
      if(this.form.schedule.split(' ').length!==5){toast('Invalid schedule','error');return;}
      let r=this.editTarget?await put('/api/cron/jobs/'+this.editTarget.id,this.form):await post('/api/cron/jobs',this.form);
      if(r.ok){toast(this.editTarget?'Task updated':'Task added','success');this.showForm=false;await this.load();}
      else toast(r.error||'Failed','error');
    },
    async toggleJob(j,enable){const r=await post('/api/cron/jobs/'+j.id+'/toggle',{enable});if(r.ok){j.enabled=enable;toast(enable?'Enabled':'Disabled','success');}else toast('Failed','error');},
    async del(j){if(!confirm('Delete task "'+(j.name||j.command)+'"?')) return;const r=await del('/api/cron/jobs/'+j.id);if(r.ok){toast('Deleted','success');await this.load();}},
    async runNow(j){
      this.runModal={show:true,name:j.name||'Task',cmd:j.command,lines:[],done:false,exit:null};
      const r=await post('/api/cron/jobs/'+j.id+'/run');
      if(!r.ok){this.runModal.lines=['✗ '+(r.error||'Failed')];this.runModal.done=true;return;}
      this._pollTimer=setInterval(async()=>{
        const s=await get('/api/cron/run/'+r.run_id);if(!s.ok)return;
        this.runModal.lines=s.lines||[];
        this.$nextTick(()=>{if(this.$refs.runTerminal)this.$refs.runTerminal.scrollTop=this.$refs.runTerminal.scrollHeight;});
        if(s.done){clearInterval(this._pollTimer);this.runModal.done=true;this.runModal.exit=s.exit_code;await this.load();}
      },500);
    },
    async openLogs(j){const r=await get('/api/cron/jobs/'+j.id+'/logs');if(r.ok)this.logModal={show:true,name:j.name||j.command,log:r.log,last_run:r.last_run,last_exit:r.last_exit};},
  };
}

// ── BANDWIDTH ─────────────────────────────────────────────────────────────────
function bandwidthPage() {
  return {
    summary:{interface:'',total_rx:0,total_tx:0,daily:[],monthly:[]},
    rt:{rx_per_sec:0,tx_per_sec:0},
    domains:[],hasVnstat:false,fmtBytes,
    async init(){await this.loadSummary();await this.loadDomains();await this.loadRealtime();setInterval(()=>this.loadRealtime(),3000);},
    async loadSummary(){const r=await get('/api/bandwidth/summary');if(r.ok){this.summary=r;this.hasVnstat=r.source==='vnstat';}},
    async loadRealtime(){const r=await get('/api/bandwidth/realtime');if(r.ok)this.rt=r;},
    async loadDomains(){const r=await get('/api/bandwidth/domains');if(r.ok)this.domains=r.domains;},
    async installVnstat(){toast('Installing vnstat…','info');const r=await post('/api/bandwidth/install-vnstat');toast(r.ok?'vnstat installed!':'Failed',r.ok?'success':'error');if(r.ok)await this.loadSummary();},
  };
}

// ── SECURITY ──────────────────────────────────────────────────────────────────
function securityPage() {
  return {
    tab:'ssh',score:0,checks:[],
    ssh:{port:'22',password_auth:'yes',root_login:'yes',pubkey_auth:'yes',max_auth_tries:'6'},
    f2bJails:[],attempts:[],portsOutput:'',
    modsec:{installed:false,enabled:false,rules:0},
    lb:{configured:false,servers:[{address:'127.0.0.1:8001',weight:1},{address:'127.0.0.1:8002',weight:1}],method:'roundrobin',domain:'_',port:'80'},
    async init(){await Promise.all([this.loadScore(),this.loadSSH()]);},
    async loadScore(){const r=await get('/api/security/score');if(r.ok){this.score=r.score;this.checks=r.checks;}},
    async loadSSH(){const r=await get('/api/security/ssh');if(r.ok)this.ssh=r.config;},
    async saveSSH(){const r=await put('/api/security/ssh',this.ssh);toast(r.ok?'SSH config saved':'Failed',r.ok?'success':'error');if(r.ok)await this.loadScore();},
    async loadFail2ban(){const r=await get('/api/security/fail2ban');if(r.ok)this.f2bJails=r.jails.map(j=>({...j,banInput:''}));else toast(r.error||'Fail2ban not running','error');},
    async unbanIP(ip,jail){const r=await post('/api/security/fail2ban/unban',{ip,jail});toast(r.ok?'Unbanned '+ip:'Failed',r.ok?'success':'error');if(r.ok)await this.loadFail2ban();},
    async banIP(ip,jail){if(!ip)return;const r=await post('/api/security/fail2ban/ban',{ip,jail});toast(r.ok?'Banned '+ip:'Failed',r.ok?'success':'error');if(r.ok)await this.loadFail2ban();},
    async loadAttempts(){const r=await get('/api/security/login-attempts');if(r.ok)this.attempts=r.attempts;},
    async loadPorts(){const r=await get('/api/security/ports');if(r.ok)this.portsOutput=r.output;},
    async loadModsec(){const r=await get('/api/security/modsecurity');if(r.ok)this.modsec=r;},
    async toggleModsec(enable){const r=await post('/api/security/modsecurity/toggle',{enable});if(r.ok){this.modsec.enabled=enable;toast(enable?'WAF Blocking Mode ON':'WAF Detection Only','success');}else toast(r.error||'Failed','error');},
    async loadLB(){const r=await get('/api/security/loadbalancer');if(r.ok){this.lb.configured=r.configured;if(r.configured){this.lb.servers=r.servers.length?r.servers:[{address:'127.0.0.1:8001',weight:1}];this.lb.method=r.method||'roundrobin';}}},
    async saveLB(){if(!this.lb.servers.length){toast('Add at least one server','error');return;}const r=await put('/api/security/loadbalancer',{servers:this.lb.servers,method:this.lb.method,domain:this.lb.domain||'_',port:this.lb.port||'80'});if(r.ok){toast('Load balancer configured!','success');this.lb.configured=true;}else toast(r.error||'Failed','error');},
    async deleteLB(){if(!confirm('Remove load balancer config?')) return;const r=await del('/api/security/loadbalancer');if(r.ok){toast('Removed','success');this.lb.configured=false;}},
  };
}

// ── CDN ───────────────────────────────────────────────────────────────────────
function cdnPage() {
  return {
    providers:[],activeCdn:'',selectedProvider:null,view:'grid',form:{},showPw:{},testing:false,testResult:null,saving:false,
    cf:{zones:[],selZone:'',settings:{},dns:[],analytics:{},purgeUrl:'',loading:false},
    bunny:{zones:[],selZone:'',stats:{},purgeUrl:'',loading:false},
    generic:{testUrl:'',testResult:null,domain:'',applyResult:''},
    sites:[],
    async init(){await this.load();const ws=await get('/api/websites');if(ws.ok)this.sites=ws.sites||[];},
    async load(){const r=await get('/api/cdn/providers');if(r.ok){this.providers=r.providers;this.activeCdn=r.active||'';}},
    selectProvider(p){this.selectedProvider=p;this.form={};this.showPw={};this.testResult=null;this.view='settings';},
    async testConnection(){
      this.testing=true;this.testResult=null;
      let r;
      if(this.selectedProvider.id==='cloudflare')r=await post('/api/cdn/cloudflare/test',this.form);
      else if(this.selectedProvider.id==='bunnycdn')r=await post('/api/cdn/bunnycdn/test',this.form);
      else r=await post('/api/cdn/generic/test',{...this.form,provider:this.selectedProvider.id,test_url:this.generic.testUrl});
      this.testing=false;this.testResult=r;
      if(r.ok)toast('Connection successful!','success');else toast('Failed: '+(r.error||'Check credentials'),'error');
    },
    async saveConfig(){
      this.saving=true;
      const r=await put('/api/cdn/config',{...this.form,provider:this.selectedProvider.id});
      this.saving=false;
      if(r.ok){toast(this.selectedProvider.name+' connected!','success');this.activeCdn=this.selectedProvider.id;await this.load();this.openDashboard(this.selectedProvider);}
      else toast(r.error||'Save failed','error');
    },
    async disconnect(p){if(!confirm('Disconnect '+p.name+'?')) return;await del('/api/cdn/config',{provider:p.id});toast('Disconnected','success');if(this.activeCdn===p.id){this.activeCdn='';this.view='grid';}await this.load();},
    async openDashboard(p){this.selectedProvider=p;this.view='dashboard';if(p.id==='cloudflare')await this.loadCfZones();if(p.id==='bunnycdn')await this.loadBunnyZones();},
    async loadCfZones(){this.cf.loading=true;const r=await get('/api/cdn/cloudflare/zones');this.cf.loading=false;if(r.ok){this.cf.zones=r.zones;if(r.zones.length){this.cf.selZone=r.zones[0].id;await this.loadCfSettings();}}else toast(r.error||'Failed','error');},
    async loadCfSettings(){if(!this.cf.selZone)return;this.cf.loading=true;const[settR,analR]=await Promise.all([get('/api/cdn/cloudflare/zone/'+this.cf.selZone+'/settings'),get('/api/cdn/cloudflare/zone/'+this.cf.selZone+'/analytics')]);this.cf.loading=false;if(settR.ok)this.cf.settings=settR.settings;if(analR.ok)this.cf.analytics=analR.totals;},
    async cfUpdateSetting(key,val){const r=await put('/api/cdn/cloudflare/zone/'+this.cf.selZone+'/settings',{settings:{[key]:val}});if(r.ok){toast(key+' updated','success');this.cf.settings[key]=val;}else toast('Failed','error');},
    async cfPurge(){const urls=this.cf.purgeUrl?[this.cf.purgeUrl]:[];const r=await post('/api/cdn/cloudflare/zone/'+this.cf.selZone+'/purge',{urls});if(r.ok){toast(urls.length?'URL purged':'All cache purged!','success');this.cf.purgeUrl='';}else toast(r.errors?.join(',')||'Failed','error');},
    async loadCfDns(){const r=await get('/api/cdn/cloudflare/zone/'+this.cf.selZone+'/dns');if(r.ok)this.cf.dns=r.records;},
    async loadBunnyZones(){this.bunny.loading=true;const r=await get('/api/cdn/bunnycdn/zones');this.bunny.loading=false;if(r.ok){this.bunny.zones=r.zones;if(r.zones.length){this.bunny.selZone=r.zones[0].id;await this.loadBunnyStats();}}else toast(r.error||'Failed','error');},
    async loadBunnyStats(){if(!this.bunny.selZone)return;const r=await get('/api/cdn/bunnycdn/stats/'+this.bunny.selZone);if(r.ok)this.bunny.stats=r;},
    async bunnyPurge(){const r=await post('/api/cdn/bunnycdn/purge/'+this.bunny.selZone,{url:this.bunny.purgeUrl});if(r.ok){toast(this.bunny.purgeUrl?'URL purged':'Zone purged!','success');this.bunny.purgeUrl='';}else toast('Failed','error');},
    async applyNginxHeaders(){if(!this.generic.domain){toast('Select a domain','error');return;}const r=await post('/api/cdn/nginx-headers',{domain:this.generic.domain,provider:this.selectedProvider.id});if(r.ok){toast('Cache headers applied!','success');this.generic.applyResult=r.snippet;}else toast(r.error||'Failed','error');},
    fmtBytes,
  };
}

// ── CADDY PAGE ────────────────────────────────────────────────────────────────
function caddyPage() {
  return {
    status:{installed:false,version:'',status:'inactive'},
    sites:[],webroot:'/www/wwwroot',
    showAdd:false,showCaddyfile:false,
    caddyfileContent:'',caddyfilePath:'/etc/caddy/Caddyfile',logContent:'',
    form:{domain:'',path:'',type:'static',php:'8.3',proxy_target:'',path_edited:false},
    drawerSite:null,drawerShow:false,drawerConf:'',
    async init(){await Promise.all([this.loadStatus(),this.loadSites()]);},
    async loadStatus(){const r=await get('/api/caddy/status');if(r.ok)this.status=r;},
    async loadSites(){const r=await get('/api/caddy/sites');if(r.ok){this.sites=r.sites;this.webroot=r.webroot||'/www/wwwroot';}},
    async create(){
      if(!this.form.domain){toast('Domain required','error');return;}
      const r=await post('/api/caddy/sites',this.form);
      if(r.ok){toast('Site created! '+(r.note||''),'success');this.showAdd=false;this.form={domain:'',path:'',type:'static',php:'8.3',proxy_target:'',path_edited:false};await this.loadSites();}
      else toast(r.error||'Failed','error');
    },
    async del(domain){if(!confirm('Delete site: '+domain+'?')) return;const r=await del('/api/caddy/sites/'+domain);if(r.ok){toast('Deleted','success');await this.loadSites();}},
    async openDrawer(s){this.drawerSite=s;this.drawerShow=true;const r=await get('/api/caddy/sites/'+s.domain+'/config');if(r.ok)this.drawerConf=r.content;},
    async saveDrawerConf(){const r=await put('/api/caddy/sites/'+this.drawerSite.domain+'/config',{content:this.drawerConf});toast(r.ok?'Saved':'Error: '+(r.error||''),r.ok?'success':'error');},
    async openCaddyfile(){const r=await get('/api/caddy/caddyfile');if(r.ok){this.caddyfileContent=r.content;this.caddyfilePath=r.path;this.showCaddyfile=true;}},
    async saveCaddyfile(){const r=await put('/api/caddy/caddyfile',{content:this.caddyfileContent});if(r.ok){toast('Saved & Caddy reloaded','success');this.showCaddyfile=false;await this.loadSites();}else toast('Error: '+(r.error||''),'error');},
    async control(action){const r=await post('/api/caddy/control',{action});if(r.ok){this.status.status=r.status;toast(action+' Caddy','success');}},
    async loadLogs(){const r=await get('/api/caddy/logs?lines=150');if(r.ok)this.logContent=r.logs;},
    async sslInfo(domain){const r=await get('/api/caddy/sites/'+domain+'/ssl');if(r.ok)toast(r.info||'Auto-provisioned','info');},
  };
}

// ── UPDATE MODAL ──────────────────────────────────────────────────────────────
function updateModalData() {
  return {
    checkState:'checking',updating:false,updateDone:false,updateSuccess:false,
    updateError:'',updateLines:[],updateProgress:0,_pollTimer:null,errorMsg:'',
    async init(){document.addEventListener('vortex-check-update',()=>this.checkForUpdates());await this.checkForUpdates();},
    async checkForUpdates(){
      this.checkState='checking'; this.updating=false; this.errorMsg='';
      try {
        const r = await get('/api/update/check');

        // Sync to parent panelApp
        try {
          const appEl = document.querySelector('[x-data="panelApp()"]');
          const app   = appEl ? Alpine.$data(appEl) : null;
          if (app) {
            app.updateModal.current   = r.current   || 'v3.0.0';
            app.updateModal.latest    = r.latest    || r.current || 'v3.0.0';
            app.updateModal.name      = r.name      || 'VortexPanel';
            app.updateModal.body      = r.body      || '';
            app.updateModal.published = r.published || '';
            if (r.has_update) app.updateAvailable = true;
          }
        } catch(e) {}

        // r.ok is always true from our backend (even on no-releases)
        // Only go to error state if there's an error AND no version info
        if (r.error && !r.current) {
          this.errorMsg = r.error;
          this.checkState = 'error';
          return;
        }

        // note = informational (e.g. "no releases yet") → show as up to date
        if (r.note || (!r.has_update && !r.error)) {
          this.checkState = 'uptodate';
          return;
        }

        this.checkState = r.has_update ? 'available' : 'uptodate';

      } catch(e) {
        this.errorMsg = 'Network error: ' + (e.message || 'Cannot reach server');
        this.checkState = 'error';
      }
    },
    async startUpdate(){
      try{const app=Alpine.$data(document.querySelector('[x-data^="panelApp"]')||document.body);var version=app?app.updateModal.latest:'';}catch{var version='';}
      this.updating=true;this.updateDone=false;this.updateSuccess=false;
      this.updateLines=['🚀 Starting update to '+version+'...'];this.updateProgress=5;
      const r=await post('/api/update/start',{version});
      if(!r.ok){this.updateLines.push('✗ Failed: '+(r.error||''));this.updateDone=true;this.updateSuccess=false;return;}
      this._pollTimer=setInterval(async()=>{
        try{
          const s=await get('/api/update/status');if(!s.ok)return;
          this.updateLines=s.lines||[];
          this.updateProgress=Math.min(90,5+(s.lines||[]).length*5);
          this.$nextTick(()=>{if(this.$refs.terminal)this.$refs.terminal.scrollTop=this.$refs.terminal.scrollHeight;});
          if(s.done){clearInterval(this._pollTimer);this.updateProgress=100;this.updateDone=true;this.updateSuccess=s.success;this.updateError=s.error||'';try{const app=Alpine.$data(document.querySelector('[x-data^="panelApp"]'));if(app&&s.success)app.updateAvailable=false;}catch{}}
        }catch{}
      },600);
    },
  };
}

// ── FILE MANAGER ──────────────────────────────────────────────────────────────
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
      const r = await get('/api/ai/config');
      if (r.ok) {
        this.configured = r.config.enabled && !!r.config.api_key;
        this.modelName  = r.config.model || 'NeonCodex';
        if (!r.config.api_key) {
          this.configured = false;
        }
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
        if (this.open) this.unread = 0;
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
