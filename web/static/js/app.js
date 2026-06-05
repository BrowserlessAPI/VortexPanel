// VortexPanel frontend
// Alpine.js + vanilla JS, no build step required

const API = '';   // relative — works behind any proxy

// ── helpers ──────────────────────────────────────────────

async function request(method, path, data) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
    };

    const token = localStorage.getItem('vp_token');
    if (token) opts.headers['Authorization'] = `Bearer ${token}`;

    if (data !== undefined) opts.body = JSON.stringify(data);

    const res = await fetch(API + path, opts);

    const json = await res.json().catch(() => ({}));

    if (res.status === 401) {
        // on login page just throw the error, don't redirect
        if (window.location.pathname !== '/login') {
            localStorage.removeItem('vp_token');
            localStorage.removeItem('vp_user');
            window.location.href = '/login';
            return;
        }
    }

    if (!res.ok) throw new Error(json.detail || json.error || `HTTP ${res.status}`);
    return json;
}

const api = {
    get:    (path)       => request('GET',    path),
    post:   (path, data) => request('POST',   path, data),
    put:    (path, data) => request('PUT',    path, data),
    patch:  (path, data) => request('PATCH',  path, data),
    delete: (path)       => request('DELETE', path),
};

function fmtBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function fmtUptime(secs) {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function toast(msg, type = 'ok') {
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = msg;
    document.getElementById('toasts').appendChild(el);
    setTimeout(() => el.classList.add('show'), 10);
    setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 3000);
}


// ── App root ──────────────────────────────────────────────

document.addEventListener('alpine:init', () => {

    // ── Login ─────────────────────────────────────────────
    Alpine.data('login', () => ({
        username: '',
        password: '',
        show_pw: false,
        loading: false,
        error: '',

        async submit() {
            this.error = '';
            this.loading = true;
            try {
                const r = await api.post('/api/auth/login', {
                    username: this.username,
                    password: this.password,
                });
                localStorage.setItem('vp_token', r.token);
                localStorage.setItem('vp_user', JSON.stringify(r.user));

                const from = new URLSearchParams(window.location.search).get('from') || '/dashboard';
                window.location.href = from;
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        }
    }));


    // ── Shell (authenticated layout) ──────────────────────
    Alpine.data('shell', () => ({
        user:    JSON.parse(localStorage.getItem('vp_user') || 'null'),
        page:    '',
        loading: false,
        menu_open: false,
        theme:   localStorage.getItem('vp_theme') || 'blue',

        nav: [
            { group: 'Overview', items: [
                { id: 'dashboard',  icon: '▦', label: 'Dashboard'      },
                { id: 'websites',   icon: '🌐', label: 'Websites'       },
                { id: 'databases',  icon: '🗄', label: 'Databases'      },
                { id: 'files',      icon: '📁', label: 'File Manager'   },
                { id: 'php',        icon: '🐘', label: 'PHP Extensions' },
            ]},
            { group: 'Server', items: [
                { id: 'services',   icon: '⚙', label: 'Services'       },
                { id: 'modules',    icon: '📦', label: 'Modules'        },
                { id: 'docker',     icon: '🐳', label: 'Docker'         },
                { id: 'firewall',   icon: '🛡', label: 'Firewall'       },
                { id: 'terminal',   icon: '💻', label: 'Terminal'       },
                { id: 'backups',    icon: '💾', label: 'Backups'        },
            ]},
            { group: 'Network', items: [
                { id: 'dns',        icon: '🌍', label: 'DNS Manager'    },
                { id: 'mail',       icon: '📧', label: 'Mail Server'    },
                { id: 'ftp',        icon: '📂', label: 'FTP / SFTP'     },
            ]},
            { group: 'System', items: [
                { id: 'cron',       icon: '⏱', label: 'Cron Jobs'      },
                { id: 'monitoring', icon: '📊', label: 'Monitoring'     },
                { id: 'settings',   icon: '⚙', label: 'Settings'       },
            ]},
        ],

        get page_title() {
            for (const g of this.nav) {
                const item = g.items.find(i => i.id === this.page);
                if (item) return item.label;
            }
            return 'VortexPanel';
        },

        init() {
            if (!this.user) { window.location.href = '/login'; return; }

            // apply theme
            document.documentElement.setAttribute('data-theme', this.theme);

            // route from hash
            const go = () => {
                this.page = window.location.hash.slice(1) || 'dashboard';
            };
            window.addEventListener('hashchange', go);
            go();
        },

        navigate(id) {
            window.location.hash = id;
        },

        setTheme(t) {
            this.theme = t;
            localStorage.setItem('vp_theme', t);
            document.documentElement.setAttribute('data-theme', t);
        },

        async logout() {
            await api.post('/api/auth/logout').catch(() => {});
            localStorage.removeItem('vp_token');
            localStorage.removeItem('vp_user');
            window.location.href = '/login';
        }
    }));


    // ── Dashboard ─────────────────────────────────────────
    Alpine.data('dashboard', () => ({
        metrics: null,
        sysinfo: null,
        services: [],
        history: [],
        loading: true,

        async init() {
            await this.refresh();
            setInterval(() => this.refresh_metrics(), 5000);
        },

        async refresh() {
            this.loading = true;
            try {
                [this.metrics, this.sysinfo, this.services] = await Promise.all([
                    api.get('/api/system/metrics'),
                    api.get('/api/system/info'),
                    api.get('/api/services'),
                ]);
            } catch (e) {
                toast('Failed to load metrics', 'danger');
            } finally {
                this.loading = false;
            }
        },

        async refresh_metrics() {
            try {
                this.metrics = await api.get('/api/system/metrics');
            } catch (e) {}
        },

        get cpu()  { return this.metrics?.cpu?.percent ?? 0; },
        get ram()  { return this.metrics?.memory?.percent ?? 0; },
        get disk() { return this.metrics?.disk?.percent ?? 0; },

        get ram_used()  { return fmtBytes(this.metrics?.memory?.used); },
        get ram_total() { return fmtBytes(this.metrics?.memory?.total); },
        get disk_used() { return fmtBytes(this.metrics?.disk?.used); },
        get disk_total(){ return fmtBytes(this.metrics?.disk?.total); },
        get uptime()    { return this.metrics?.uptime ? fmtUptime(this.metrics.uptime) : '--'; },

        running_count() {
            return this.services.filter(s => s.active).length;
        }
    }));


    // ── Services ──────────────────────────────────────────
    Alpine.data('services', () => ({
        list: [],
        loading: true,
        acting: null,

        async init() {
            await this.load();
        },

        async load() {
            this.loading = true;
            this.list = await api.get('/api/services').catch(() => []);
            this.loading = false;
        },

        async action(name, act) {
            this.acting = name + act;
            try {
                await api.post(`/api/services/${name}/${act}`);
                toast(`${name} ${act}ed`, 'ok');
                await this.load();
            } catch (e) {
                toast(e.message, 'danger');
            } finally {
                this.acting = null;
            }
        }
    }));

});


// ── Websites ──────────────────────────────────────────────
document.addEventListener('alpine:init', () => {

Alpine.data('websites', () => ({
    list: [], loading: true, show_add: false, adding: false,
    add_tab: 'Create site',
    form: { domain: '', path: '', php: '8.3', type: 'php', create_db: false, create_ftp: false, batch_domains: '' },
    php_versions: ['8.3','8.2','8.1','8.0','7.4'],
    active_site: null,
    site_tab: 'domain',
    site_config: '',
    site_tabs: [
        { id: 'domain',   icon: '🌐', label: 'Domain Manager' },
        { id: 'dir',      icon: '📁', label: 'Directory'      },
        { id: 'ssl',      icon: '🔒', label: 'SSL'            },
        { id: 'config',   icon: '⚙', label: 'Config'         },
        { id: 'rewrite',  icon: '↩', label: 'URL Rewrite'    },
        { id: 'redirect', icon: '↗', label: 'Redirect'       },
        { id: 'proxy',    icon: '🔀', label: 'Reverse Proxy'  },
    ],

    async init() { await this.load(); },

    async load() {
        this.loading = true;
        this.list = await api.get('/api/websites').catch(() => []);
        this.loading = false;
    },

    async add() {
        if (!this.form.domain && !this.form.batch_domains) return;
        this.adding = true;
        try {
            await api.post('/api/websites', this.form);
            toast('Website created', 'ok');
            this.show_add = false;
            this.form = { domain: '', path: '', php: '8.3', type: 'php', create_db: false, create_ftp: false };
            await this.load();
        } catch(e) { toast(e.message, 'danger'); }
        this.adding = false;
    },

    async open_site(s) {
        this.active_site = s;
        this.site_tab = 'domain';
        const r = await api.get(`/api/websites/${s.domain}/config`).catch(() => ({ content: '' }));
        this.site_config = r.content;
    },

    async save_config() {
        try {
            await api.put(`/api/websites/${this.active_site.domain}/config`, { content: this.site_config });
            toast('Config saved & Nginx reloaded', 'ok');
        } catch(e) { toast(e.message, 'danger'); }
    },

    async toggle(domain) {
        await api.post(`/api/websites/${domain}/toggle`).catch(e => toast(e.message,'danger'));
        await this.load();
    },

    async remove(domain) {
        if (!confirm(`Delete ${domain}? This will remove the Nginx config.`)) return;
        await api.delete(`/api/websites/${domain}`).catch(e => toast(e.message,'danger'));
        await this.load();
    }
}));


// ── File Manager ──────────────────────────────────────────
Alpine.data('filemanager', () => ({
    path: '/', files: [], loading: true,
    selected: null, content: '', editing: false,

    async init() { await this.ls('/'); },
    async ls(p) {
        this.loading = true; this.path = p;
        const r = await api.get(`/api/files/list?path=${encodeURIComponent(p)}`).catch(() => ({ items: [] }));
        this.files = r.items || [];
        this.loading = false;
    },
    async open(f) {
        if (f.is_dir) { await this.ls(f.path); return; }
        const r = await api.get(`/api/files/read?path=${encodeURIComponent(f.path)}`).catch(() => ({ content: '' }));
        this.selected = f; this.content = r.content; this.editing = true;
    },
    async save() {
        await api.put('/api/files/write', { path: this.selected.path, content: this.content });
        toast('File saved', 'ok'); this.editing = false;
    },
    up() {
        const parts = this.path.split('/').filter(Boolean);
        parts.pop();
        this.ls('/' + parts.join('/') || '/');
    }
}));


// ── Databases ─────────────────────────────────────────────
Alpine.data('databases', () => ({
    list: [], loading: true, show_add: false,
    form: { name: '', type: 'mysql', user: '', password: '' },

    async init() { await this.load(); },
    async load() {
        this.loading = true;
        this.list = await api.get('/api/databases').catch(() => []);
        this.loading = false;
    },
    async add() {
        try {
            await api.post('/api/databases', this.form);
            toast('Database created', 'ok');
            this.show_add = false;
            await this.load();
        } catch(e) { toast(e.message, 'danger'); }
    }
}));


// ── Modules ───────────────────────────────────────────────
Alpine.data('modules', () => ({
    catalog: [], installed: [], loading: true, filter: 'All', search: '',
    installing: null, log_lines: [],

    categories: ['All','Web Server','PHP','Database','Cache','Runtime','Security','Mail','FTP','DevOps'],

    async init() {
        this.loading = true;
        [this.catalog, this.installed] = await Promise.all([
            api.get('/api/modules/catalog').catch(() => []),
            api.get('/api/modules/installed').catch(() => []),
        ]);
        this.loading = false;
    },

    get filtered() {
        return this.catalog.filter(m => {
            const cat = this.filter === 'All' || m.category === this.filter;
            const q   = !this.search || m.name.toLowerCase().includes(this.search.toLowerCase());
            return cat && q;
        });
    },

    is_installed(id) { return this.installed.some(i => i.id === id && i.installed); },

    async install(id, name) {
        this.installing = id; this.log_lines = [];
        const es = new EventSource(`/api/modules/${id}/install?token=${localStorage.getItem('vp_token')}`);
        es.onmessage = e => {
            const d = JSON.parse(e.data);
            if (d.log) this.log_lines.push(d.log);
            if (d.done) { es.close(); this.installing = null; this.init(); }
        };
        es.onerror = () => { es.close(); this.installing = null; toast('Install failed','danger'); };
    }
}));


// ── Firewall ──────────────────────────────────────────────
Alpine.data('firewall', () => ({
    rules: [], status: {}, loading: true, show_add: false,
    form: { port: '', protocol: 'tcp', action: 'allow', comment: '' },

    async init() { await this.load(); },
    async load() {
        this.loading = true;
        [this.rules, this.status] = await Promise.all([
            api.get('/api/firewall/rules').catch(() => []),
            api.get('/api/firewall/status').catch(() => ({})),
        ]);
        this.loading = false;
    },
    async add() {
        try {
            await api.post('/api/firewall/rules', this.form);
            toast('Rule added', 'ok'); this.show_add = false; await this.load();
        } catch(e) { toast(e.message, 'danger'); }
    },
    async remove(id) {
        await api.delete(`/api/firewall/rules/${id}`).catch(e => toast(e.message,'danger'));
        await this.load();
    }
}));


// ── Cron Jobs ─────────────────────────────────────────────
Alpine.data('cron', () => ({
    jobs: [], loading: true, show_add: false,
    form: { name: '', schedule: '0 * * * *', command: '', enabled: true },
    presets: [
        { label: 'Every minute',  val: '* * * * *'   },
        { label: 'Every hour',    val: '0 * * * *'   },
        { label: 'Daily at 2am',  val: '0 2 * * *'   },
        { label: 'Weekly Sunday', val: '0 2 * * 0'   },
        { label: 'Monthly',       val: '0 2 1 * *'   },
    ],

    async init() { await this.load(); },
    async load() {
        this.loading = true;
        this.jobs = await api.get('/api/cron').catch(() => []);
        this.loading = false;
    },
    async add() {
        try {
            await api.post('/api/cron', this.form);
            toast('Cron job added', 'ok'); this.show_add = false; await this.load();
        } catch(e) { toast(e.message, 'danger'); }
    },
    async toggle(id) {
        await api.post(`/api/cron/${id}/toggle`).catch(e => toast(e.message,'danger'));
        await this.load();
    },
    async remove(id) {
        await api.delete(`/api/cron/${id}`).catch(e => toast(e.message,'danger'));
        await this.load();
    }
}));


// ── Settings ──────────────────────────────────────────────
Alpine.data('settings', () => ({
    cfg: {}, loading: true, saving: false, tab: 'panel',
    pw: { current: '', new_password: '', confirm: '' },

    async init() { await this.load(); },
    async load() {
        this.loading = true;
        this.cfg = await api.get('/api/settings').catch(() => ({}));
        this.loading = false;
    },
    async save() {
        this.saving = true;
        try {
            await api.post('/api/settings', this.cfg);
            toast('Settings saved', 'ok');
        } catch(e) { toast(e.message, 'danger'); }
        this.saving = false;
    },
    async change_password() {
        if (this.pw.new_password !== this.pw.confirm) { toast('Passwords do not match','danger'); return; }
        try {
            await api.post('/api/auth/change-password', { current: this.pw.current, new_password: this.pw.new_password });
            toast('Password changed', 'ok');
            this.pw = { current: '', new_password: '', confirm: '' };
        } catch(e) { toast(e.message, 'danger'); }
    }
}));


// ── Monitoring ────────────────────────────────────────────
Alpine.data('monitoring', () => ({
    metrics: null, history: [], processes: [], loading: true,

    async init() {
        await this.refresh();
        setInterval(() => this.refresh(), 5000);
    },
    async refresh() {
        [this.metrics, this.processes] = await Promise.all([
            api.get('/api/system/metrics').catch(() => null),
            api.get('/api/system/processes').catch(() => []),
        ]);
        if (this.metrics) {
            this.history.push({
                time: new Date().toLocaleTimeString('en',{hour:'2-digit',minute:'2-digit'}),
                cpu:  Math.round(this.metrics.cpu.percent),
                mem:  Math.round(this.metrics.memory.percent),
            });
            if (this.history.length > 20) this.history.shift();
        }
        this.loading = false;
    },
    bar(v, warn=70, danger=90) {
        return v > danger ? 'var(--danger)' : v > warn ? 'var(--warn)' : 'var(--ok)';
    }
}));

}); // end alpine:init
