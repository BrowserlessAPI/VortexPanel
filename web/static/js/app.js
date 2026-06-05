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

    if (res.status === 401) {
        localStorage.removeItem('vp_token');
        localStorage.removeItem('vp_user');
        window.location.href = '/login';
        return;
    }

    const json = await res.json().catch(() => ({}));
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
