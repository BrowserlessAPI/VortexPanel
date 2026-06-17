# Contributing to VortexPanel

First off, thanks for taking the time to contribute! 🎉

VortexPanel is built with Python/Flask backend and Alpine.js frontend. It's designed to be approachable — no Node.js build step, no complex toolchain. If you can run `python3 app.py`, you're ready to contribute.

---

## How to contribute

### Reporting a bug
- Check [existing issues](https://github.com/BrowserlessAPI/VortexPanel/issues) first
- Use the **Bug Report** issue template
- Include: OS and version, what you did, what happened, what you expected, any error messages from `/var/log/vortexpanel/error.log`

### Requesting a feature
- Use the **Feature Request** issue template
- Describe the use case, not just the implementation
- Check the [roadmap in the README](README.md#-roadmap) — if it's already listed, +1 the existing issue instead of opening a new one

### Submitting a pull request
1. Fork the repo and create a branch: `git checkout -b feature/your-feature-name`
2. Make your changes (see Code Style below)
3. Test on a real or virtual Linux system — the panel must start with `python3 app.py`
4. Open a PR against `main` — describe what you changed and why
5. Reference any related issues with `Closes #123`

---

## Development setup

```bash
git clone https://github.com/BrowserlessAPI/VortexPanel.git
cd VortexPanel
pip install -r requirements.txt
python3 app.py
```

Panel runs at `http://127.0.0.1:8888`. Admin password is printed on first run and saved to `admin_password.txt`.

---

## Code style

### Backend (Python)
- Python 3.8+ compatible
- Follow existing patterns in `panel/routes/` — each feature is a Flask Blueprint
- Shell commands via the existing `sh(cmd)` helper (returns stdout string) or `sh3(cmd)` (returns `stdout, stderr, returncode`)
- Every route must check `if not req(): return jsonify({'ok':False}), 401` first
- Multi-distro support via `get_os()` from `os_utils.py` — never hardcode `apt-get`; use `pkg_install()` instead
- Use `panel_cache.set(key, value, ttl)` for expensive read-only endpoints

### Frontend (Alpine.js + HTML)
- No npm, no build step — plain HTML/JS/CSS only
- New pages go in `web/templates/index.html` as `<div x-show="page==='yourpage'" x-data="yourPage()">`
- New Alpine components go in `web/static/js/app.js`
- Every page component's `init()` must include: `document.addEventListener('vortex-logged-in', () => { this.init(); });`
- Use existing CSS variables from `web/static/css/theme.css` — no hardcoded colors
- Use `.modal-overlay` class for modals/drawers (not inline `position:fixed` — causes stacking context issues)
- Avoid `x-show` with `overflow:hidden` parents — use `.modal-overlay` class which is defined at root level

### Adding a new module
1. Create `panel/routes/your_module.py` with a Blueprint
2. Import and register it in `app.py`
3. Add a nav item in `web/static/js/app.js` in the `navItems` array
4. Add the page HTML in `web/templates/index.html`
5. Add an `async init()` with the `vortex-logged-in` listener

---

## Areas where help is most welcome

- 🧪 **Testing** on RHEL-family distros (AlmaLinux, Rocky, Fedora, Oracle, CentOS Stream, CloudLinux) — firewalld path specifically
- 🌍 **Translations** — panel strings are in the HTML templates
- 📖 **Documentation** — setup guides, module how-tos, video walkthroughs
- 🐛 **Bug fixes** — especially on multi-distro edge cases

---

## Code of Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
