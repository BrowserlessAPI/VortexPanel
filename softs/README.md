# VortexPanel software builds

Server software for the App Store (web servers, databases, PHP, Node.js, Python,
Docker, Redis, Memcached, Supervisor, Fail2ban, ClamAV, BIND9, ddclient, Pure-FTPd,
Caddy WAF, ...) is built, tested and published by VortexPanel itself, and every
panel installs and updates it from the VortexPanel download server (Cloudflare R2)
instead of the OS package sources. Panel releases on GitHub only carry panel code.

```
 every 24 h        AI review          build              test                 publish             every panel (6 h)
 watch.py  ---->  ai_review.py ---->  build.py  ---->   test.py  ---------->  publish.py  ---->  panel/softs.py
 upstream         security, CVEs,     each OS + CPU     fresh container,     R2 + signed         "Update to vX",
 releases         breaking changes,   in a clean        the panel's own      catalog.json        auto security
                  release notes       container         engine + smoke test  (beta -> stable)    updates, rollback
```

## One-time setup

1. **Signing key** (on your own machine, once):

       pip install cryptography && python3 softs/pipeline/keygen.py

   It prints a secret key and a public key.

2. **Repository secrets** (GitHub > Settings > Secrets and variables > Actions > New repository secret):

   | Secret | Value |
   |---|---|
   | `R2_ACCOUNT_ID` | Cloudflare account ID (R2 overview page, right side) |
   | `R2_ACCESS_KEY_ID` | R2 API token: Access Key ID (Object Read & Write, this bucket only) |
   | `R2_SECRET_ACCESS_KEY` | R2 API token: Secret Access Key |
   | `R2_BUCKET` | bucket name |
   | `SOFTS_SIGNING_KEY` | the secret key from step 1 |
   | `CLAUDE_CODE_OAUTH_TOKEN` | AI review on your Claude subscription (Pro, Max, Team or Enterprise), no API billing: run `claude setup-token` on your computer and paste the token it prints (valid one year). The workflow runs the Claude Code GitHub Action as the reviewer. |
   | `ANTHROPIC_API_KEY` | instead: a Claude API key (or `AI_BASE_URL` + `AI_API_KEY` for any OpenAI-compatible API, e.g. NeonCodex; model in the variable `AI_MODEL`). With none of these, releases still go out; security is then detected from CVE ids in the changelog. |

   Keys go only into GitHub secrets: never into this repository or a chat.

3. **Panel trust file**: `panel/trust/softs.json`

       {"base_url": "https://<your R2 custom domain>", "keys": ["<public key from step 1>"]}

   Until both are set, the App Store keeps installing from the OS package sources.

4. **First run**: Actions > Software builds > Run workflow. The first run finds
   about 48 versions (every followed release line of 23 apps) and builds them over
   about four days (at most `SOFTS_MAX_BUILDS` versions per run, default 12).

Optional repository variables: `SOFTS_PROMOTE_HOURS` (beta to stable, default 24),
`SOFTS_KEEP_PER_TRACK` (default 3), `SOFTS_MAX_BUILDS` (default 12), `AI_MODEL`.

## Daily operation (nothing to do)

- New upstream release -> AI review -> builds for el8/el9/el10, Ubuntu 22.04/24.04,
  Debian 12/13 on x86_64 and ARM -> each build installed and smoke-tested on a fresh
  system -> uploaded and signed.
- Security releases go straight to **stable**; others start on **beta** and become
  stable after 24 hours.
- Panels check every 6 hours, show **Update to vX** in the App Store, send an alert,
  and install security updates automatically (Software updates > Automatic updates).
- A build that fails on some system is published for the systems that passed;
  the run is marked failed (GitHub e-mails you) and the missing systems are retried
  on the next three runs.
- The AI review can hold a release with a breaking change; it is then not published
  and listed in the run summary.
- **Mirrored tools** (`kind: "mirror"` recipes: phpMyAdmin, Adminer, Roundcube,
  Anubis, ffmpeg, OWASP CRS): `mirror.py` copies each new upstream release file to
  `pinned/<app>/<version>/` in R2 (checked against the upstream checksum when one is
  published) and lists it in the catalog. Panels install only these copies.
- **GitHub Releases copy** (`github_mirror.py`, last job of every run): every file in
  the catalog and the signed catalog itself are copied to the public repository
  `BrowserlessAPI/vortexpanel-softs` (repository variable `SOFTS_GITHUB_REPO`), one release
  per app version (`nginx-1.31.8`, files `<sha16>-<name>`) plus a `catalog` release. Panels
  download from R2 and fall back to these copies; they check every file against the signed
  catalog either way. Files the catalog no longer lists are removed. GitHub limits how fast
  files may be added, so the first copy takes a few daily runs.
  Setup: create the public repository with a README, then a fine-grained token with
  *Contents: read and write* on that repository only, saved as the secret
  `SOFTS_MIRROR_TOKEN`. Without the secret the step is skipped.
- **VortexPanel Apps** (System Hardening, PHP Security, ...) are not in this repository or
  in the public catalog. They are proprietary: source in the private repository
  `BrowserlessAPI/vortexpanel-apps`, which publishes the packages and a signed `index.json`
  to their own Cloudflare R2 bucket (the panel's `apps_url`). Panels download them straight
  from that bucket; they are never mirrored to GitHub.

## Manual controls (Actions > Software builds > Run workflow)

| Input | Effect |
|---|---|
| `only: nginx,php` | check only these apps |
| `force: nginx=1.31.9` | build exactly this version (also re-adds missing systems) |
| `withdraw: nginx=1.31.9` | hide a bad release; panels that installed it offer a rollback |
| `restore: nginx=1.31.9` | undo a withdraw |
| `promote_now: nginx=1.31.9` | move a beta release to stable now |

Forcing a version that is already published but whose recipe changed since (a fixed
service unit, a security patch) publishes it as a **build bump**: `clamav=1.5.4`
becomes `1.5.4.1`, built from the same upstream release, so servers already running
1.5.4 are offered the fix as a normal update.

## Adding software

`softs/recipes/<app>/`:

- `recipe.json` - upstream source (`watch`), tracks, build and runtime packages,
  OS packages it takes over (`replaces`), `universal` (one build for every Linux),
  `coexist` (several versions side by side, like PHP)
- `build.sh` - builds into `$DEST$PREFIX` inside the target container
- `scripts/install.sh activate.sh check.sh uninstall.sh` - system integration on the
  server; always point units and links at `$VP_CURRENT`, never at `$VP_PREFIX`
- `smoke.sh` - the container test after install
- databases also have `scripts/preupdate.sh` (copy the data folder, `data_backup`) and
  `scripts/postfail.sh` (put it back, `data_restore`); see `pipeline/lib.sh`
- `patches/<upstream version>/*.patch` (PHP) - security patches the upstream project
  published as source only (PHP's PHP2Shell backport for 8.1.34). Each must apply with
  no fuzz; the build records them in `share/conf/vp-patches.txt`
- PHP's PECL extensions (igbinary, apcu, redis, imagick, memcached): pinned PECL
  releases with SHA-256 for PHP 8.1 to 8.5; for PHP 8.6, whose extension API changed,
  exact upstream commits with PHP 8.6 support (`PECL_GIT` in `build.sh`, checked by
  commit id) until releases with it are out. igbinary, apcu and redis must build or the
  PHP build fails; every extension a build lists in `share/conf/pecl.txt` must load in
  the smoke test

On a server every version lives in `/usr/local/vortex/<app>/<version>`, and
`/usr/local/vortex/<app>/current` (or `/<track>`) points at the one in use. An update
that does not start or fails its check is switched back automatically.

## Zip format

    manifest.json     app, version, track, target, arch, prefix, runtime packages (detected
                      from the binaries at build time), replaces, payload sha256
    payload.tar.xz    files under the prefix
    scripts/          install.sh activate.sh check.sh uninstall.sh lib.sh
