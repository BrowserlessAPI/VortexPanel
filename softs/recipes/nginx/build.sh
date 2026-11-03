# Nginx: the nginx.org package layout (conf.d, user nginx) that the panel already
# manages, built with every module the panel uses compiled in. The binary and its
# dynamic modules live under $PREFIX; /usr/sbin/nginx links to .../nginx/current.
cd "$SRC"
tar -xzf "$SOURCE_FILE"
cd nginx-"$VERSION" 2>/dev/null || cd nginx-release-"$VERSION"
CONF=./configure; [ -x "$CONF" ] || CONF=auto/configure
CUR=/usr/local/vortex/nginx/current

# ModSecurity connector as a dynamic module built against this exact nginx. It links
# libmodsecurity.so.3 with the run path of the VortexPanel library (softs app
# "libmodsecurity", installed by the ModSecurity WAF module), so no OS package is needed.
# The library is compiled here only to build against (same newest v3 release; soname 3).
MODSEC_NGINX_TAG=v1.0.4
MODSEC_RUNPATH=/usr/local/vortex/libmodsecurity/current/lib
# the libmodsecurity version published as stable for this system (resolve.py, from the
# catalog): the module never needs newer library symbols than servers have; else the newest tag
if [ -n "${VP_MODSEC_VERSION:-}" ]; then
  MS_TAG="v$VP_MODSEC_VERSION"
else
  MS_TAG="$(git ls-remote --tags --refs https://github.com/owasp-modsecurity/ModSecurity.git | sed 's|.*refs/tags/||' \
            | grep -E '^v3\.[0-9]+\.[0-9]+$' | sort -V | tail -1)"
fi
[ -n "$MS_TAG" ] || { echo "[build] cannot find a ModSecurity v3 release"; exit 3; }
curl -fsSL --retry 4 -o "$SRC/modsecurity.tgz" \
  "https://github.com/owasp-modsecurity/ModSecurity/releases/download/$MS_TAG/modsecurity-$MS_TAG.tar.gz"
mkdir -p "$SRC/ms-src" "$SRC/ms"
tar -xzf "$SRC/modsecurity.tgz" -C "$SRC/ms-src" --strip-components=1 --no-same-owner
( cd "$SRC/ms-src" && ./configure --prefix="$SRC/ms" --disable-static --disable-doxygen-doc --disable-examples \
    --with-pcre2 --without-lua --without-ssdeep --without-maxmind --without-geoip >/dev/null && make -j"$JOBS" >/dev/null && make install >/dev/null )
[ -e "$SRC/ms/lib/libmodsecurity.so.3" ] || { echo "[build] libmodsecurity did not build"; exit 3; }
git clone -q --depth 1 --branch "$MODSEC_NGINX_TAG" https://github.com/owasp-modsecurity/ModSecurity-nginx.git "$SRC/modsec-nginx"
# the connector's config adds a run path to the build folder: only the VortexPanel one may remain
sed -i -E 's#-Wl,-rpath[,=]\$\{?MODSECURITY_LIB\}? ?##g' "$SRC/modsec-nginx/config"
export MODSECURITY_INC="$SRC/ms/include" MODSECURITY_LIB="$SRC/ms/lib"
MODSEC="--add-dynamic-module=$SRC/modsec-nginx"

$CONF \
  --prefix=/etc/nginx \
  --sbin-path="$PREFIX/sbin/nginx" \
  --modules-path="$CUR/modules" \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/run/nginx.pid \
  --lock-path=/run/nginx.lock \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --user=nginx --group=nginx \
  --with-compat --with-file-aio --with-threads \
  --with-http_addition_module --with-http_auth_request_module --with-http_dav_module \
  --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module \
  --with-http_mp4_module --with-http_random_index_module --with-http_realip_module \
  --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module \
  --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-http_v3_module \
  --with-mail --with-mail_ssl_module \
  --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module \
  --with-cc-opt='-O2 -g -fstack-protector-strong -Wformat -Werror=format-security -fPIC -D_FORTIFY_SOURCE=2' \
  --with-ld-opt="-Wl,-z,relro -Wl,-z,now -pie -Wl,-rpath,$MODSEC_RUNPATH" \
  $MODSEC

make -j"$JOBS"
install -d "$DEST$PREFIX/sbin" "$DEST$PREFIX/modules" "$DEST$PREFIX/share"
install -m 0755 objs/nginx "$DEST$PREFIX/sbin/nginx"
for so in objs/*.so; do [ -e "$so" ] && install -m 0644 "$so" "$DEST$PREFIX/modules/"; done
[ -e "$DEST$PREFIX/modules/ngx_http_modsecurity_module.so" ] || { echo "[build] the ModSecurity module was not built"; exit 3; }
RP="$(readelf -d "$DEST$PREFIX/modules/ngx_http_modsecurity_module.so" | sed -n 's/.*(R\(UN\)\{0,1\}PATH).*\[\(.*\)\]/\2/p' | tr '\n' ':')"
[ "$RP" = "$MODSEC_RUNPATH:" ] || { echo "[build] the ModSecurity module run path is '$RP', expected only $MODSEC_RUNPATH"; exit 3; }
case "$(readelf -d "$DEST$PREFIX/sbin/nginx" | grep -E 'R(UN)?PATH')" in *"$SRC"*) echo "[build] nginx has a build-folder run path"; exit 3 ;; esac
printf 'nginx %s\nmodsecurity %s\nmodsecurity-nginx %s\n' "$VERSION" "${MS_TAG#v}" "$MODSEC_NGINX_TAG" > "$DEST$PREFIX/share/BUILDINFO"
# default configuration, copied to /etc/nginx only when the server has none
cp -r conf "$DEST$PREFIX/share/conf"
[ -d docs/html ] && cp -r docs/html "$DEST$PREFIX/share/html" || cp -r html "$DEST$PREFIX/share/html" 2>/dev/null || true
