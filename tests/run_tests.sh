#!/bin/sh
# run_tests.sh — unit tests + end-to-end tests on local mirrors.
#
# Covers:
#   * codec core unit vectors (sha/crc/gzip/json) + dep-resolver v2 unit
#   * ed25519 RFC 8032 vectors + signify blob round-trips
#   * e2e phase 1: update/install/list/reinstall/remove lifecycle
#   * e2e phase 2: dep-resolution v2 (auto pull-in, plan, missing deps,
#                  --no-deps, reverse-dep warning on remove)
#   * e2e phase 3: symlink policy (deny / keep / cleanup)
#   * e2e phase 4: download resume (server that kills the connection
#                  mid-transfer, then a proper Range server)
#   * e2e phase 5: upgrade (v2 resolver + world file)
#   * e2e phase 6: genesis bootstrap (install --root into a clean image)
#   * e2e phase 7: epkg audit — index signatures (signify/ed25519):
#                  signed update OK, tampered index rejected (strict),
#                  audit=warn, missing .sig rejected, epkg audit cached,
#                  tampered cache detected, wrong pubkey rejected
set -e
cd "$(dirname "$0")/.."

echo "== build =="
make >/dev/null

echo "== unit: codec core (sha/crc/gzip/json/deps/ed25519/signify) =="
${CC:-cc} -std=c99 -Wall -O1 -Iinclude -Isrc -o /tmp/epkg_t_core \
    tests/t_core.c src/epk_sha256.c src/epk_crc32.c src/epk_inflate.c \
    src/epk_gzc.c src/epk_json.c src/epk_index.c src/epk_deps.c \
    src/epk_db.c src/epk_util.c src/epk_ed25519.c src/epk_signify.c \
    src/epk_port_posix.c
/tmp/epkg_t_core | tail -1

echo "== unit: ed25519 RFC 8032 vectors =="
${CC:-cc} -std=c99 -Wall -O1 -Iinclude -Isrc -o /tmp/epkg_t_ed \
    tests/t_ed25519.c src/epk_ed25519.c src/epk_sha256.c
/tmp/epkg_t_ed | tail -1

WORK=$(mktemp -d)
MIRROR="$WORK/mirror"
mkdir -p "$MIRROR/packages"

# ---------- packages ----------
# 1) hello: plain single-file package
PKG="$WORK/hello"
mkdir -p "$PKG/usr/bin"
{
    echo "pkgname = hello"
    echo "pkgver = 1.0-r0"
    echo "pkgdesc = e2e test package"
    echo "deps ="
} > "$PKG/PKGINFO"
printf '#!/bin/sh\necho hi\n' > "$PKG/usr/bin/hello"
./mkepkg "$PKG" "$MIRROR/packages/hello-1.0-r0.epkg" >/dev/null

# 2) dep chain: libbar <- libfoo <- app (with a version constraint)
PKG="$WORK/libbar"
mkdir -p "$PKG/usr/lib"
echo "bar lib" > "$PKG/usr/lib/libbar.so"
{
    echo "pkgname = libbar"
    echo "pkgver = 1.0-r0"
    echo "pkgdesc = bottom of the dep chain"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/libbar-1.0-r0.epkg" >/dev/null

PKG="$WORK/libfoo"
mkdir -p "$PKG/usr/lib"
echo "foo lib" > "$PKG/usr/lib/libfoo.so"
{
    echo "pkgname = libfoo"
    echo "pkgver = 1.1-r0"
    echo "pkgdesc = middle of the dep chain"
    echo "deps = libbar"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/libfoo-1.1-r0.epkg" >/dev/null

PKG="$WORK/app"
mkdir -p "$PKG/usr/bin"
printf '#!/bin/sh\necho app\n' > "$PKG/usr/bin/app"
{
    echo "pkgname = app"
    echo "pkgver = 2.0-r0"
    echo "pkgdesc = depends on libfoo (with constraint)"
    echo "deps = libfoo >= 1.0"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/app-2.0-r0.epkg" >/dev/null

# 3) broken: depends on a package that does not exist
PKG="$WORK/broken"
mkdir -p "$PKG/etc"
echo x > "$PKG/etc/broken.conf"
{
    echo "pkgname = broken"
    echo "pkgver = 1.0-r0"
    echo "pkgdesc = has a missing dependency"
    echo "deps = ghost"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/broken-1.0-r0.epkg" >/dev/null

# 4) links: file + symlink (symlink policy test)
PKG="$WORK/links"
mkdir -p "$PKG/usr/bin"
echo "real content" > "$PKG/usr/bin/real"
ln -s real "$PKG/usr/bin/quick"
{
    echo "pkgname = links"
    echo "pkgver = 1.0-r0"
    echo "pkgdesc = symlink policy test"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/links-1.0-r0.epkg" >/dev/null

# 5) bigdata: ~200 KB uncompressible payload (resume test)
PKG="$WORK/bigdata"
mkdir -p "$PKG/usr/share"
head -c 200000 /dev/urandom > "$PKG/usr/share/big.bin"
{
    echo "pkgname = bigdata"
    echo "pkgver = 3.0-r0"
    echo "pkgdesc = big package for the resume test"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/bigdata-3.0-r0.epkg" >/dev/null

# 6) upgrade wave: newer hello / libfoo / app (excluded from index #1)
PKG="$WORK/hello2"
mkdir -p "$PKG/usr/bin"
printf '#!/bin/sh\necho "Hello v2 from epkg!"\n' > "$PKG/usr/bin/hello"
chmod +x "$PKG/usr/bin/hello"
{
    echo "pkgname = hello"
    echo "pkgver = 1.1-r0"
    echo "pkgdesc = e2e test package, second release"
    echo "deps ="
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/hello-1.1-r0.epkg" >/dev/null

PKG="$WORK/libfoo2"
mkdir -p "$PKG/usr/lib"
echo "foo lib v2" > "$PKG/usr/lib/libfoo.so"
{
    echo "pkgname = libfoo"
    echo "pkgver = 1.2-r0"
    echo "pkgdesc = middle of the dep chain, newer"
    echo "deps = libbar"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/libfoo-1.2-r0.epkg" >/dev/null

PKG="$WORK/app2"
mkdir -p "$PKG/usr/bin"
printf '#!/bin/sh\necho "app v2"\n' > "$PKG/usr/bin/app"
{
    echo "pkgname = app"
    echo "pkgver = 2.1-r0"
    echo "pkgdesc = depends on libfoo (newer constraint)"
    echo "deps = libfoo >= 1.2"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/app-2.1-r0.epkg" >/dev/null

# 7) conflicting future app: needs a libfoo the repo will never have
PKG="$WORK/app9"
mkdir -p "$PKG/usr/bin"
echo "future app" > "$PKG/usr/bin/app9"
{
    echo "pkgname = app9"
    echo "pkgver = 1.0-r0"
    echo "pkgdesc = needs an impossible libfoo"
    echo "deps = libfoo >= 99"
} > "$PKG/PKGINFO"
./mkepkg "$PKG" "$MIRROR/packages/app9-1.0-r0.epkg" >/dev/null

# ---------- index.json generator (reads PKGINFO from every .epkg) ----------
cat > "$WORK/gen_index.py" <<'PYEOF'
import hashlib, json, os, sys, tarfile
repo = sys.argv[1]
exclude = set(sys.argv[2:])
pkgs = {}
pdir = os.path.join(repo, "packages")
def vkey(v):
    out, num = [], ""
    for ch in v:
        if ch.isdigit():
            num += ch
        else:
            if num: out.append((0, int(num))); num = ""
            out.append((1, ch))
    if num: out.append((0, int(num)))
    return out
for fn in sorted(os.listdir(pdir)):
    if not fn.endswith(".epkg") or fn in exclude:
        continue
    path = os.path.join(pdir, fn)
    data = open(path, "rb").read()
    t = tarfile.open(path)
    pi = {}
    for line in t.extractfile("PKGINFO").read().decode().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            pi[k.strip()] = v.strip()
    name = pi["pkgname"]
    ent = {"pkgname": name, "pkgver": pi["pkgver"],
           "pkgdesc": pi.get("pkgdesc", ""), "arch": "any",
           "filename": fn, "sha256": hashlib.sha256(data).hexdigest(),
           "size": len(data),
           "deps": [d.strip() for d in pi.get("deps", "").split(",") if d.strip()]}
    if name not in pkgs or vkey(ent["pkgver"]) > vkey(pkgs[name]["pkgver"]):
        pkgs[name] = ent
json.dump({"epkg_index": 1, "packages": list(pkgs.values())},
          open(os.path.join(repo, "index.json"), "w"))
print("index.json:", len(pkgs), "packages")
PYEOF

# index #1: only the initial wave (upgrade candidates hidden)
python3 "$WORK/gen_index.py" "$MIRROR" \
    hello-1.1-r0.epkg libfoo-1.2-r0.epkg app-2.1-r0.epkg app9-1.0-r0.epkg >/dev/null

# ---------- range-capable normal server ----------
cat > "$WORK/full_server.py" <<'PYEOF'
import http.server, os, sys
repo, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = os.path.join(repo, self.path.lstrip('/').split('?')[0])
        if not os.path.exists(path):
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        data = open(path, 'rb').read()
        size = len(data)
        start = 0
        rng = self.headers.get('Range')
        if rng and rng.startswith('bytes='):
            try:
                start = int(rng.split('=')[1].split('-')[0])
            except ValueError:
                start = 0
        if start > 0:
            self.send_response(206)
            self.send_header('Content-Range',
                             'bytes %d-%d/%d' % (start, size - 1, size))
        else:
            self.send_response(200)
        self.send_header('Content-Length', str(size - start))
        self.end_headers()
        self.wfile.write(data[start:])
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

# ---------- evil server: kills the connection mid-transfer ----------
cat > "$WORK/abort_server.py" <<'PYEOF'
import http.server, os, sys
repo, port = sys.argv[1], int(sys.argv[2])
SLICE = 30000            # bytes delivered per connection, then abort
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = os.path.join(repo, self.path.lstrip('/').split('?')[0])
        if '/packages/' in self.path and os.path.exists(path):
            data = open(path, 'rb').read()
            size = len(data)
            start = 0
            rng = self.headers.get('Range')
            partial = False
            if rng and rng.startswith('bytes='):
                try:
                    start = int(rng.split('=')[1].split('-')[0])
                    partial = True
                except ValueError:
                    pass
            end = min(start + SLICE, size)
            if partial:
                self.send_response(206)
                self.send_header('Content-Range',
                                 'bytes %d-%d/%d' % (start, end - 1, size))
            else:
                self.send_response(200)
            self.send_header('Content-Length', str(size - start))  # lie
            self.end_headers()
            try:
                self.wfile.write(data[start:end])
                self.wfile.flush()
            except Exception:
                pass
            self.connection.close()      # abrupt: client sees EOF
        else:                            # small files: serve normally
            if not os.path.exists(path):
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            data = open(path, 'rb').read()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PYEOF

PORT=8902
cat > "$WORK/epkg.conf" <<EOF
mirror = http://127.0.0.1:$PORT
db = $WORK/db
cache = $WORK/cache
root = $WORK/root/
EOF
export EPKG_CONF="$WORK/epkg.conf"

start_full()   { (cd "$MIRROR" && python3 "$WORK/full_server.py"  "$MIRROR" "$PORT" >/dev/null 2>&1 &); sleep 1; }
start_abort()  { (cd "$MIRROR" && python3 "$WORK/abort_server.py" "$MIRROR" "$PORT" >/dev/null 2>&1 &); sleep 1; }
stop_server()  { pkill -f "server.py $MIRROR $PORT" >/dev/null 2>&1 || pkill -f "_server.py $MIRROR $PORT" >/dev/null 2>&1 || true; sleep 1; }

# =================================================================
echo "== e2e 1: lifecycle =="
start_full
./epkg update >/dev/null && echo "step update OK"
./epkg install hello >/dev/null && echo "step install OK"
test -f "$WORK/root/usr/bin/hello" && echo "step file-exists OK"
./epkg list 2>&1 | grep -q hello && echo "step list OK"
./epkg install hello 2>&1 | grep -q "already installed" && echo "step reinstall OK"
./epkg remove hello >/dev/null && echo "step remove OK"
test ! -f "$WORK/root/usr/bin/hello" && echo "step gone OK"
./epkg list 2>&1 | grep -q "no packages installed" && echo "step empty-list OK"

# =================================================================
echo "== e2e 2: dep-resolution v2 =="
./epkg install app > "$WORK/app.out" 2>&1 && echo "step dep-install OK"
grep -q "plan (3)" "$WORK/app.out" && echo "step plan-printed OK"
test -f "$WORK/root/usr/lib/libbar.so" && echo "step dep-deep OK"
test -f "$WORK/root/usr/lib/libfoo.so" && echo "step dep-mid OK"
test -f "$WORK/root/usr/bin/app" && echo "step dep-root OK"
./epkg deps app 2>&1 | grep -q libbar && echo "step deps-cmd OK"
./epkg remove libbar > "$WORK/rm.out" 2>&1 && echo "step dep-remove OK"
grep -q "libfoo-1.1-r0 depends on libbar" "$WORK/rm.out" \
    && echo "step reverse-dep-warn OK"

if ./epkg install broken >/dev/null 2>&1; then
    echo "step missing-dep FAIL"; exit 1
else
    echo "step missing-dep rejected OK"
fi
./epkg install broken --no-deps >/dev/null 2>&1 && echo "step no-deps OK"
./epkg remove broken >/dev/null
./epkg remove libfoo app >/dev/null

# =================================================================
echo "== e2e 3: symlink policy =="
./epkg install links >/dev/null 2>&1
test -f "$WORK/root/usr/bin/real" && echo "step links-file OK"
test ! -e "$WORK/root/usr/bin/quick" && echo "step symlink-deny OK"
./epkg remove links >/dev/null
EPKG_SYMLINKS=keep ./epkg install links >/dev/null 2>&1
test -L "$WORK/root/usr/bin/quick" && echo "step symlink-keep OK"
test "$(readlink "$WORK/root/usr/bin/quick")" = "real" \
    && echo "step symlink-target OK"
./epkg remove links >/dev/null
test ! -e "$WORK/root/usr/bin/quick" && echo "step symlink-remove OK"

stop_server

# =================================================================
echo "== e2e 4: download resume =="
start_abort
./epkg update >/dev/null && echo "step resume-update OK"
if ./epkg install bigdata > "$WORK/res1.out" 2>&1; then
    echo "step resume-abort FAIL (should not complete)"; exit 1
else
    echo "step resume-abort detected OK"
fi
grep -q "will resume" "$WORK/res1.out" && echo "step resume-msg OK"
test -s "$WORK/cache/bigdata-3.0-r0.epkg.part" \
    && echo "step resume-part-kept OK"
stop_server

start_full
./epkg install bigdata > "$WORK/res2.out" 2>&1 && echo "step resume-finish OK"
grep -q "resuming at" "$WORK/res2.out" && echo "step resume-continued OK"
cmp -s "$WORK/bigdata/usr/share/big.bin" "$WORK/root/usr/share/big.bin" \
    && echo "step resume-content OK"
test ! -e "$WORK/cache/bigdata-3.0-r0.epkg.part" \
    && echo "step resume-part-cleaned OK"
./epkg remove bigdata >/dev/null
stop_server

# =================================================================
echo "== e2e 5: upgrade (v2 resolver + world file) =="
start_full
./epkg update >/dev/null && echo "step upd5-update OK"
./epkg install app >/dev/null 2>&1 && echo "step upd5-install OK"
grep -qx app "$WORK/db/world" && echo "step upd5-world OK"
if grep -qx libbar "$WORK/db/world"; then
    echo "step upd5-world-clean FAIL (deps leaked into world)"; exit 1
else
    echo "step upd5-world-clean OK"
fi
./epkg upgrade 2>&1 | grep -q "(nothing to do)" && echo "step upd5-nothing OK"

# --- repo publishes the newer wave: regenerate the index ---
python3 "$WORK/gen_index.py" "$MIRROR" >/dev/null
./epkg update >/dev/null
./epkg upgrade > "$WORK/up.out" 2>&1 && echo "step upd5-upgrade OK"
grep -q "upgrading libfoo 1.1-r0 -> 1.2-r0" "$WORK/up.out" \
    && echo "step upd5-chain-dep OK"
grep -q "upgrading app 2.0-r0 -> 2.1-r0" "$WORK/up.out" \
    && echo "step upd5-chain-root OK"
grep -q "foo lib v2" "$WORK/root/usr/lib/libfoo.so" \
    && echo "step upd5-new-content OK"
./epkg list 2>&1 | grep -q "2.1-r0.*\[world\]" && echo "step upd5-list-world OK"

if ./epkg upgrade ghostpkg >/dev/null 2>&1; then
    echo "step upd5-missing FAIL"; exit 1
else
    echo "step upd5-missing rejected OK"
fi
if ./epkg install app9 >/dev/null 2>&1; then
    echo "step upd5-conflict FAIL"; exit 1
else
    echo "step upd5-conflict rejected OK"
fi

./epkg upgrade hello >/dev/null 2>&1 && echo "step upd5-explicit OK"
test -f "$WORK/root/usr/bin/hello" && echo "step upd5-explicit-file OK"
grep -qx hello "$WORK/db/world" && echo "step upd5-explicit-world OK"

# =================================================================
echo "== e2e 6: genesis bootstrap (install --root into a clean image) =="
GEN="$WORK/genesis"
cat > "$WORK/genesis.conf" <<EOF
mirror = http://127.0.0.1:$PORT
EOF
EPKG_CONF="$WORK/genesis.conf" \
    ./epkg install --root "$GEN" hello > "$WORK/gen.out" 2>&1 \
    && echo "step genesis-install OK"
test -f "$GEN/usr/bin/hello" && echo "step genesis-file OK"
test -f "$GEN/var/lib/epkg/installed/hello" && echo "step genesis-db OK"
test -f "$GEN/var/cache/epkg/hello-1.1-r0.epkg" && echo "step genesis-cache OK"
grep -qx hello "$GEN/var/lib/epkg/world" && echo "step genesis-world OK"
grep -q "genesis:" "$WORK/gen.out" && echo "step genesis-hint OK"
EPKG_CONF="$WORK/genesis.conf" ./epkg list --root "$GEN" 2>&1 | grep -q hello \
    && echo "step genesis-list OK"
EPKG_CONF="$WORK/genesis.conf" ./epkg upgrade --root "$GEN" >/dev/null 2>&1 \
    && echo "step genesis-upgrade OK"
EPKG_CONF="$WORK/genesis.conf" ./epkg remove --root "$GEN" hello >/dev/null 2>&1 \
    && echo "step genesis-remove OK"
test ! -e "$GEN/usr/bin/hello" && echo "step genesis-gone OK"
test ! -e "$GEN/var/lib/epkg/installed/hello" && echo "step genesis-db-clean OK"

stop_server

# =================================================================
echo "== e2e 7: epkg audit (signify/ed25519 index signatures) =="
start_full

cat > "$WORK/audit.conf" <<EOF
mirror = http://127.0.0.1:$PORT
db = $WORK/adb
cache = $WORK/acache
root = $WORK/aroot/
pubkey = $WORK/repokey.pub
EOF

./epkg-key gen -c "e2e repo key" "$WORK/repokey" >/dev/null
./epkg-key sign -s "$WORK/repokey" -m "$MIRROR/index.json" \
    -x "$MIRROR/index.sig" >/dev/null

export EPKG_CONF="$WORK/audit.conf"
./epkg update > "$WORK/aud.out" 2>&1 && echo "step audit-update OK"
grep -q "index signature ok" "$WORK/aud.out" && echo "step audit-sig-ok OK"
./epkg install hello >/dev/null 2>&1 && echo "step audit-install OK"
./epkg audit 2>&1 | grep -q "VALID" && echo "step audit-cached OK"

# tampered index on the mirror must be rejected in strict mode
# (tamper keeps the JSON valid, so the signature check is what fails)
cp "$MIRROR/index.json" "$WORK/index.bak"
sed -i 's/e2e test package/tampered package/' "$MIRROR/index.json"
if ./epkg update > "$WORK/aud2.out" 2>&1; then
    echo "step audit-tamper FAIL (accepted a tampered index)"; exit 1
else
    echo "step audit-tamper rejected OK"
fi
if grep -q "index signature INVALID" "$WORK/aud2.out"; then
    echo "step audit-tamper-msg OK"
else
    echo "step audit-tamper-msg FAIL (no signature error)"; exit 1
fi

# audit=warn accepts the same tampered index with a warning
EPKG_AUDIT=warn ./epkg update > "$WORK/audw.out" 2>&1 \
    && echo "step audit-warn-accept OK"
if grep -q "WARNING: index signature INVALID" "$WORK/audw.out"; then
    echo "step audit-warn-msg OK"
else
    echo "step audit-warn-msg FAIL"; exit 1
fi

# restore a clean index and re-audit
cp "$WORK/index.bak" "$MIRROR/index.json"
./epkg update >/dev/null 2>&1 && echo "step audit-recover OK"

# missing index.sig is rejected in strict mode
mv "$MIRROR/index.sig" "$WORK/index.sig.bak"
if ./epkg update >/dev/null 2>&1; then
    echo "step audit-nosig FAIL (accepted an unsigned index)"; exit 1
else
    echo "step audit-nosig rejected OK"
fi
mv "$WORK/index.sig.bak" "$MIRROR/index.sig"

# tampered cached index must fail 'epkg audit'
cp "$WORK/adb/index.json" "$WORK/index.cache.bak"
echo '{"evil":1}' >> "$WORK/adb/index.json"
if ./epkg audit >/dev/null 2>&1; then
    echo "step audit-cache-tamper FAIL"; exit 1
else
    echo "step audit-cache-tamper rejected OK"
fi
cp "$WORK/index.cache.bak" "$WORK/adb/index.json"
./epkg audit >/dev/null 2>&1 && echo "step audit-cache-recover OK"

# wrong pubkey must be rejected
./epkg-key gen -c "other key" "$WORK/otherkey" >/dev/null
sed "s|$WORK/repokey.pub|$WORK/otherkey.pub|" "$WORK/audit.conf" \
    > "$WORK/audit2.conf"
if EPKG_CONF="$WORK/audit2.conf" ./epkg audit >/dev/null 2>&1; then
    echo "step audit-wrongkey FAIL"; exit 1
else
    echo "step audit-wrongkey rejected OK"
fi

# keynum check: epkg-key fp prints the same keynum the index was signed with
if ./epkg-key fp -p "$WORK/repokey.pub" 2>&1 | grep -q keynum; then
    echo "step audit-fp OK"
else
    echo "step audit-fp FAIL"; exit 1
fi

stop_server

rm -rf "$WORK"
echo "== ALL TESTS PASSED =="
