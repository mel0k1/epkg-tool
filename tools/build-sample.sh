#!/bin/sh
# build-sample.sh — build the example repository under sample-repo/.
#
# Creates demo packages with mkepkg, then generates index.json.
# The index lists ONE entry per package name — the newest version
# (hello 1.1-r0 here); the older hello-1.0-r0.epkg stays in packages/
# so you can practice "epkg upgrade" against a repo that was built
# when 1.0-r0 was the newest (see README.md, "Upgrading packages").
#
# Push sample-repo/ to a GitHub repository and epkg can use it as a
# mirror: https://raw.githubusercontent.com/<user>/<repo>/main
#
# usage: sh tools/build-sample.sh
set -e
cd "$(dirname "$0")/.."

BUILD=$(mktemp -d)
REPO=sample-repo
mkdir -p "$REPO/packages"

# ---------- demo package #1: hello 1.0-r0 (kept for upgrade demo) ----------
mkdir -p "$BUILD/hello/usr/bin" "$BUILD/hello/usr/share/doc"
cat > "$BUILD/hello/PKGINFO" <<'EOF'
pkgname = hello
pkgver = 1.0-r0
pkgdesc = Friendly hello demo for epkg
arch = any
deps =
EOF
cat > "$BUILD/hello/usr/bin/hello" <<'EOF'
#!/bin/sh
echo "Hello from epkg!"
EOF
chmod +x "$BUILD/hello/usr/bin/hello"
echo "This is the epkg sample 'hello' package." > "$BUILD/hello/usr/share/doc/hello.txt"
./mkepkg "$BUILD/hello" "$REPO/packages/hello-1.0-r0.epkg"

# ---------- demo package #1b: hello 1.1-r0 (the current release) ----------
mkdir -p "$BUILD/hello2/usr/bin" "$BUILD/hello2/usr/share/doc"
cat > "$BUILD/hello2/PKGINFO" <<'EOF'
pkgname = hello
pkgver = 1.1-r0
pkgdesc = Friendly hello demo for epkg, second release
arch = any
deps =
EOF
cat > "$BUILD/hello2/usr/bin/hello" <<'EOF'
#!/bin/sh
echo "Hello v2 from epkg!"
EOF
chmod +x "$BUILD/hello2/usr/bin/hello"
echo "This is the epkg sample 'hello' package (v2)." > "$BUILD/hello2/usr/share/doc/hello.txt"
./mkepkg "$BUILD/hello2" "$REPO/packages/hello-1.1-r0.epkg"

# ---------- demo package #2: motd (config-only) ----------
mkdir -p "$BUILD/motd/etc"
cat > "$BUILD/motd/PKGINFO" <<'EOF'
pkgname = motd
pkgver = 1.0-r0
pkgdesc = Sample config package: installs /etc/motd
arch = any
deps =
EOF
cat > "$BUILD/motd/etc/motd" <<'EOF'
Welcome to your hobby OS, powered by epkg!
EOF
./mkepkg "$BUILD/motd" "$REPO/packages/motd-1.0-r0.epkg"

# ---------- regenerate index.json (newest version per name) ----------
python3 - "$REPO" <<'EOF'
import hashlib, json, os, sys, tarfile

repo = sys.argv[1]

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

pkgs = {}
pdir = os.path.join(repo, "packages")
for fn in sorted(os.listdir(pdir)):
    if not fn.endswith(".epkg"):
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
    ent = {
        "pkgname": name,
        "pkgver": pi["pkgver"],
        "pkgdesc": pi.get("pkgdesc", ""),
        "arch": pi.get("arch", "any"),
        "filename": fn,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "deps": [d.strip() for d in pi.get("deps", "").split(",") if d.strip()],
    }
    if name not in pkgs or vkey(ent["pkgver"]) > vkey(pkgs[name]["pkgver"]):
        pkgs[name] = ent

index = {
    "epkg_index": 1,
    "repo": os.path.basename(os.path.abspath(repo)),
    "generated_by": "epkg-tools sample",
    "packages": list(pkgs.values()),
}
with open(os.path.join(repo, "index.json"), "w") as f:
    json.dump(index, f, indent=2)
    f.write("\n")
print("index.json:", len(pkgs), "packages (newest per name)")
EOF

# ---------- sign the index (signify/ed25519, demo key) ----------
# A demo secret key is generated under sample/ on the first build and
# kept OUT of the repo directory: real maintainers keep theirs offline.
if [ ! -f sample/demo-sec ]; then
    ./epkg-key gen -c "epkg sample demo key (DO NOT TRUST)" sample/demo-sec
fi
./epkg-key sign -s sample/demo-sec -m "$REPO/index.json" -x "$REPO/index.sig"
cp sample/demo-sec.pub "$REPO/demo.pub"
echo "index signed: $REPO/index.sig (public key: $REPO/demo.pub)"

echo "Point epkg.conf at the repo and set:"
echo "  pubkey = <path to demo.pub>   # or inline base64"
echo "then: epkg update && epkg audit"

rm -rf "$BUILD"
echo "sample repo ready in $REPO/"
