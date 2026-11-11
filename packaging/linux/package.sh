#!/bin/sh
# Turn build/linux/pyCertWiz (from build.sh) into an AppImage and .deb, .rpm and
# Arch packages, in dist/. Runs on the CI runner (or any Linux with curl).
#
#   packaging/linux/package.sh x86_64|aarch64
set -eu

ARCH=${1:-$(uname -m)}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=$ROOT/build/linux
DIST=$ROOT/dist
TOOLS=$ROOT/build/tools
VERSION=$(cat "$BUILD/VERSION")
ID=io.github.rob_c.pyCertWiz
mkdir -p "$DIST" "$TOOLS"
case "$ARCH" in
x86_64) deb_arch=amd64; nfpm_arch=amd64; nfpm_tar=Linux_x86_64 ;;
aarch64) deb_arch=arm64; nfpm_arch=arm64; nfpm_tar=Linux_arm64 ;;
*) echo "unsupported architecture $ARCH" >&2; exit 1 ;;
esac

github_asset() {  # repo tag pattern -> download URL of the matching release asset
    curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
        "https://api.github.com/repos/$1/releases/$2" |
        grep -o '"browser_download_url": *"[^"]*"' | cut -d'"' -f4 | grep -E "$3" | head -1
}

# --- AppImage ---------------------------------------------------------------
appdir=$BUILD/AppDir
rm -rf "$appdir" && mkdir -p "$appdir/usr/lib" "$appdir/usr/share/applications" "$appdir/usr/share/metainfo"
cp -a "$BUILD/pyCertWiz" "$appdir/usr/lib/pycertwiz"
cat >"$appdir/AppRun" <<'APPRUN'
#!/bin/sh
here=$(dirname "$(readlink -f "$0")")
exec "$here/usr/lib/pycertwiz/pyCertWiz" "$@"
APPRUN
chmod 755 "$appdir/AppRun"
cp "$ROOT/packaging/linux/$ID.desktop" "$appdir/$ID.desktop"
cp "$ROOT/packaging/linux/$ID.desktop" "$appdir/usr/share/applications/"
cp "$ROOT/packaging/linux/$ID.metainfo.xml" "$appdir/usr/share/metainfo/"
cp "$BUILD/icons/pycertwiz-256.png" "$appdir/$ID.png"
ln -sf "$ID.png" "$appdir/.DirIcon"
tool=$TOOLS/appimagetool-$ARCH.AppImage
[ -x "$tool" ] || { curl -fsSL -o "$tool" "$(github_asset AppImage/appimagetool tags/continuous "appimagetool-$ARCH.AppImage$")"; chmod +x "$tool"; }
APPIMAGE_EXTRACT_AND_RUN=1 ARCH=$ARCH "$tool" --no-appstream "$appdir" "$DIST/pyCertWiz-$VERSION-$ARCH.AppImage"

# --- .deb, .rpm and Arch packages (nfpm) --------------------------------------
nfpm=$TOOLS/nfpm
if [ ! -x "$nfpm" ]; then
    url=$(github_asset goreleaser/nfpm latest "nfpm_[0-9.]+_${nfpm_tar}\.tar\.gz$")
    curl -fsSL "$url" | tar -xz -C "$TOOLS" nfpm
fi
cp "$BUILD/icons/pycertwiz-256.png" "$BUILD/$ID.png"
# The oldest glibc the bundle runs on: the newest symbol version any file needs
# (GLIBC_ABI_DT_RELR, from linkers that pack relocations, means glibc 2.36).
symbols=$(find "$BUILD/pyCertWiz" -type f \( -name '*.so*' -o -perm -u+x \) -exec objdump -T {} + 2>/dev/null |
    grep -oE 'GLIBC_([0-9]+\.[0-9]+(\.[0-9]+)?|ABI_DT_RELR)' | sort -u)
glibc=$(printf '%s\n' "$symbols" | sed -n 's/^GLIBC_\([0-9]\)/\1/p' | sort -V | tail -1)
if printf '%s\n' "$symbols" | grep -q ABI_DT_RELR; then
    glibc=$(printf '%s\n2.36\n' "$glibc" | sort -V | tail -1)
fi
echo "the bundle needs glibc $glibc or newer"
sed -e "s|@VERSION@|$VERSION|; s|@ARCH@|$nfpm_arch|; s|@BUNDLE@|$BUILD/pyCertWiz|; s|@ICON@|$BUILD/$ID.png|; s|@GLIBC@|$glibc|g" \
    "$ROOT/packaging/linux/nfpm.yaml" >"$BUILD/nfpm.yaml"
for packager in deb rpm archlinux; do
    (cd "$ROOT" && "$nfpm" package --config "$BUILD/nfpm.yaml" --packager "$packager" --target "$DIST/")
done
cp "$BUILD/pyCertWiz-$VERSION-linux-$ARCH.tar.gz" "$DIST/"
ls -l "$DIST"
