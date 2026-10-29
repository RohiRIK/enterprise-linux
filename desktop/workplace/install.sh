#!/usr/bin/env bash
# Install Workplace into a root filesystem: desktop/workplace/install.sh --root DIR [--prefix /usr]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="" prefix="/usr"
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="${2:?}"; shift 2 ;;
    --prefix) prefix="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$root" ] || { echo "error: --root is required" >&2; exit 2; }
root="${root%/}"
pkg="$root$prefix/lib/enterprise-linux/workplace"
mkdir -p "$pkg"
cp -r "$here/workplace" "$pkg/"
find "$pkg" -name '__pycache__' -prune -exec rm -rf {} +
mkdir -p "$root$prefix/bin"
cat > "$root$prefix/bin/workplace" <<EOS
#!/usr/bin/env python3
import sys
sys.path.insert(0, "$prefix/lib/enterprise-linux/workplace")
from workplace.__main__ import main
sys.exit(main())
EOS
chmod 0755 "$root$prefix/bin/workplace"
install -D -m 0644 "$here/data/org.enterpriselinux.Workplace.desktop" "$root$prefix/share/applications/org.enterpriselinux.Workplace.desktop"
install -D -m 0644 "$here/data/org.enterpriselinux.Workplace.metainfo.xml" "$root$prefix/share/metainfo/org.enterpriselinux.Workplace.metainfo.xml"
install -D -m 0644 "$here/data/icons/org.enterpriselinux.Workplace.svg" "$root$prefix/share/icons/hicolor/scalable/apps/org.enterpriselinux.Workplace.svg"
