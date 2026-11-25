#!/usr/bin/env bash
# Build the self-contained replication archive for deposit (for example on Zenodo).
#
#   bash docs/paper/EMSE/replication-package/scripts/build_archive.sh
#
# Output: docs/paper/EMSE/replication-package/dist/inert-mas-replication-<commit>.tar.xz (git-ignored)
#
# The archive contains
#   - the committed repository at HEAD (git archive): code, tests, baselines, TAMAS adapter and data,
#     zoo models, manifests, the 182 result shards in results/final/, analysis scripts, manuscript,
#     taxonomy audit trail and API cache, this package;
#   - hpc/fetched/code/     the four code snapshots that produced the records (named by content hash,
#                           git-ignored because hpc/fetched/ also holds logs with account names).
# It deliberately leaves out hpc/fetched/jobs.jsonl and other fetched logs, which carry cluster
# account names, and anything under hpc/.ssh/.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../../../.." && pwd)
cd "$ROOT"
PKG=docs/paper/EMSE/replication-package
[[ -z "$(git status --porcelain)" ]] || { echo "working tree not clean: commit first so the archive matches HEAD" >&2; exit 1; }
sha256sum --quiet -c $PKG/data/SHA256SUMS-results.txt
sha256sum --quiet -c $PKG/data/SHA256SUMS-code-snapshots.txt
COMMIT=$(git rev-parse --short=12 HEAD)
NAME=inert-mas-replication-$COMMIT
DIST=$PKG/dist
STAGE=$(mktemp -d)
# copied files may be read-only (cp -a keeps modes), so make the staging tree writable before removal
trap 'chmod -R u+w "$STAGE" 2>/dev/null; rm -rf "$STAGE"' EXIT
mkdir -p "$DIST" "$STAGE/$NAME"
git archive --format=tar HEAD | tar -x -C "$STAGE/$NAME"
mkdir -p "$STAGE/$NAME/hpc/fetched"
cp -a hpc/fetched/code "$STAGE/$NAME/hpc/fetched/code"
printf '%s\n' "$(git rev-parse HEAD)" > "$STAGE/$NAME/COMMIT"
tar -C "$STAGE" -cf - "$NAME" | xz -T0 -9 > "$DIST/$NAME.tar.xz"
(cd "$DIST" && sha256sum "$NAME.tar.xz" > "$NAME.tar.xz.sha256")
ls -lh "$DIST/$NAME.tar.xz"
cat "$DIST/$NAME.tar.xz.sha256"
