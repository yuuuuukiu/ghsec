#!/usr/bin/env bash
#
# build-release.sh builds every release artefact for ghsec.
#
# It is the single source of truth for release packaging: the Makefile calls it
# locally and the GitHub Actions release workflow calls it in CI, so a local
# build and a published release can never drift apart.
#
# Usage:
#   scripts/build-release.sh v1.2.3
#   scripts/build-release.sh v1.2.3 --dist dist
#
# Environment:
#   COMMIT   git revision to embed (default: the short HEAD hash)
#   DATE     build timestamp to embed (default: now, UTC)
#
# Produces, inside the dist directory:
#   ghsec_<version>_<os>_<arch>.tar.gz   (macOS, Linux)
#   ghsec_<version>_<os>_<arch>.zip      (Windows)
#   SHA256SUMS                           (checksums for every archive)
#
# The archives contain the binary plus LICENSE and README.md, so a download is
# self-contained.

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
	echo "usage: $0 <version> [--dist DIR]" >&2
	exit 2
fi

DIST="dist"
shift
while [[ $# -gt 0 ]]; do
	case "$1" in
	--dist)
		DIST="${2:?--dist needs a directory}"
		shift 2
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

# "v1.2.3" is the git tag; "1.2.3" is the file-name version.
NUM="${VERSION#v}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo none)}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# Release targets. Keep this list in sync with the README's platform table.
TARGETS=(
	"darwin/amd64"
	"darwin/arm64"
	"linux/amd64"
	"linux/arm64"
	"windows/amd64"
	"windows/arm64"
)

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${DATE}"

mkdir -p "$DIST"
STAGE="$DIST/.stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "building ghsec ${VERSION} (commit ${COMMIT}) for ${#TARGETS[@]} targets"

ARCHIVES=()
for target in "${TARGETS[@]}"; do
	os="${target%%/*}"
	arch="${target##*/}"

	bin="ghsec"
	[[ "$os" == "windows" ]] && bin="ghsec.exe"

	out="$STAGE/$bin"
	# -buildvcs=false keeps the build reproducible and lets it run from an
	# exported source tree that has no .git directory.
	GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
		go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$out" ./cmd/ghsec

	# Fail fast if a target silently produced something unusable.
	if [[ ! -s "$out" ]]; then
		echo "error: build produced no binary for ${target}" >&2
		exit 1
	fi

	cp LICENSE README.md "$STAGE/"

	name="ghsec_${NUM}_${os}_${arch}"
	if [[ "$os" == "windows" ]]; then
		archive="$DIST/${name}.zip"
		rm -f "$archive"
		(cd "$STAGE" && zip -q -9 "$OLDPWD/$archive" "$bin" LICENSE README.md)
	else
		archive="$DIST/${name}.tar.gz"
		rm -f "$archive"
		# GNU tar accepts ownership/mtime normalisation; bsdtar (macOS) does not,
		# so fall back to a plain archive there. COPYFILE_DISABLE stops macOS
		# from injecting AppleDouble ._ files into the tarball.
		if tar --version 2>/dev/null | grep -q "GNU tar"; then
			tar --format=ustar --owner=0 --group=0 --numeric-owner \
				--mtime="@${SOURCE_DATE_EPOCH:-$(date -u +%s)}" \
				-czf "$archive" -C "$STAGE" "$bin" LICENSE README.md
		else
			COPYFILE_DISABLE=1 tar -czf "$archive" -C "$STAGE" "$bin" LICENSE README.md
		fi
	fi

	ARCHIVES+=("$(basename "$archive")")
	echo "  ${name}  $(du -h "$archive" | cut -f1)"
done

rm -rf "$STAGE"

# SHA256SUMS in the canonical "hash  filename" form, so both
# `shasum -a 256 -c` (macOS) and `sha256sum -c` (Linux) accept it.
(
	cd "$DIST"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${ARCHIVES[@]}" >SHA256SUMS
	else
		shasum -a 256 "${ARCHIVES[@]}" >SHA256SUMS
	fi
)

echo
echo "checksums written to ${DIST}/SHA256SUMS"
cat "$DIST/SHA256SUMS"
