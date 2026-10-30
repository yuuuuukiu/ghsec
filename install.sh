#!/usr/bin/env sh
#
# ghsec installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/yuuuuukiu/ghsec/main/install.sh | sh
#
# Environment variables:
#   GHSEC_VERSION      install a specific tag (for example v1.0.0)
#                      default: the latest published release
#   GHSEC_INSTALL_DIR  install into this directory
#                      default: /usr/local/bin when writable, else ~/.local/bin
#   GHSEC_NO_VERIFY    set to 1 to skip checksum verification (not recommended)
#
# The script downloads the release archive for this platform, verifies its
# SHA-256 against the published SHA256SUMS file, and installs a single binary.
# It never invokes sudo and never edits shell profiles.

set -eu

REPO="yuuuuukiu/ghsec"
BIN="ghsec"

say() { printf '%s\n' "$*"; }
err() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# --- platform detection -----------------------------------------------------

detect_os() {
	os=$(uname -s 2>/dev/null || echo unknown)
	case "$os" in
	Darwin) echo darwin ;;
	Linux) echo linux ;;
	*) err "unsupported operating system: $os (this installer handles macOS and Linux; Windows users should run install.ps1)" ;;
	esac
}

detect_arch() {
	arch=$(uname -m 2>/dev/null || echo unknown)
	case "$arch" in
	x86_64 | amd64) echo amd64 ;;
	arm64 | aarch64) echo arm64 ;;
	*) err "unsupported architecture: $arch (ghsec ships amd64 and arm64 builds)" ;;
	esac
}

# --- download helpers -------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

fetch() {
	# fetch URL DEST
	if have curl; then
		curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
	elif have wget; then
		wget -q -O "$2" "$1"
	else
		err "neither curl nor wget is available; install one of them and retry"
	fi
}

# fetch_text returns a URL's body on stdout.
fetch_text() {
	if have curl; then
		curl -fsSL --retry 3 --retry-delay 2 "$1"
	elif have wget; then
		wget -q -O - "$1"
	else
		err "neither curl nor wget is available; install one of them and retry"
	fi
}

# latest_version resolves the newest release tag without hitting the API rate
# limit: GitHub redirects /releases/latest to the actual tag URL.
latest_version() {
	url=""
	if have curl; then
		url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)
	fi
	tag=""
	case "$url" in
	*/releases/tag/*) tag="${url##*/releases/tag/}" ;;
	esac
	if [ -z "$tag" ]; then
		# Fall back to the API when the redirect cannot be followed.
		tag=$(fetch_text "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null |
			tr ',' '\n' | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
	fi
	[ -n "$tag" ] || err "could not determine the latest ghsec release; set GHSEC_VERSION explicitly"
	printf '%s\n' "$tag"
}

# --- checksum verification --------------------------------------------------

verify_checksum() {
	# verify_checksum FILE SUMS_FILE NAME
	file="$1"
	sums="$2"
	name="$3"

	if [ "${GHSEC_NO_VERIFY:-0}" = "1" ]; then
		say "  skipping checksum verification (GHSEC_NO_VERIFY=1)"
		return 0
	fi

	expected=$(grep " ${name}\$" "$sums" 2>/dev/null | head -n 1 | awk '{print $1}')
	[ -n "$expected" ] || err "no checksum published for ${name}; refusing to install"

	if have sha256sum; then
		actual=$(sha256sum "$file" | awk '{print $1}')
	elif have shasum; then
		actual=$(shasum -a 256 "$file" | awk '{print $1}')
	elif have openssl; then
		actual=$(openssl dgst -sha256 "$file" | awk '{print $NF}')
	else
		err "no SHA-256 tool available (need sha256sum, shasum or openssl)"
	fi

	if [ "$expected" != "$actual" ]; then
		err "checksum mismatch for ${name}
  expected: ${expected}
  actual:   ${actual}
The download may be corrupted or tampered with. Aborting."
	fi
	say "  checksum verified"
}

# --- install location -------------------------------------------------------

choose_dir() {
	if [ -n "${GHSEC_INSTALL_DIR:-}" ]; then
		mkdir -p "$GHSEC_INSTALL_DIR" 2>/dev/null || err "cannot create GHSEC_INSTALL_DIR=$GHSEC_INSTALL_DIR"
		printf '%s\n' "$GHSEC_INSTALL_DIR"
		return
	fi
	if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		printf '%s\n' /usr/local/bin
		return
	fi
	# Fall back to a user-owned directory rather than silently escalating.
	fallback="${HOME}/.local/bin"
	mkdir -p "$fallback" 2>/dev/null || err "cannot create ${fallback}"
	printf '%s\n' "$fallback"
}

# --- main -------------------------------------------------------------------

main() {
	os=$(detect_os)
	arch=$(detect_arch)

	version="${GHSEC_VERSION:-}"
	if [ -z "$version" ]; then
		say "resolving the latest ghsec release…"
		version=$(latest_version)
	fi
	num="${version#v}"

	asset="ghsec_${num}_${os}_${arch}"
	base="https://github.com/${REPO}/releases/download/${version}"

	say "installing ghsec ${version} for ${os}/${arch}"

	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t ghsec)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	if [ "$os" = "windows" ]; then
		archive="${asset}.zip"
	else
		archive="${asset}.tar.gz"
	fi

	say "  downloading ${archive}"
	fetch "${base}/${archive}" "${tmp}/${archive}" || err "download failed: ${base}/${archive}
Check that release ${version} exists and publishes a ${os}/${arch} build."

	say "  downloading SHA256SUMS"
	fetch "${base}/SHA256SUMS" "${tmp}/SHA256SUMS" || err "could not download SHA256SUMS for ${version}"

	verify_checksum "${tmp}/${archive}" "${tmp}/SHA256SUMS" "${archive}"

	say "  extracting"
	case "$archive" in
	*.tar.gz) tar -xzf "${tmp}/${archive}" -C "$tmp" ;;
	*.zip) unzip -q "${tmp}/${archive}" -d "$tmp" ;;
	esac

	[ -f "${tmp}/${BIN}" ] || err "the archive did not contain the ${BIN} binary"

	dest_dir=$(choose_dir)
	dest="${dest_dir}/${BIN}"

	if [ -e "$dest" ]; then
		say "  replacing existing ${dest}"
	fi
	install -m 0755 "${tmp}/${BIN}" "$dest" 2>/dev/null || {
		cp "${tmp}/${BIN}" "$dest" && chmod 0755 "$dest"
	}

	say ""
	say "ghsec ${version} installed to ${dest}"
	if ! command -v "$BIN" >/dev/null 2>&1; then
		say ""
		say "note: ${dest_dir} is not on your PATH. Add it with:"
		say "  export PATH=\"${dest_dir}:\$PATH\""
	fi
	say ""
	say "run '${BIN}' to start the interactive UI, or '${BIN} --help' for the CLI."
}

main "$@"
