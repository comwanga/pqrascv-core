#!/usr/bin/env bash
# Intel TDX provisioning check.
# Verifies TDX host/guest support and /dev/tdx_guest accessibility.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

info "Checking CPU for TDX support..."
if ! grep -q "tdx_guest\|tdx" /proc/cpuinfo 2>/dev/null; then
    die "CPU does not advertise TDX. Requires Intel Sapphire Rapids or later with TDX enabled in BIOS."
fi
info "CPU reports TDX support."

KERNEL_VERSION=$(uname -r)
info "Kernel version: ${KERNEL_VERSION}"
KERNEL_MAJOR=$(echo "${KERNEL_VERSION}" | cut -d. -f1)
KERNEL_MINOR=$(echo "${KERNEL_VERSION}" | cut -d. -f2)
if [[ "${KERNEL_MAJOR}" -lt 5 ]] || { [[ "${KERNEL_MAJOR}" -eq 5 ]] && [[ "${KERNEL_MINOR}" -lt 19 ]]; }; then
    die "Kernel ${KERNEL_VERSION} is too old. TDX guest driver requires Linux >= 5.19."
fi

info "Checking /dev/tdx_guest..."
if [[ ! -c /dev/tdx_guest ]]; then
    die "/dev/tdx_guest not found. Ensure this is a TDX guest VM and the tdx_guest kernel module is loaded."
fi
info "/dev/tdx_guest is accessible."

if ! lsmod | grep -q "tdx_guest"; then
    warn "tdx_guest module not in lsmod output (may be built-in). Continuing."
fi

info "TDX provisioning check complete."
