#!/usr/bin/env bash
# AMD SEV-SNP provisioning check.
# Verifies that the host supports SEV-SNP and /dev/sev-guest is accessible.
# Must be run as root on an AMD EPYC (Milan/Genoa) host or VM.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

info "Checking CPU for SEV-SNP support..."
if ! grep -q "sev_snp" /proc/cpuinfo 2>/dev/null; then
    die "CPU does not advertise sev_snp. Ensure BIOS has AMD SME/SEV enabled."
fi
info "CPU reports sev_snp support."

info "Checking kvm_amd module..."
if ! lsmod | grep -q "kvm_amd"; then
    warn "kvm_amd not loaded. Attempting modprobe..."
    modprobe kvm_amd || die "Failed to load kvm_amd. Install linux-modules-extra."
fi
info "kvm_amd loaded."

info "Checking /dev/sev-guest..."
if [[ ! -c /dev/sev-guest ]]; then
    die "/dev/sev-guest not found. Ensure this VM is running with SEV-SNP enabled."
fi
if [[ ! -r /dev/sev-guest ]] || [[ ! -w /dev/sev-guest ]]; then
    die "/dev/sev-guest is not readable/writable. Check permissions or run as root."
fi
info "/dev/sev-guest is accessible."

info "Checking SEV-SNP firmware..."
SNP_FW_VERSION=$(cat /sys/module/ccp/parameters/snp_fw_version 2>/dev/null || echo "unknown")
info "SEV-SNP firmware version: ${SNP_FW_VERSION}"
if [[ "${SNP_FW_VERSION}" == "unknown" ]]; then
    warn "Cannot read firmware version. Ensure AMD SEV firmware is installed."
fi

if command -v pqrascv-cli &>/dev/null; then
    info "Testing SNP attestation via pqrascv-cli..."
    pqrascv-cli attest --backend amd-sev-snp --firmware /dev/zero --dry-run \
        && info "SNP attestation test passed." \
        || warn "SNP attestation test failed (expected on bare metal without SNP VM)."
else
    warn "pqrascv-cli not found. Skipping attestation test."
fi

info "SEV-SNP provisioning check complete."
