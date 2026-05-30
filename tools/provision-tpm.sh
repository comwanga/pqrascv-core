#!/usr/bin/env bash
# TPM 2.0 provisioning: check, initialize, and create an Attestation Key (AK).
# Requires tpm2-tools and tpm2-tss to be installed.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

AK_CONTEXT="/var/lib/pqrascv/ak.ctx"
AK_PUB_PEM="/var/lib/pqrascv/ak_pub.pem"
EK_CERT="/var/lib/pqrascv/ek_cert.der"

mkdir -p /var/lib/pqrascv

for cmd in tpm2_getcap tpm2_createek tpm2_createak tpm2_readpublic; do
    command -v "${cmd}" &>/dev/null || die "${cmd} not found. Install tpm2-tools: apt install tpm2-tools"
done

info "Checking TPM device..."
if [[ ! -c /dev/tpm0 ]] && [[ ! -c /dev/tpmrm0 ]]; then
    die "No TPM device found (/dev/tpm0 or /dev/tpmrm0). Ensure TPM is enabled in BIOS."
fi
TPM_DEV=$([[ -c /dev/tpmrm0 ]] && echo "/dev/tpmrm0" || echo "/dev/tpm0")
info "Using TPM device: ${TPM_DEV}"

info "TPM capabilities:"
tpm2_getcap properties-fixed 2>/dev/null | grep -E "TPM2_PT_(VENDOR|FIRMWARE|REVISION)" || true

info "Retrieving Endorsement Key certificate..."
tpm2_getekcertificate -o "${EK_CERT}" 2>/dev/null \
    && info "EK certificate saved to ${EK_CERT}" \
    || warn "EK certificate not available (some virtual TPMs omit this)."

info "Creating Endorsement Key handle..."
tpm2_createek --ek-context /tmp/ek.ctx --key-algorithm rsa \
    || warn "EK creation failed (some TPMs pre-create the EK — proceeding anyway)."

if [[ -f "${AK_CONTEXT}" ]]; then
    info "AK context already exists at ${AK_CONTEXT}. Skipping creation."
else
    info "Creating Attestation Key (AK)..."
    tpm2_createak \
        --ek-context /tmp/ek.ctx \
        --ak-context "${AK_CONTEXT}" \
        --key-algorithm ecc \
        --hash-algorithm sha256 \
        --signing-algorithm ecdsa \
        --public "${AK_PUB_PEM}" \
        || die "Failed to create AK. TPM may be locked or EK not available."
    info "AK created. Context: ${AK_CONTEXT}"
fi

info "Reading AK public key..."
tpm2_readpublic --object-context "${AK_CONTEXT}" --output "${AK_PUB_PEM}" --format pem \
    && info "AK public key saved to ${AK_PUB_PEM}" \
    || warn "Could not read AK public key."

info "TPM provisioning complete. AK context: ${AK_CONTEXT}"
