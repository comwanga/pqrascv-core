$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "================================================="
Write-Host "PQ-RASCV Production Determinism Integration Tests"
Write-Host "================================================="
Write-Host ""

Write-Host "[*] Compiling Release Binary..."
cargo build --release -p pqrascv-cli | Out-Null

$cli = ".\target\release\pqrascv.exe"

$nonce = "d7e5b9f6c4d2d7e5b9f6c4d2d7e5b9f6c4d2d7e5b9f6c4d2d7e5b9f6c4d21234"
$epoch = 42
$stateroot = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"

Set-Content -Path test_fw.bin -Value "Production Firmware v1.0" -NoNewline
Set-Content -Path tampered_fw.bin -Value "Production Firmware v1.1" -NoNewline

Write-Host "[*] Generating keys..."
& $cli keygen --out-seed seed.bin --out-vk vk.bin | Out-Null

Write-Host "[*] Generating Baseline Attestation Quote..."
& $cli attest --seed seed.bin --vk vk.bin --firmware test_fw.bin --slsa-level 3 --nonce $nonce --epoch $epoch --state-root $stateroot --out quote.cbor | Out-Null

# Grab the valid hash
$validOut = & $cli verify --vk vk.bin --quote quote.cbor --nonce $nonce --epoch $epoch --state-root $stateroot
$validHash = ($validOut | Select-String "Firmware Hash:\s+([a-f0-9]{64})" | ForEach-Object { $_.Matches.Groups[1].Value })[0]

Write-Host ""
Write-Host "-------------------------------------------------"
Write-Host "TEST SUITE execution starting..."
Write-Host "-------------------------------------------------"
Write-Host ""

# TEST 1
Write-Host "TEST 1 - Replay Attack Rejection"
$wrongNonce = "0000000000000000000000000000000000000000000000000000000000000000"
$out1 = & $cli verify --vk vk.bin --quote quote.cbor --nonce $wrongNonce --json | ConvertFrom-Json
if ($out1.verification -eq "FAILED" -and $out1.reason -match "verification failed") {
    Write-Host "  [PASS] Successfully rejected replayed/incorrect nonce." -ForegroundColor Green
} else { Write-Host "  [FAIL]" -ForegroundColor Red }

# TEST 2
Write-Host ""
Write-Host "TEST 2 - Tampered Firmware (Hash Mismatch)"
$wrongHash = "1111111111111111111111111111111111111111111111111111111111111111"
$out2 = & $cli verify --vk vk.bin --quote quote.cbor --nonce $nonce --expected-hash $wrongHash --json | ConvertFrom-Json
if ($out2.verification -eq "FAILED" -and $out2.reason -match "Firmware hash mismatch") {
    Write-Host "  [PASS] Successfully rejected tampered firmware hash." -ForegroundColor Green
} else { Write-Host "  [FAIL]" -ForegroundColor Red }

# TEST 3
Write-Host ""
Write-Host "TEST 3 - Divergent State Root"
$wrongRoot = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
$out3 = & $cli verify --vk vk.bin --quote quote.cbor --nonce $nonce --state-root $wrongRoot --json | ConvertFrom-Json
if ($out3.verification -eq "FAILED" -and $out3.reason -match "Consensus Root: INVALID") {
    Write-Host "  [PASS] Successfully rejected invalid consensus state root." -ForegroundColor Green
} else { Write-Host "  [FAIL]" -ForegroundColor Red }

# TEST 5
Write-Host ""
Write-Host "TEST 5 - Corrupted Quote Fuzz Validation"
Copy-Item quote.cbor quote_corrupted.cbor
$bytes = [System.IO.File]::ReadAllBytes("$pwd\quote_corrupted.cbor")
[System.IO.File]::WriteAllBytes("$pwd\quote_corrupted.cbor", $bytes[0..($bytes.Length - 11)])

$out5 = & $cli verify --vk vk.bin --quote quote_corrupted.cbor --nonce $nonce --json | ConvertFrom-Json
if ($out5.verification -eq "FAILED" -and $out5.reason -match "failed") {
    Write-Host "  [PASS] Graceful verification failure on corrupted CBOR." -ForegroundColor Green
} else { Write-Host "  [FAIL]" -ForegroundColor Red }

# TEST 6
Write-Host ""
Write-Host "TEST 6 - Cross-Process Determinism (The Ultimate Test)"
& $cli attest --seed seed.bin --vk vk.bin --firmware test_fw.bin --slsa-level 3 --nonce $nonce --epoch $epoch --state-root $stateroot --out quote1.cbor | Out-Null
& $cli attest --seed seed.bin --vk vk.bin --firmware test_fw.bin --slsa-level 3 --nonce $nonce --epoch $epoch --state-root $stateroot --out quote2.cbor | Out-Null

$hash1 = (Get-FileHash quote1.cbor -Algorithm SHA256).Hash
$hash2 = (Get-FileHash quote2.cbor -Algorithm SHA256).Hash

if ($hash1 -eq $hash2) {
    Write-Host "  [PASS] Deterministic execution verified!" -ForegroundColor Green
    Write-Host "         Quote 1 Hash: $hash1" -ForegroundColor DarkGray
    Write-Host "         Quote 2 Hash: $hash2" -ForegroundColor DarkGray
} else { 
    Write-Host "  [FAIL] Nondeterminism detected!" -ForegroundColor Red 
    Write-Host "         Quote 1 Hash: $hash1"
    Write-Host "         Quote 2 Hash: $hash2"
}

Write-Host ""
Write-Host "Done."
