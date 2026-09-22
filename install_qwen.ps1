#Requires -Version 5.1
<#
install_qwen.ps1 -- one-shot setup of a local Ollama model for the RE judge.

Each step is idempotent (safe to re-run):
  1. Install Ollama            -- skipped if 'ollama' is already available.
  2. Pull the model            -- skipped if already present; checks free space first.
  3. Verify the model answers  -- runs a trivial prompt and checks for a reply.

Run (from the repo root):
  powershell -ExecutionPolicy Bypass -File .\install_qwen.ps1
  powershell -ExecutionPolicy Bypass -File .\install_qwen.ps1 -Model qwen2.5:14b -MinFreeGB 12

NOTE: this file is intentionally ASCII-only and has no BOM. Windows PowerShell 5.1
reads a BOM-less file as the system ANSI codepage, so non-ASCII text would be
mangled or break parsing (the same trap build.ps1 sidesteps with a BOM). Keeping
it ASCII lets it run correctly regardless of how it is read.
#>
[CmdletBinding()]
param(
    [string]$Model     = "qwen2.5:32b",
    [int]   $MinFreeGB = 22          # 32b is ~18.5 GB; leave headroom. Lower for 14b.
)
$ErrorActionPreference = "Stop"

function Test-Ollama { [bool](Get-Command ollama -ErrorAction SilentlyContinue) }

function Wait-Server {
    # Ollama serves its HTTP API on :11434; pull/run need it up.
    for ($i = 0; $i -lt 30; $i++) {
        try { Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 3 | Out-Null; return $true }
        catch { Start-Sleep -Seconds 2 }
    }
    return $false
}

# --- 1. Install Ollama -------------------------------------------------------
if (Test-Ollama) {
    Write-Host "[i] Ollama already installed: $((Get-Command ollama).Source)"
} else {
    Write-Host "[i] Ollama not found -- installing from ollama.com ..."
    Invoke-RestMethod https://ollama.com/install.ps1 | Invoke-Expression
    # The installer updates PATH for NEW shells only; refresh it for this session.
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path','User')
    if (-not (Test-Ollama)) {
        $guess = Join-Path $env:LOCALAPPDATA "Programs\Ollama"
        if (Test-Path (Join-Path $guess "ollama.exe")) { $env:Path += ";" + $guess }
    }
    if (-not (Test-Ollama)) {
        throw "Ollama installed but 'ollama' is not on PATH. Open a NEW terminal and re-run this script."
    }
    Write-Host "[+] Ollama installed."
}

# --- ensure the server is up -------------------------------------------------
if (-not (Wait-Server)) {
    Write-Host "[i] Ollama server not responding -- starting it ..."
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden -ErrorAction SilentlyContinue
    if (-not (Wait-Server)) { throw "Ollama server did not come up on http://localhost:11434" }
}

# --- 2. Pull the model (idempotent, with a free-space check) ------------------
$present = @()
try { $present = (Invoke-RestMethod "http://localhost:11434/api/tags").models.name } catch {}
if ($present -contains $Model) {
    Write-Host "[i] Model '$Model' already present -- skipping pull."
} else {
    if ($env:OLLAMA_MODELS) { $store = $env:OLLAMA_MODELS }
    else { $store = Join-Path $env:USERPROFILE ".ollama\models" }

    $freeGB = $null
    try {
        $driveLetter = (Split-Path -Qualifier $store).TrimEnd(":")
        $freeGB = [math]::Round((Get-PSDrive -Name $driveLetter).Free / 1GB, 1)
    } catch {
        Write-Warning "Could not determine free space for '$store' ($($_.Exception.Message)) -- skipping the space check."
    }
    if ($null -ne $freeGB) {
        Write-Host "[i] Model store: $store  (drive has $freeGB GB free)"
        if ($freeGB -lt $MinFreeGB) {
            throw "Only $freeGB GB free, need >= $MinFreeGB GB for '$Model'. Free space, lower -MinFreeGB, or set OLLAMA_MODELS to another drive."
        }
    }

    Write-Host "[i] Pulling '$Model' -- this can take a while (32b ~ 18.5 GB) ..."
    ollama pull $Model
    if ($LASTEXITCODE -ne 0) { throw "ollama pull '$Model' failed (exit code $LASTEXITCODE)." }
    Write-Host "[+] Model '$Model' pulled."
}

# --- 3. Verify the model answers --------------------------------------------
Write-Host "[i] Verifying '$Model' responds (first load of a big model can take minutes) ..."
$reply = (& ollama run $Model "hello") | Out-String
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($reply)) {
    throw "Model '$Model' did not answer (exit code $LASTEXITCODE)."
}
$firstLine = ($reply.Trim() -split "`r?`n")[0]
Write-Host "[+] Model answered: $firstLine"
Write-Host ""
Write-Host "[+] Done. '$Model' is installed and working."
Write-Host "    Point the judge at it in RE_args.txt: judge_model = models/judge_local32.txt"
Write-Host "    (that description uses litellm_model = ollama_chat/$Model)"
