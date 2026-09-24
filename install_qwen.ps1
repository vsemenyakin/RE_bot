#Requires -Version 5.1
<#
install_qwen.ps1 -- one-shot setup of a local Ollama model for the RE judge.

Each step is idempotent (safe to re-run):
  1. Install Ollama            -- skipped if 'ollama' is already available.
  2. Reserve Ollama's TCP port -- excludes it from the WinNAT/Hyper-V dynamic range
                                  so `ollama serve` cannot be blocked after a reboot
                                  (WSAEACCES 'bind ... forbidden', common with Docker
                                  installed). Needs ADMIN; skipped if already reserved,
                                  if a server is already up, or with -SkipPortReserve.
                                  Briefly stops WinNAT (Docker/WSL networking blips).
  3. Pull the model            -- skipped if already present; checks free space first.
  4. Verify the model answers  -- runs a trivial prompt and checks for a reply.

Run (from the repo root; use an ADMIN terminal so step 2 can reserve the port):
  powershell -ExecutionPolicy Bypass -File .\install_qwen.ps1                          # qwen3:30b (default)
  powershell -ExecutionPolicy Bypass -File .\install_qwen.ps1 -Model qwen3:30b         # same, explicit
  powershell -ExecutionPolicy Bypass -File .\install_qwen.ps1 -Model qwen2.5:14b -MinFreeGB 12
  powershell -ExecutionPolicy Bypass -File .\install_qwen.ps1 -SkipPortReserve         # don't touch WinNAT

NOTE: this file is intentionally ASCII-only and has no BOM. Windows PowerShell 5.1
reads a BOM-less file as the system ANSI codepage, so non-ASCII text would be
mangled or break parsing (the same trap build.ps1 sidesteps with a BOM). Keeping
it ASCII lets it run correctly regardless of how it is read.
#>
[CmdletBinding()]
param(
    [string]$Model      = "qwen3:30b",
    [int]   $MinFreeGB  = 22,         # qwen3:30b / qwen2.5:32b ~19 GB; leave headroom. Lower for 14b.
    [int]   $OllamaPort = 11434,      # Ollama's HTTP port; reserved so WinNAT cannot hijack it
    [switch]$SkipPortReserve          # skip the WinNAT port-reservation step
)
$ErrorActionPreference = "Stop"

function Test-Ollama { [bool](Get-Command ollama -ErrorAction SilentlyContinue) }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ServerOnPort([int]$Port) {
    try { Invoke-RestMethod -Uri "http://localhost:$Port/api/tags" -TimeoutSec 2 | Out-Null; return $true }
    catch { return $false }
}

function Test-PortExcluded([int]$Port) {
    # Is $Port inside a TCP excluded/reserved range? (numeric lines are locale-safe)
    $out = netsh int ipv4 show excludedportrange protocol=tcp 2>$null
    foreach ($line in $out) {
        if ($line -match '^\s*(\d+)\s+(\d+)\s*$') {
            if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
        }
    }
    return $false
}

function Test-PortBindable([int]$Port) {
    # THE definitive test. A persistent admin exclusion leaves the port bindable; a
    # live WinNAT/Hyper-V reservation does NOT (bind throws WSAEACCES) -- yet BOTH
    # show up in 'show excludedportrange', so excludedportrange alone cannot tell
    # them apart. Actually binding does. (Returns $false too if a server holds it.)
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) { try { $listener.Stop() } catch {} }
    }
}

function Invoke-WinNatReserve {
    # The documented fix: stop WinNAT (releases its dynamic reservations), add our
    # port to the PERSISTENT excluded range (so WinNAT won't grab it again, and it
    # stays bindable), restart WinNAT. Needs admin; briefly blips Docker/WSL net.
    Write-Host "    (briefly stops WinNAT -- Docker/WSL networking blips for a moment)"
    try { net stop winnat /y 2>&1 | Out-Null } catch {}
    try { netsh int ipv4 add excludedportrange protocol=tcp startport=$OllamaPort numberofports=1 store=persistent 2>&1 | Out-Null } catch {}
    try { net start winnat 2>&1 | Out-Null } catch {}
}

function Reserve-OllamaPort {
    # Make Ollama's port usable now AND durable across reboots. WinNAT/Hyper-V
    # dynamically reserves TCP ranges; a reboot can land one on Ollama's port, after
    # which `ollama serve` fails with WSAEACCES ("bind ... forbidden"). We decide
    # what to do from an actual bind test, not from the ambiguous exclusion list.
    if (Test-ServerOnPort $OllamaPort) {
        Write-Host "[i] A server already answers on port $OllamaPort -- leaving networking alone."
        return
    }
    $bindable = Test-PortBindable $OllamaPort
    $excluded = Test-PortExcluded $OllamaPort

    if ($bindable) {
        if ($excluded) {
            Write-Host "[i] Port $OllamaPort already reserved and bindable -- nothing to do."
            return
        }
        # Free but unprotected: a future reboot could let WinNAT grab it.
        if (-not (Test-Admin)) {
            Write-Host "[i] Port $OllamaPort is free now. To reserve it against future reboots, re-run from an ADMIN terminal."
            return
        }
        Write-Host "[i] Port $OllamaPort is free -- reserving it so WinNAT cannot grab it later..."
        Invoke-WinNatReserve
    } else {
        # Not bindable and no server here -> a live WinNAT/Hyper-V reservation holds it.
        if (-not (Test-Admin)) {
            Write-Warning "Port $OllamaPort is held by WinNAT/Hyper-V and cannot be bound -- 'ollama serve' will fail."
            Write-Host "    Re-run this script from an ADMIN terminal, or fix it manually (admin):"
            Write-Host "      net stop winnat"
            Write-Host "      netsh int ipv4 add excludedportrange protocol=tcp startport=$OllamaPort numberofports=1 store=persistent"
            Write-Host "      net start winnat"
            return
        }
        Write-Host "[i] Port $OllamaPort is held by WinNAT/Hyper-V -- freeing and reserving it for Ollama..."
        Invoke-WinNatReserve
    }

    if (Test-PortBindable $OllamaPort) {
        Write-Host "[+] Port $OllamaPort reserved for Ollama and bindable (persists across reboots)."
    } else {
        Write-Warning ("Port $OllamaPort still not bindable after the WinNAT reservation. Try rebooting, or " +
            "reserve manually (admin): net stop winnat; netsh int ipv4 add excludedportrange protocol=tcp startport=$OllamaPort numberofports=1 store=persistent; net start winnat")
    }
}

function Wait-Server {
    # Ollama serves its HTTP API on :$OllamaPort; pull/run need it up.
    for ($i = 0; $i -lt 30; $i++) {
        try { Invoke-RestMethod -Uri "http://localhost:$OllamaPort/api/tags" -TimeoutSec 3 | Out-Null; return $true }
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

# --- reserve Ollama's port so WinNAT/Hyper-V cannot hijack it -----------------
# Must run BEFORE we start the server: if the port is already in a WinNAT-reserved
# range, `ollama serve` cannot bind it (WSAEACCES). See Reserve-OllamaPort.
if (-not $SkipPortReserve) { Reserve-OllamaPort }

# --- ensure the server is up -------------------------------------------------
if (-not (Wait-Server)) {
    Write-Host "[i] Ollama server not responding -- starting it ..."
    # Capture serve output so a bind failure shows its real cause, not a silent timeout.
    $serveOut = Join-Path $env:TEMP "ollama_serve_install.log"
    $serveErr = "$serveOut.err"
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Hidden `
        -RedirectStandardOutput $serveOut -RedirectStandardError $serveErr -ErrorAction SilentlyContinue
    if (-not (Wait-Server)) {
        $errText = ""
        foreach ($f in @($serveErr, $serveOut)) {
            if (Test-Path $f) { $errText += (Get-Content $f -Raw -ErrorAction SilentlyContinue) }
        }
        $errText = $errText.Trim()
        throw ("Ollama server did not come up on http://localhost:$OllamaPort .`n" +
               "--- ollama serve output ---`n" + $(if ($errText) { $errText } else { "(no output captured)" }) +
               "`n---------------------------`n" +
               "If it says 'bind ... forbidden', port $OllamaPort is held by WinNAT/Hyper-V -- " +
               "re-run this script from an ADMIN terminal so it can free and reserve the port.")
    }
}

# --- 2. Pull the model (idempotent, with a free-space check) ------------------
$present = @()
try { $present = (Invoke-RestMethod "http://localhost:$OllamaPort/api/tags").models.name } catch {}
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

    Write-Host "[i] Pulling '$Model' -- this can take a while (multi-GB download) ..."
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

# Point the user at the matching judge descriptor for the model actually pulled.
switch -Wildcard ($Model) {
    "qwen3:*"     { $desc = "models/judge_local_qwen3.txt" }
    "qwen2.5:32b" { $desc = "models/judge_local32.txt" }
    "qwen2.5:14b" { $desc = "models/judge_local.txt" }
    default       { $desc = "models/<your description>.txt" }
}
Write-Host "[+] Done. '$Model' is installed and working."
Write-Host "    Point the judge at it in RE_args.txt: judge_model = $desc"
Write-Host "    (that description uses litellm_model = ollama_chat/$Model)"
