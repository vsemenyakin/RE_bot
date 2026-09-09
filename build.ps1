# Сборка образа re-workbench.
#
#   .\build.ps1                      обычная сборка
#   .\build.ps1 -Suite bookworm      ARM-корни под Pi OS 2023-2024
#   .\build.ps1 -NoCache             пересобрать с нуля
#   .\build.ps1 -SkipSelfTest        не прогонять проверку после сборки
#
# Требуется запущенный Docker Desktop (buildx и binfmt для ARM-стадий в комплекте).
#
# ВНИМАНИЕ при редактировании: файл обязан сохраняться в UTF-8 *с BOM*.
# Windows PowerShell 5.1 без BOM читает его как cp1251, и русская "т" (UTF-8 D1 82)
# превращается в символ U+201A, который парсер считает открывающей кавычкой.

param(
    [string]$Suite = "trixie",
    [string]$GhidraVersion = "12.1.3",
    [string]$GhidraBuild = "20260817",
    [string]$Tag = "re-workbench:latest",
    [switch]$NoCache,
    [switch]$SkipSelfTest
)

# Намеренно Continue: у нативных команд проверяем $LASTEXITCODE вручную,
# иначе безобидный вывод docker в stderr роняет скрипт.
$ErrorActionPreference = "Continue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Fail($msg) { Write-Host $msg -ForegroundColor Red; exit 1 }

Write-Host "Проверяю Docker..." -ForegroundColor Cyan
docker version --format "{{.Server.Version}}" > $null
if ($LASTEXITCODE -ne 0) { Fail "Docker недоступен. Запущен ли Docker Desktop?" }

# binfmt/QEMU на хосте не нужен: ARM-корни собираются распаковкой .deb,
# ни один ARM-бинарь при сборке не запускается.

$buildArgs = @(
    "build",
    "--build-arg", "RPI_SUITE=$Suite",
    "--build-arg", "GHIDRA_VERSION=$GhidraVersion",
    "--build-arg", "GHIDRA_BUILD=$GhidraBuild",
    "-t", $Tag
)
if ($NoCache) { $buildArgs += "--no-cache" }
$buildArgs += (Join-Path $here "image")

Write-Host "Собираю $Tag (Debian $Suite, Ghidra $GhidraVersion)." -ForegroundColor Cyan
Write-Host "Первый раз это 15-30 минут, в основном Ghidra (~400 МБ) и python-пакеты." -ForegroundColor Gray
& docker @buildArgs
if ($LASTEXITCODE -ne 0) { Fail "Сборка не удалась" }

if (-not $SkipSelfTest) {
    Write-Host ""
    Write-Host "Проверяю образ..." -ForegroundColor Cyan
    docker run --rm --network none $Tag bash /opt/re/scripts/selftest.sh
}

$manual = Join-Path $here "runs\manual"
Write-Host ""
Write-Host "Готово. Зайти внутрь:" -ForegroundColor Green
Write-Host ('  docker run --rm -it --network none -v "' + $manual + ':/work" ' + $Tag) -ForegroundColor Gray
