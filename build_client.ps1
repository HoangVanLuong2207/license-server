param(
    [string]$ServerUrl = "http://127.0.0.1:8000",
    [string]$OriginalExe = "F:\AutoTruyenLua_Vua.exe\AutoTruyenLua_Vua.exe"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "release"
$work = Join-Path $root "build"
$spec = Join-Path $root "client_launcher.spec"
$config = Join-Path $root "license-client.ini"

if (-not (Test-Path -LiteralPath $root)) { throw "Không tìm thấy thư mục license-server" }
if (-not (Test-Path -LiteralPath $OriginalExe)) { throw "Không tìm thấy file gốc: $OriginalExe" }

Remove-Item -LiteralPath $dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue
Set-Content -LiteralPath $config -Encoding UTF8 -Value "[license]`nserver_url=$ServerUrl`n"

python -m PyInstaller --noconfirm --clean --onefile --name AutoTruyenLua_Launcher `
    --distpath $dist --workpath $work --specpath $root `
    --add-binary "$OriginalExe;." `
    --add-data "$config;." `
    (Join-Path $root "client_launcher.py")

Remove-Item -LiteralPath (Join-Path $dist "AutoTruyenLua_Vua.exe") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $dist "license-client.ini") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $config -Force -ErrorAction SilentlyContinue
Write-Output "Bundled server URL: $ServerUrl" | Out-Null

Write-Host "Release created at: $dist"
