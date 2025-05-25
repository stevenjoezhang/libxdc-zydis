[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
$vsPath = &"${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationpath
Write-Host "Microsoft Visual Studio path = '$vsPath'" -ForegroundColor Cyan

Import-Module (Get-ChildItem $vsPath -Recurse -File -Filter Microsoft.VisualStudio.DevShell.dll).FullName
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation

cmake -B build -T "ClangCL,host=x64" -A x64
cmake --build build --config Release --target INSTALL --clean-first
