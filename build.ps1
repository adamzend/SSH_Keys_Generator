param(
    [string]$Python = 'python',
    [string]$InnoCompiler = ''
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $arguments = @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--windowed', '--name', 'SSH_Keys_Generator', '--distpath', $PSScriptRoot, '--workpath', (Join-Path $PSScriptRoot '.build\work'), '--specpath', (Join-Path $PSScriptRoot '.build'))
    foreach ($asset in @('remote.py', 'INSTRUKCJA.txt', 'GUIDE_EN.txt', 'LICENSE', 'THIRD_PARTY_LICENSES.txt')) {
        $arguments += @('--add-data', ((Join-Path $PSScriptRoot $asset) + ';.'))
    }
    foreach ($folder in @('locales', 'assets')) {
        $arguments += @('--add-data', ((Join-Path $PSScriptRoot $folder) + ';' + $folder))
    }
    $arguments += 'app.py'
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
    if ($InnoCompiler) {
        & $InnoCompiler (Join-Path $PSScriptRoot 'installer.iss')
        if ($LASTEXITCODE -ne 0) { throw 'Inno Setup build failed.' }
    }
}
finally { Pop-Location }
