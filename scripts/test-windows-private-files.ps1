[CmdletBinding()]
param(
    [switch] $KeepAccounts
)

$ErrorActionPreference = 'Stop'

if (-not [OperatingSystem]::IsWindows()) {
    throw 'This integration check must run on Windows.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session so it can create disposable local test accounts.'
}

if (-not (Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
    throw 'The Microsoft.PowerShell.LocalAccounts module is required.'
}

$tag = [Guid]::NewGuid().ToString('N')
$otherName = "NazoCtlSpecOther_$tag"
$otherPasswordText = "N!$tag-other-7x"
$otherPassword = ConvertTo-SecureString $otherPasswordText -AsPlainText -Force
$fixture = Join-Path ([IO.Path]::GetTempPath()) "nazoauthctl-$tag-secret"
$probe = Join-Path ([IO.Path]::GetTempPath()) "nazoauthctl-$tag-probe.ps1"
$workspace = Split-Path -Parent $PSScriptRoot

function Invoke-AsUser {
    param(
        [Parameter(Mandatory)] [string] $User,
        [Parameter(Mandatory)] [securestring] $Password,
        [Parameter(Mandatory)] [string[]] $Arguments
    )
    $credential = [PSCredential]::new(".\$User", $Password)
    $process = Start-Process -FilePath (Get-Command pwsh).Source `
        -Credential $credential -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    return $process.ExitCode
}

try {
    New-LocalUser -Name $otherName -Password $otherPassword -AccountNeverExpires `
        -PasswordNeverExpires -UserMayNotChangePassword -Description 'NazoAuthCtl disposable filesystem test peer' |
        Out-Null

    # The Rust test creates the file through the production Win32 primitive,
    # including its create-time protected DACL.  No real key material is used.
    $env:NAZO_WINDOWS_PRIVATE_FILES_FIXTURE = $fixture
    Push-Location $workspace
    try {
        & cargo test -p nazoauthctl-runtime --test windows_private_files `
            windows_private_file_is_protected_before_first_write --locked -- --nocapture
        if ($LASTEXITCODE -ne 0) {
            throw "Rust Windows private-file test failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
        Remove-Item Env:NAZO_WINDOWS_PRIVATE_FILES_FIXTURE -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
        throw 'The Rust fixture was not created.'
    }

    Set-Content -LiteralPath $probe -Encoding UTF8 -Value @'
param([string] $Target)
$ErrorActionPreference = 'Stop'
try {
    [IO.File]::ReadAllBytes($Target) | Out-Null
    exit 1
}
catch {
    try {
        [IO.File]::WriteAllText($Target, 'foreign-write')
        exit 2
    }
    catch {
        exit 0
    }
}
'@

    $probeArguments = @('-NoProfile', '-NonInteractive', '-File', $probe, $fixture)
    $probeExit = Invoke-AsUser -User $otherName -Password $otherPassword -Arguments $probeArguments
    if ($probeExit -ne 0) {
        throw "The second disposable account accessed the private fixture (probe exit $probeExit)."
    }

    $ownerContent = [IO.File]::ReadAllText($fixture)
    if ($ownerContent -ne 'cross-account-fixture') {
        throw 'The owner could not read back the intact private fixture.'
    }

    Write-Host 'Windows private-file two-account check passed.'
}
finally {
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
    if (-not $KeepAccounts) {
        Remove-LocalUser -Name $otherName -ErrorAction SilentlyContinue
    }
}
