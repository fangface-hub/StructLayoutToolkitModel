$ErrorActionPreference = "Stop"
& (Join-Path $PSScriptRoot "bump_version.ps1") -Part Minor
