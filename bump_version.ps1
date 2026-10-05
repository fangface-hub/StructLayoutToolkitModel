param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Major", "Minor", "Patch")]
    [string]$Part
)

$ErrorActionPreference = "Stop"

$projectPath = Join-Path $PSScriptRoot "pyproject.toml"
$lockPath = Join-Path $PSScriptRoot "uv.lock"
$projectContent = [System.IO.File]::ReadAllText($projectPath)
$lockContent = [System.IO.File]::ReadAllText($lockPath)

$projectPattern = '(?m)(^\[project\]\r?\n(?:(?!^\[)[^\r\n]*\r?\n)*?^version[ \t]*=[ \t]*")(\d+\.\d+\.\d+)(")'
$lockPattern = '(?m)(^\[\[package\]\]\r?\n(?:(?!^\[\[package\]\])[^\r\n]*\r?\n)*?^name[ \t]*=[ \t]*"sltmodel"\r?\n(?:(?!^\[\[package\]\])[^\r\n]*\r?\n)*?^version[ \t]*=[ \t]*")(\d+\.\d+\.\d+)(")'
$projectMatches = [regex]::Matches($projectContent, $projectPattern)
$lockMatches = [regex]::Matches($lockContent, $lockPattern)

if ($projectMatches.Count -ne 1) {
    throw "Expected exactly one [project] version in $projectPath."
}
if ($lockMatches.Count -ne 1) {
    throw "Expected exactly one sltmodel package version in $lockPath."
}

$projectMatch = $projectMatches[0]
$lockMatch = $lockMatches[0]
$currentVersion = $projectMatch.Groups[2].Value
if ($lockMatch.Groups[2].Value -ne $currentVersion) {
    throw "The sltmodel version in uv.lock does not match pyproject.toml."
}

$versionParts = $currentVersion.Split('.') | ForEach-Object { [int]$_ }
$major = $versionParts[0]
$minor = $versionParts[1]
$patch = $versionParts[2]

switch ($Part) {
    "Major" {
        $major++
        $minor = 0
        $patch = 0
    }
    "Minor" {
        $minor++
        $patch = 0
    }
    "Patch" {
        $patch++
    }
}

$newVersion = "$major.$minor.$patch"
$projectStart = $projectMatch.Groups[2].Index
$lockStart = $lockMatch.Groups[2].Index
$updatedProject = $projectContent.Substring(0, $projectStart) +
    $newVersion +
    $projectContent.Substring($projectStart + $projectMatch.Groups[2].Length)
$updatedLock = $lockContent.Substring(0, $lockStart) +
    $newVersion +
    $lockContent.Substring($lockStart + $lockMatch.Groups[2].Length)

$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($projectPath, $updatedProject, $utf8WithoutBom)
[System.IO.File]::WriteAllText($lockPath, $updatedLock, $utf8WithoutBom)
Write-Host "Bumped version to $newVersion"
