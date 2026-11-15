#!/usr/bin/env pwsh
# ╔═══════════════════════════════════════════════════════════════╗
# ║   ███████╗ ██████╗██╗   ██╗██████╗  ██████╗                   ║
# ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗                  ║
# ║   ███████╗██║     ██║   ██║██║  ██║██║   ██║                  ║
# ║   ╚════██║██║     ██║   ██║██║  ██║██║   ██║                  ║
# ║   ███████║╚██████╗╚██████╔╝██████╔╝╚██████╔╝  D I G I T A L E ║
# ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝                   ║
# ║   Security check: network, Wi-Fi, websites, email, Bluetooth, ║
# ║   GDPR and NIS2.   © 2026 Gaetano Cardinale — gcardinale.it   ║
# ╠═══════════════════════════════════════════════════════════════╣
# ║ SPDX-License-Identifier: AGPL-3.0-or-later                    ║
# ║ Attribution required (AGPL sec. 7(b)): see NOTICE file        ║
# ╚═══════════════════════════════════════════════════════════════╝
<#
.SYNOPSIS
    Verifies that every C# source file starts with the mandatory header in build/header.txt.

.DESCRIPTION
    The header is a license term (AGPL-3.0 section 7(b), see NOTICE): it must be present,
    identical, at the very top of every .cs file under src/ and tests/, before any `using`.
    Files under bin/ and obj/ are generated and ignored. Line endings are not significant.
    Exits with code 1 and lists the offending files when at least one header is missing or altered.

.PARAMETER Root
    Repository root. Defaults to the parent folder of this script.

.EXAMPLE
    pwsh build/check-headers.ps1
#>
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$headerPath = Join-Path $Root 'build/header.txt'
$header = @(Get-Content -LiteralPath $headerPath -Encoding utf8)
if ($header.Count -eq 0) {
    Write-Error "The header file '$headerPath' is empty."
}

$separator = [IO.Path]::DirectorySeparatorChar
$generated = "$($separator)bin$($separator)", "$($separator)obj$($separator)"
$files = @(
    foreach ($folder in 'src', 'tests') {
        $path = Join-Path $Root $folder
        if (Test-Path -LiteralPath $path) {
            Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.cs' |
                Where-Object { $full = $_.FullName; -not ($generated | Where-Object { $full.Contains($_) }) }
        }
    }
)

$failures = @(
    foreach ($file in $files) {
        $lines = @(Get-Content -LiteralPath $file.FullName -Encoding utf8 -TotalCount $header.Count)
        $ok = $lines.Count -eq $header.Count
        for ($i = 0; $ok -and $i -lt $header.Count; $i++) {
            # Ordinal comparison: PowerShell's -ne would ignore case.
            $ok = [string]::Equals($lines[$i], $header[$i], [StringComparison]::Ordinal)
        }

        if (-not $ok) {
            [IO.Path]::GetRelativePath($Root, $file.FullName)
        }
    }
)

if ($failures.Count -gt 0) {
    Write-Host "Missing or altered header (see build/header.txt) in $($failures.Count) file(s):"
    $failures | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "Header OK in $($files.Count) C# file(s)."
exit 0
