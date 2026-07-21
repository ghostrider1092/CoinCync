#requires -Version 5.1

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SourceRoot,

  [Parameter(Mandatory = $true)]
  [string]$Destination
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $SourceRoot).Path)
$rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
$manifest = Join-Path $root 'index.parts'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
  throw "Explorer source manifest missing: $manifest"
}

$entries = @(
  Get-Content -LiteralPath $manifest -Encoding UTF8 |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }
)
if ($entries.Count -eq 0) {
  throw "Explorer source manifest contains no parts: $manifest"
}

$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$stream = [IO.MemoryStream]::new()
try {
  foreach ($entry in $entries) {
    $segments = $entry -split '[\\/]'
    if ([IO.Path]::IsPathRooted($entry) -or $segments -contains '..') {
      throw "Unsafe explorer source path: $entry"
    }
    $path = [IO.Path]::GetFullPath((Join-Path $root $entry))
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Explorer source escapes source root: $entry"
    }
    if (-not $seen.Add($path)) {
      throw "Duplicate explorer source path: $entry"
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      throw "Explorer source part missing: $entry"
    }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -eq 0) {
      throw "Explorer source part is empty: $entry"
    }
    $stream.Write($bytes, 0, $bytes.Length)
  }

  $destinationPath = [IO.Path]::GetFullPath($Destination)
  if ($destinationPath -eq $root -or
      $destinationPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to write assembled output inside explorer sources'
  }
  $parent = Split-Path -Parent $destinationPath
  if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
  }
  [IO.File]::WriteAllBytes($destinationPath, $stream.ToArray())
} finally {
  $stream.Dispose()
}
