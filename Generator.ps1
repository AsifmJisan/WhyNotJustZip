#requires -Version 5.1
<#
WhyNotJustZip
Creates one self-contained, text-only restoration .ps1 file.
Requires Windows PowerShell 5.1+ and built-in .NET APIs. No third-party tools.

Security design:
- ZIP created on disk (streamed by .NET), then encrypted with AES-256-CBC.
- Encrypt-then-MAC: HMAC-SHA256 authenticates header metadata and ciphertext before decryption.
- PBKDF2-HMAC-SHA1 via the broadly available .NET Framework API; 600,000 iterations.
- This is a first implementation. Review and test it on disposable sample projects before relying on it for irreplaceable data.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FormatVersion = 'PRX1'
$script:Iterations = 600000
$script:ChunkSize = 1MB

function Get-PasswordBytes {
    param([Parameter(Mandatory)][Security.SecureString]$SecurePassword)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        return ,([Text.Encoding]::UTF8.GetBytes($plain))
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Read-PasswordBytes {
    param([string]$Prompt)
    $secure = Read-Host -Prompt $Prompt -AsSecureString
    if ($secure.Length -lt 1) { throw 'Password cannot be empty.' }
    return ,(Get-PasswordBytes $secure)
}

function Get-KeyMaterial {
    param([byte[]]$PasswordBytes, [byte[]]$Salt, [int]$Iterations)
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordBytes, $Salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return ,$kdf.GetBytes(64) } finally { $kdf.Dispose() }
}

function Get-HmacForFile {
    param([byte[]]$Key, [string]$Path, [byte[]]$Prefix)
    $hmac = [Security.Cryptography.HMACSHA256]::new($Key)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $null = $hmac.TransformBlock($Prefix, 0, $Prefix.Length, $Prefix, 0)
        $buffer = New-Object byte[] $script:ChunkSize
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $null = $hmac.TransformBlock($buffer, 0, $read, $buffer, 0)
        }
        $empty = [byte[]]@()
        $null = $hmac.TransformFinalBlock($empty, 0, 0)
        return ,$hmac.Hash
    } finally { $stream.Dispose(); $hmac.Dispose() }
}

function ConvertTo-Hex {
    param([byte[]]$Bytes)
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function ConvertFrom-Hex {
    param([string]$Hex)
    if ($Hex -notmatch '^(?:[0-9a-fA-F]{2})+$') { throw 'Invalid hexadecimal metadata.' }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}

function Test-IgnoreRuleFileName {
    param([string]$Name)
    # Ignore-rule files have a leading dot and a name ending in "ignore",
    # optionally followed by a suffix/extension: .gitignore, .stignore, .dockerignore.
    return ($Name -match '^\..*ignore(?:\..*)?$')
}

function Get-IgnoreFiles {
    param([string]$Root)
    $found = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($item.PSIsContainer) {
                if (Test-BuiltinExcludedDirectory $item.Name) { continue }
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                $stack.Push($item.FullName)
            } elseif (Test-IgnoreRuleFileName $item.Name) {
                $found.Add($item)
            }
        }
    }
    return $found
}

function Test-BuiltinExcludedDirectory {
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    $exact = @(
        '.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env',
        'bin', 'obj', 'dist', 'build', '.pytest_cache', '.mypy_cache',
        '.ruff_cache', '.idea', '.vscode', 'coverage', '.next', '.nuxt',
        '.turbo', '.cache', 'vendor', 'target', 'packages'
    )
    return ($exact -contains $n)
}

function Test-BuiltinExcludedFile {
    param([string]$Name)
    $n = $Name.ToLowerInvariant()
    if (Test-IgnoreRuleFileName $Name) { return $true }
    if ($n -in @('.ds_store', 'thumbs.db', 'desktop.ini', '.coverage', 'npm-debug.log', 'yarn-error.log')) { return $true }
    if ($n -match '\.(pyc|pyo|tmp|temp|bak|swp|swo)$') { return $true }
    return $false
}

function Convert-GlobToRegex {
    param([string]$Pattern)
    # A deliberately limited glob translator. Unsupported constructs are reported.
    $p = $Pattern.Replace('\', '/')
    $regex = [Regex]::Escape($p).Replace('\*\*', '§DOUBLESTAR§').Replace('\*', '[^/]*').Replace('\?', '[^/]')
    $regex = $regex.Replace('§DOUBLESTAR§', '.*')
    return '^' + $regex + '$'
}

function Read-IgnoreRules {
    param([IO.FileInfo]$IgnoreFile, [string]$Root)
    $kind = if ($IgnoreFile.Name -eq '.stignore') { 'Syncthing' } elseif ($IgnoreFile.Name -eq '.gitignore') { 'Git' } else { 'Generic' }
    $rules = New-Object System.Collections.Generic.List[object]
    $baseDir = $IgnoreFile.Directory.FullName
    $lines = [IO.File]::ReadAllLines($IgnoreFile.FullName)
    $lineNo = 0
    foreach ($raw in $lines) {
        $lineNo++
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $negate = $false
        if ($kind -eq 'Git' -and $line.StartsWith('!')) {
            $negate = $true; $line = $line.Substring(1)
        }
        if ($line.StartsWith('!') -and $kind -ne 'Git') {
            Write-Warning "$($IgnoreFile.FullName):$lineNo uses negation unsupported by this parser; rule skipped."
            continue
        }
        if ($line.StartsWith('/') -or $line -match '(^|/)\.\.(/|$)' -or $line.Contains('[') -or $line.Contains(']')) {
            Write-Warning "$($IgnoreFile.FullName):$lineNo uses an advanced/absolute pattern not fully supported; rule skipped: $raw"
            continue
        }
        if ($kind -eq 'Syncthing' -and $line.StartsWith('(?i)')) {
            $line = $line.Substring(4)
        } elseif ($kind -eq 'Syncthing' -and $line.StartsWith('(?d)')) {
            Write-Warning "$($IgnoreFile.FullName):$lineNo uses Syncthing's (?d) semantics, which this version cannot reproduce exactly; rule skipped."
            continue
        }
        $directoryOnly = $line.EndsWith('/')
        $pattern = $line.TrimEnd('/')
        if (-not $pattern) { continue }
        $hasSlash = $pattern.Contains('/')
        $regexText = Convert-GlobToRegex $pattern
        $regex = [regex]::new($regexText, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $rules.Add([pscustomobject]@{
            Kind = $kind; Base = $baseDir; Pattern = $pattern; Regex = $regex
            HasSlash = $hasSlash; DirectoryOnly = $directoryOnly; Negate = $negate
            Source = $IgnoreFile.FullName; Line = $lineNo
        })
    }
    return $rules
}

function Test-PathAgainstIgnoreRules {
    param([string]$FullPath, [bool]$IsDirectory, [object[]]$Rules)
    $excluded = $false
    foreach ($rule in $Rules) {
        $base = $rule.Base.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $FullPath.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $relative = $FullPath.Substring($base.Length).Replace('\', '/')
        $match = $false
        if ($rule.DirectoryOnly -and -not $IsDirectory) {
            # Directory-only rules still match files beneath a matching directory.
            $segments = $relative.Split('/')
            for ($i = 0; $i -lt $segments.Length - 1; $i++) {
                $prefix = ($segments[0..$i] -join '/')
                if ($rule.Regex.IsMatch($prefix) -or (-not $rule.HasSlash -and $rule.Regex.IsMatch($segments[$i]))) { $match = $true; break }
            }
        } elseif ($rule.HasSlash) {
            $match = $rule.Regex.IsMatch($relative)
        } else {
            foreach ($segment in $relative.Split('/')) {
                if ($rule.Regex.IsMatch($segment)) { $match = $true; break }
            }
        }
        if ($match) { $excluded = -not $rule.Negate }
    }
    return $excluded
}

function New-FilteredZip {
    param([string]$Root, [string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') 
    $ignoreFiles = @(Get-IgnoreFiles $rootFull)
    $allRules = New-Object System.Collections.Generic.List[object]
    foreach ($f in $ignoreFiles) {
        foreach ($r in @(Read-IgnoreRules -IgnoreFile $f -Root $rootFull)) { $allRules.Add($r) }
    }
    if ($ignoreFiles.Count -eq 0) {
        Write-Host 'No recognized ignore-rule files found.' -ForegroundColor DarkYellow
    } else {
        Write-Host "Discovered $($ignoreFiles.Count) ignore-rule file(s)." -ForegroundColor Cyan
    }

    $zip = [IO.Compression.ZipFile]::Open($ZipPath, [IO.Compression.ZipArchiveMode]::Create)
    $included = 0; $excluded = 0; $totalBytes = [long]0
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($rootFull)
    try {
        while ($stack.Count -gt 0) {
            $dir = $stack.Pop()
            foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)) {
                $relative = $item.FullName.Substring($rootFull.Length).TrimStart('\', '/').Replace('\', '/')
                if (-not $relative) { continue }
                if ($item.PSIsContainer) {
                    if (Test-BuiltinExcludedDirectory $item.Name) {
                        Write-Host "EXCLUDED [built-in directory]: $relative" -ForegroundColor DarkYellow; $excluded++; continue
                    }
                    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                        Write-Warning "Skipped reparse point/junction: $relative"; $excluded++; continue
                    }
                    if (Test-PathAgainstIgnoreRules -FullPath $item.FullName -IsDirectory $true -Rules @($allRules)) {
                        Write-Host "EXCLUDED [ignore rule]: $relative/" -ForegroundColor DarkYellow; $excluded++; continue
                    }
                    $stack.Push($item.FullName)
                    # Preserve empty directories by writing explicit directory entries.
                    $children = @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue)
                    if ($children.Count -eq 0) {
                        $entry = $zip.CreateEntry(($relative.TrimEnd('/') + '/'))
                        $included++
                    }
                } else {
                    if (Test-BuiltinExcludedFile $item.Name) {
                        Write-Host "EXCLUDED [built-in file]: $relative" -ForegroundColor DarkYellow; $excluded++; continue
                    }
                        $rulesArray = $allRules.ToArray()
                        if (Test-PathAgainstIgnoreRules -FullPath $item.FullName -IsDirectory $false -Rules $rulesArray) {
                        Write-Host "EXCLUDED [ignore rule]: $relative" -ForegroundColor DarkYellow; $excluded++; continue
                    }
                    $entry = $zip.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
                    $src = [IO.File]::OpenRead($item.FullName)
                    $dst = $entry.Open()
                    try {
                        $src.CopyTo($dst, $script:ChunkSize)
                    } finally { $dst.Dispose(); $src.Dispose() }
                    $included++; $totalBytes += $item.Length
                }
            }
        }
    } finally { $zip.Dispose() }
    return [pscustomobject]@{ Included = $included; Excluded = $excluded; TotalBytes = $totalBytes }
}

function Get-StandaloneRestoreEngine {
    return @'
#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ChunkSize = 1MB
function Read-PasswordBytes {
    $secure = Read-Host -Prompt 'Archive password' -AsSecureString
    if ($secure.Length -lt 1) { throw 'Password cannot be empty.' }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr); return ,([Text.Encoding]::UTF8.GetBytes($plain)) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
function ConvertFrom-Hex([string]$Hex) {
    if ($Hex -notmatch '^(?:[0-9a-fA-F]{2})+$') { throw 'Invalid metadata.' }
    $b = New-Object byte[] ($Hex.Length / 2)
    for ($i=0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i*2,2),16) }
    return ,$b
}
function Get-KeyMaterial([byte[]]$PasswordBytes,[byte[]]$Salt,[int]$Iterations) {
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($PasswordBytes,$Salt,$Iterations,[Security.Cryptography.HashAlgorithmName]::SHA256)
    try { return ,$kdf.GetBytes(64) } finally { $kdf.Dispose() }
}
function Get-HmacForFile([byte[]]$Key,[string]$Path,[byte[]]$Prefix) {
    $h = [Security.Cryptography.HMACSHA256]::new($Key)
    $s = [IO.File]::OpenRead($Path)
    try {
        $null = $h.TransformBlock($Prefix,0,$Prefix.Length,$Prefix,0)
        $b = New-Object byte[] $script:ChunkSize
        while (($n=$s.Read($b,0,$b.Length)) -gt 0) { $null=$h.TransformBlock($b,0,$n,$b,0) }
        $e=[byte[]]@(); $null=$h.TransformFinalBlock($e,0,0); return ,$h.Hash
    } finally { $s.Dispose(); $h.Dispose() }
}
function Read-PayloadToFile([string]$Self,[string]$Target) {
    $reader = [IO.File]::OpenText($Self)
    $out = [IO.File]::Create($Target)
    $inside = $false
    try {
        while (($line=$reader.ReadLine()) -ne $null) {
            if (-not $inside) { if ($line -eq '###PRX_PAYLOAD_BEGIN###') { $inside=$true }; continue }
            if ($line -eq '###PRX_PAYLOAD_END###') { break }
            if ($line.Length -eq 0) { continue }
            if (-not $line.StartsWith('#')) {
                throw 'Invalid payload line: expected a comment-prefixed Base64 line.'
            }
            $line = $line.Substring(1)
            $bytes = [Convert]::FromBase64String($line)
            $out.Write($bytes,0,$bytes.Length)
        }
        if (-not $inside) { throw 'Embedded payload marker not found.' }
    } finally { $reader.Dispose(); $out.Dispose() }
}
function Restore-Archive {
    $self = $PSCommandPath
    if (-not $self) { $self = $PSCommandPath }
    $header = Get-Content -LiteralPath $self -TotalCount 12
    $meta = @{}
    foreach ($line in $header) {
        if ($line -match '^# PRX-([A-Z]+): (.+)$') { $meta[$Matches[1]]=$Matches[2] }
    }
    foreach ($required in @('SALT','IV','MAC','ITER','VERSION')) { if (-not $meta.ContainsKey($required)) { throw "Missing metadata: $required" } }
    if ($meta.VERSION -ne 'PRX1') { throw 'Unsupported archive version.' }
    $iterations=[int]$meta.ITER
    if ($iterations -lt 100000 -or $iterations -gt 5000000) { throw 'Invalid KDF iteration count.' }
    $salt=ConvertFrom-Hex $meta.SALT; $iv=ConvertFrom-Hex $meta.IV; $expectedMac=ConvertFrom-Hex $meta.MAC
    $tmpRoot=Join-Path ([IO.Path]::GetTempPath()) ('PRX-' + [guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $tmpRoot
    $cipher=Join-Path $tmpRoot 'payload.enc'; $plain=Join-Path $tmpRoot 'payload.zip'
    try {
        Read-PayloadToFile -Self $self -Target $cipher
        $password=Read-PasswordBytes
        $keys=Get-KeyMaterial -PasswordBytes $password -Salt $salt -Iterations $iterations
        $encKey=New-Object byte[] 32; $macKey=New-Object byte[] 32
        [Array]::Copy($keys,0,$encKey,0,32); [Array]::Copy($keys,32,$macKey,0,32)
        $prefix=[Text.Encoding]::UTF8.GetBytes("PRX1|$($meta.SALT)|$($meta.IV)|$($meta.ITER)|")
        $actualMac=Get-HmacForFile -Key $macKey -Path $cipher -Prefix $prefix
        if ($actualMac.Length -ne $expectedMac.Length) { throw 'Authentication failed. Wrong password or damaged archive.' }; $diff = 0; for ($mi=0; $mi -lt $actualMac.Length; $mi++) { $diff = $diff -bor ($actualMac[$mi] -bxor $expectedMac[$mi]) }; if ($diff -ne 0) { throw 'Authentication failed. Wrong password or damaged archive.' }
        $aes=[Security.Cryptography.Aes]::Create()
        $aes.KeySize=256; $aes.BlockSize=128; $aes.Mode=[Security.Cryptography.CipherMode]::CBC; $aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key=$encKey; $aes.IV=$iv
        $cipherStream=[IO.File]::OpenRead($cipher); $output=[IO.File]::Create($plain)
        try {
            $cs=New-Object Security.Cryptography.CryptoStream -ArgumentList @($output,$aes.CreateDecryptor(),[Security.Cryptography.CryptoStreamMode]::Write)
            try { $cipherStream.CopyTo($cs,$script:ChunkSize); $cs.FlushFinalBlock() } finally { $cs.Dispose() }
        } finally { $cipherStream.Dispose(); $output.Dispose(); $aes.Dispose() }

        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip=[IO.Compression.ZipFile]::OpenRead($plain)
        try {
            $suggested=Join-Path (Get-Location).Path 'Restored-Project'
            Write-Host 'Choose a destination folder for restoration.' -ForegroundColor Cyan
            $dest=Read-Host "Destination path (default: $suggested)"
            if ([string]::IsNullOrWhiteSpace($dest)) { $dest=$suggested }
            $dest=[IO.Path]::GetFullPath($dest)
            if (Test-Path -LiteralPath $dest) { throw "Destination already exists. Choose a new folder: $dest" }
            $null=New-Item -ItemType Directory -Path $dest
            foreach ($entry in $zip.Entries) {
                $name=$entry.FullName.Replace('\','/')
                if ($name.StartsWith('/') -or $name -match '^[A-Za-z]:' -or $name.Split('/') -contains '..') { throw "Unsafe archive path rejected: $name" }
                $target=[IO.Path]::GetFullPath((Join-Path $dest ($name.Replace('/',[IO.Path]::DirectorySeparatorChar))))
                $prefix=$dest.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
                if (-not $target.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $target -ne $dest) { throw "Path escapes destination: $name" }
                if ($name.EndsWith('/')) { $null=New-Item -ItemType Directory -Path $target -Force; continue }
                $parent=[IO.Path]::GetDirectoryName($target)
                if (-not (Test-Path -LiteralPath $parent)) { $null=New-Item -ItemType Directory -Path $parent -Force }
                $source=$entry.Open(); $targetStream=[IO.File]::Create($target)
                try { $source.CopyTo($targetStream,$script:ChunkSize) } finally { $targetStream.Dispose(); $source.Dispose() }
            }
            Write-Host "Restored files to: $dest" -ForegroundColor Green
            Write-Host 'Note: file contents and empty directories are restored; ACLs, alternate data streams, symlinks and all timestamps are not preserved.' -ForegroundColor Yellow
        } finally { $zip.Dispose() }
    } finally {
        Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
        if ($password) { [Array]::Clear($password,0,$password.Length) }
        if ($keys) { [Array]::Clear($keys,0,$keys.Length) }
    }
}
Restore-Archive
'@
}

function New-SelfContainedArtifact {
    param([string]$ZipPath, [string]$OutputPath, [byte[]]$PasswordBytes)
    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($salt); $rng.GetBytes($iv) } finally { $rng.Dispose() }
    $keys = Get-KeyMaterial -PasswordBytes $PasswordBytes -Salt $salt -Iterations $script:Iterations
    $encKey = New-Object byte[] 32; $macKey = New-Object byte[] 32
    [Array]::Copy($keys,0,$encKey,0,32); [Array]::Copy($keys,32,$macKey,0,32)
    $tempCipher = Join-Path ([IO.Path]::GetTempPath()) ('PRX-' + [guid]::NewGuid().ToString('N') + '.enc')
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.KeySize=256; $aes.BlockSize=128; $aes.Mode=[Security.Cryptography.CipherMode]::CBC; $aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key=$encKey; $aes.IV=$iv
    $src=[IO.File]::OpenRead($ZipPath); $dst=[IO.File]::Create($tempCipher)
    try {
        $cs=New-Object Security.Cryptography.CryptoStream -ArgumentList @($dst,$aes.CreateEncryptor(),[Security.Cryptography.CryptoStreamMode]::Write)
        try { $src.CopyTo($cs,$script:ChunkSize); $cs.FlushFinalBlock() } finally { $cs.Dispose() }
    } finally { $src.Dispose(); $dst.Dispose(); $aes.Dispose() }

    $saltHex=ConvertTo-Hex $salt; $ivHex=ConvertTo-Hex $iv
    $prefix=[Text.Encoding]::UTF8.GetBytes("PRX1|$saltHex|$ivHex|$($script:Iterations)|")
    $mac=Get-HmacForFile -Key $macKey -Path $tempCipher -Prefix $prefix
    $engine=Get-StandaloneRestoreEngine
    $header=@"
# Self-contained archive
# PRX-VERSION: PRX1
# PRX-SALT: $saltHex
# PRX-IV: $ivHex
# PRX-MAC: $(ConvertTo-Hex $mac)
# PRX-ITER: $($script:Iterations)
# This file contains encrypted data. Keep your password safe.
"@
    # The restore engine reads metadata from the first 12 lines and scans the payload marker.
    $content = $header + "`r`n" + $engine + "`r`n###PRX_PAYLOAD_BEGIN###`r`n"
    $writer = [IO.StreamWriter]::new($OutputPath,$false,[Text.UTF8Encoding]::new($false))
    try {
        $writer.Write($content)
        $cipherInput=[IO.File]::OpenRead($tempCipher)
        try {
            $buffer=New-Object byte[] 57 # 57 bytes -> 76 Base64 chars, one text line.
            while (($n=$cipherInput.Read($buffer,0,$buffer.Length)) -gt 0) {
                $piece=New-Object byte[] $n
                [Array]::Copy($buffer,0,$piece,0,$n)
                $writer.WriteLine('#' + [Convert]::ToBase64String($piece))
            }
        } finally { $cipherInput.Dispose() }
        $writer.WriteLine('###PRX_PAYLOAD_END###')
    } finally { $writer.Dispose() }
    Remove-Item -LiteralPath $tempCipher -Force -ErrorAction SilentlyContinue
    [Array]::Clear($keys,0,$keys.Length)
    [Array]::Clear($encKey,0,$encKey.Length)
    [Array]::Clear($macKey,0,$macKey.Length)
}

try {
    Write-Host 'WhyNotJustZip' -ForegroundColor Cyan
    Write-Host 'Creates a password-protected, standalone text .ps1 archive.' -ForegroundColor Gray
    $root = (Read-Host 'Project folder to archive').Trim('"')
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'The project folder does not exist.' }
    $root = [IO.Path]::GetFullPath($root)
    $defaultName = (Split-Path $root -Leaf) + '-Archive.ps1'
    $output = (Read-Host "Output .ps1 path (default: $(Join-Path (Get-Location).Path $defaultName))").Trim('"')
    if ([string]::IsNullOrWhiteSpace($output)) { $output = Join-Path (Get-Location).Path $defaultName }
    $output = [IO.Path]::GetFullPath($output)
    if ($output.StartsWith($root.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Output must be outside the source project folder.'
    }
    if (Test-Path -LiteralPath $output) {
        $confirm = Read-Host "Output exists. Type OVERWRITE to replace it"
        if ($confirm -cne 'OVERWRITE') { throw 'Cancelled; existing output was not changed.' }
    }
    $password = Read-PasswordBytes 'Set archive password (you will need it to restore)'
    $confirmPassword = Read-PasswordBytes 'Confirm archive password'
    if ([Convert]::ToBase64String($password) -cne [Convert]::ToBase64String($confirmPassword)) { throw 'Passwords do not match.' }
    [Array]::Clear($confirmPassword,0,$confirmPassword.Length)

    $tempZip = Join-Path ([IO.Path]::GetTempPath()) ('PRX-' + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        $stats = New-FilteredZip -Root $root -ZipPath $tempZip
        New-SelfContainedArtifact -ZipPath $tempZip -OutputPath $output -PasswordBytes $password
    } finally {
        Remove-Item -LiteralPath $tempZip -Force -ErrorAction SilentlyContinue
        [Array]::Clear($password,0,$password.Length)
    }
    $outputInfo = Get-Item -LiteralPath $output
    Write-Host ''
    Write-Host 'CREATION REPORT' -ForegroundColor Green
    Write-Host "Source:          $root"
    Write-Host "Included entries: $($stats.Included)"
    Write-Host "Excluded entries: $($stats.Excluded)"
    Write-Host "Included bytes:   $($stats.TotalBytes)"
    Write-Host "Output size:      $($outputInfo.Length) bytes"
    Write-Host "Artifact:         $output"
    Write-Host 'The original project was not modified.' -ForegroundColor Green
    Write-Warning 'Ignore parsing is intentionally conservative and not a complete implementation of every Git/Syncthing edge case. Review warnings and test restore before relying on the archive.'
} catch {
    Write-Host "`n--- FULL ERROR DETAILS ---" -ForegroundColor Red
    Write-Host ($_ | Format-List * -Force | Out-String)
    Write-Host "`n--- SCRIPT STACK ---" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace
    Write-Host "`n--- INVOCATION ---" -ForegroundColor Yellow
    Write-Host ($_ | Select-Object -ExpandProperty InvocationInfo | Format-List * | Out-String)
} finally {
    if ($password) { [Array]::Clear($password,0,$password.Length) }
}
