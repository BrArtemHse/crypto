param([string]$Go = 'go')

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
if ($Go -ne 'go') { $Go = (Resolve-Path -LiteralPath $Go).Path }
Push-Location $repoRoot
try {
    $work = Join-Path $repoRoot ('.scratch\smoke-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    function Run-Go([string[]]$Arguments) {
        & $Go @Arguments
        if ($LASTEXITCODE -ne 0) { throw ('Go command failed: ' + ($Arguments -join ' ')) }
    }
    function Expect-Failure([string[]]$Arguments) {
        & $Go @Arguments
        if ($LASTEXITCODE -eq 0) { throw ('Expected rejection: ' + ($Arguments -join ' ')) }
    }
    function Assert-Same([string]$Left, [string]$Right) {
        if ((Get-FileHash -LiteralPath $Left).Hash -ne (Get-FileHash -LiteralPath $Right).Hash) {
            throw ('Files differ: ' + $Left + ' and ' + $Right)
        }
    }
    $inputFile = Join-Path $work 'input.bin'
    [byte[]]$inputBytes = (0,0,255,1,2,3,0) + [Text.Encoding]::UTF8.GetBytes('Криптография')
    [IO.File]::WriteAllBytes($inputFile, $inputBytes)

    Run-Go @('run','./GaloisFields','mul','--p','2','--n','8','--poly','1,1,0,1,1,0,0,0,1','--x','87','--y','19')
    $affine = Join-Path $work 'affine.json'; $affinePlain = Join-Path $work 'affine-plain.bin'
    Run-Go @('run','./GaloisFields','encrypt','--p','3','--n','2','--alpha','3','--beta','5','--in',$inputFile,'--out',$affine)
    Run-Go @('run','./GaloisFields','decrypt','--p','3','--n','2','--alpha','3','--beta','5','--in',$affine,'--out',$affinePlain)
    Assert-Same $inputFile $affinePlain
    Run-Go @('run','./EllipticCurves','info','--limit','3')
    Run-Go @('run','./EllipticCurves','mul','--p','17','--a','2','--b','2','--point','5,1','--k','3')
    Run-Go @('run','./EllipticCurves','subgroups','--p','5','--a','1','--b','0','--limit','2')

    $aesCipher=Join-Path $work 'aes.bin'; $aesPlain=Join-Path $work 'aes-plain.bin'
    $aesKey='000102030405060708090a0b0c0d0e0f'
    Run-Go @('run','./AES','encrypt','--key',$aesKey,'--in',$inputFile,'--out',$aesCipher)
    Run-Go @('run','./AES','decrypt','--key',$aesKey,'--in',$aesCipher,'--out',$aesPlain)
    Assert-Same $inputFile $aesPlain

    $digest=Join-Path $work 'input.hash'
    Run-Go @('run','./Streebog','hash','--in',$inputFile,'--out',$digest)
    Run-Go @('run','./Streebog','check','--in',$inputFile,'--hash',$digest)

    $rsaPublic=Join-Path $work 'rsa-public.json'; $rsaPrivate=Join-Path $work 'rsa-private.json'
    $rsaCipher=Join-Path $work 'rsa.bin'; $rsaPlain=Join-Path $work 'rsa-plain.bin'
    Run-Go @('run','./RSA','keygen','--bits','512','--public',$rsaPublic,'--private',$rsaPrivate)
    Run-Go @('run','./RSA','encrypt','--key',$rsaPublic,'--in',$inputFile,'--out',$rsaCipher)
    Run-Go @('run','./RSA','decrypt','--key',$rsaPrivate,'--in',$rsaCipher,'--out',$rsaPlain)
    Assert-Same $inputFile $rsaPlain
    Run-Go @('run','./RSA','number','--p','61','--q','53','--e','17','--message','65')
    $smallPublic=Join-Path $work 'small-public.json'; $smallPrivate=Join-Path $work 'small-private.json'
    Run-Go @('run','./RSA','keygen','--p','61','--q','53','--e','17','--public',$smallPublic,'--private',$smallPrivate)
    Run-Go @('run','./RSA','attack','--key',$smallPublic,'--iterations','100','--out',(Join-Path $work 'recovered.json'))

    $gostPublic=Join-Path $work 'gost-public.json'; $gostPrivate=Join-Path $work 'gost-private.json'
    $signature=Join-Path $work 'input.sig'
    Run-Go @('run','./GOSTSignature','keygen','--public',$gostPublic,'--private',$gostPrivate)
    Run-Go @('run','./GOSTSignature','sign','--in',$inputFile,'--key',$gostPrivate,'--out',$signature)
    Run-Go @('run','./GOSTSignature','verify','--in',$inputFile,'--key',$gostPublic,'--sig',$signature)
    [IO.File]::WriteAllBytes($inputFile, [byte[]](9,9,9))
    Expect-Failure @('run','./Streebog','check','--in',$inputFile,'--hash',$digest)
    Expect-Failure @('run','./GOSTSignature','verify','--in',$inputFile,'--key',$gostPublic,'--sig',$signature)

    $blockDir=Join-Path $work 'block'
    Run-Go @('run','./Blockchain','generate','--name','Иванов Иван','--out',$blockDir,'--time','2026-10-27T12:00:00+03:00')
    Run-Go @('run','./Blockchain','verify','--dir',$blockDir)
    $transaction=Join-Path $blockDir 'tx01.bin'; $data=[IO.File]::ReadAllBytes($transaction)
    $data[199]=$data[199] -bxor 1; [IO.File]::WriteAllBytes($transaction,$data)
    Expect-Failure @('run','./Blockchain','verify','--dir',$blockDir)
    Write-Output ('All seven lab workflows passed. Artifacts: ' + $work)
} finally { Pop-Location }
