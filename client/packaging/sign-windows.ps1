param(
    [Parameter(Mandatory = $true)] [string] $PfxPath,
    [string] $ExePath = "..\dist\fstec-client-windows-x64\FSTEC-Client.exe",
    [string] $TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$secure = Read-Host -AsSecureString "PFX password"
$cert = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $secure
$result = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -TimestampServer $TimestampUrl -HashAlgorithm SHA256
$result | Format-List
