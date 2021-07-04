[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
# If running a server version of Windows
if ((Get-WindowsEdition -Online).Edition.StartsWith('Server')) {
    # Install the RSAT Active Directry feature
    Install-WindowsFeature RSAT-AD-PowerShell
} else {
    # Enable the RSAT Active Directory capability
    Get-WindowsCapability -Name Rsat.ActiveDirectory* -Online | Add-WindowsCapability -Online
}
Install-Module -Name Pode

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation
choco install nssm -y

$exe = (Get-Command powershell.exe).Source
$name = 'Active Directory Reporting Tool'
$file = 'C:\cyber-ad-tool\server.ps1'
$arg = "-ExecutionPolicy Bypass -NoProfile -Command `"$($file)`""

nssm install $name $exe $arg
nssm start $name