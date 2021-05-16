[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-WindowsFeature RSAT-AD-PowerShell
Install-Module -Name Pode

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature enable -n allowGlobalConfirmation
choco install nssm -y

$exe = (Get-Command powershell.exe).Source
$name = 'Active Directory Reporting Tool'
$file = 'C:\cyber-ad-tool\server.ps1'
$arg = "-ExecutionPolicy Bypass -NoProfile -Command `"$($file)`""


nssm install $name $exe $arg
nssm start $name