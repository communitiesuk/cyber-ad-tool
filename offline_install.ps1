[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-WindowsFeature RSAT-AD-PowerShell

Copy-Item -Path "C:\cyber-ad-tool\assets\Pode\" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse
Copy-Item -Path "C:\cyber-ad-tool\assets\nuget\" -Destination "C:\Program Files\PackageManagement\ProviderAssemblies" -Recurse
Copy-Item "C:\cyber-ad-tool\assets\nssm.exe" -Destination "C:\Windows\System32"


$exe = (Get-Command powershell.exe).Source
$name = 'Active Directory Reporting Tool'
$file = 'C:\cyber-ad-tool\server.ps1'
$arg = "-ExecutionPolicy Bypass -NoProfile -Command `"$($file)`""


nssm install $name $exe $arg
nssm start $name