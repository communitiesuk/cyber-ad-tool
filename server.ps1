Import-Module -Name 'Pode'
Import-Module ActiveDirectory

# Configuration variables
$Port = 8080 # Port to run server
$HttpsEnabled = $false # Enable HTTPS (set to $false to disable encryption)
$Certificate = 'f5d675a7d2c570ae386adddf434175c2b681bffb' # Certificate thumbprint (replace with thumbprint your own certificate)


Start-PodeServer {

    
   New-PodeLoggingMethod -File -Path ./logs -Name 'requests' | Enable-PodeRequestLogging
   New-PodeLoggingMethod -File -Path ./logs -Name 'requests' | Enable-PodeErrorLogging
	
   #New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging
   #New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging

    # Enable-PodeSessionMiddleware -Secret 'schwifty' -Duration 120 -Extend


    #Set-PodeState -Name 'hash' -Value @{ 'values' = @(); } | Out-Null
    
    Set-PodeState -Name 'hash' -Value @{ } | Out-Null
    
    #$hash = (Get-PodeState -Name 'hash')

    #$hash.Add("Time", "Now")

    #$hash.values += (Get-Random -Minimum 0 -Maximum 10)


    #$hash
    
    #Write-Host $hash.Time
    

	
    if ($HttpsEnabled) {
        Add-PodeEndpoint -Address * -Port $Port -Protocol Https -CertificateThumbprint $Certificate -CertificateStoreLocation LocalMachine
         #Debug-Log " https"
    }
    else {
        Add-PodeEndpoint -Address * -Port $Port -Protocol Http
         #Debug-Log " http"
    }

    Add-PodeRoute -Method Get -Path '/' -ScriptBlock {
        Add-PodeHeader -Name Access-Control-Allow-Origin -Value *
        Add-PodeHeader -Name Access-Control-Allow-Credentials -Value true
        Write-PodeViewResponse -Path 'index'
    }

    Add-PodeRoute -Method Get -Path '/groups' -ScriptBlock {
        Write-PodeViewResponse -Path 'groups'
    }
	
    Add-PodeRoute -Method Get -Path '/reports' -ScriptBlock {
        Write-PodeViewResponse -Path 'reports'
    }

    Add-PodeRoute -Method Get -Path '/computers' -ScriptBlock {
        Write-PodeViewResponse -Path 'computers'
    }

    Add-PodeRoute -Method Get -Path '/gpo' -ScriptBlock {
        Write-PodeViewResponse -Path 'gpo'
    }

    Add-PodeRoute -Method Get -Path '/footer' -ScriptBlock {
        Write-PodeViewResponse -Path 'footer'
    }

    Add-PodeRoute -Method Get -Path '/header' -ScriptBlock {
        Write-PodeViewResponse -Path 'header'
    }

    Add-PodeRoute -Method Get -Path '/scheduling' -ScriptBlock {
        Write-PodeViewResponse -Path 'scheduling'
    }

    Add-PodeRoute -Method Get -Path '/login/:username/:password/:hostname' -ScriptBlock {
        Add-PodeHeader -Name Access-Control-Allow-Origin -Value *
        Add-PodeHeader -Name Access-Control-Allow-Credentials -Value true

        #$WebEvent.Session.Data.username = "rob"
        #$Views = $WebEvent.Session.Data.username

        Write-Host "views = $views"


        $username = $WebEvent.Parameters['username']
        $password = ConvertTo-SecureString ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WebEvent.Parameters['password']))) -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
        $hostname = $WebEvent.Parameters['hostname']

        
        if ($username -eq "null") {
            Debug-Log "Username is null, using local creds"
            $forest = Get-ADForest
            $userCount = (Get-ADUser -Filter *).Count
            $groupCount = (Get-ADGroup -Filter *).Count
            $computerCount = (Get-ADComputer -Filter *).Count
        }
        else {
            Debug-Log "User  $username logged in"
            #Set-PodeCookie -Name 'username' -Value $username
            $password = ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WebEvent.Parameters['password'])))
            $securepass = ConvertTo-SecureString $password -AsPlainText -Force
            $encryptedpass = ConvertFrom-SecureString -SecureString $securepass



            #Set-PodeCookie -Name 'password' -Value  $encryptedpass  -Duration 6000 -Discard
            #Set-PodeCookie -Name 'hostname' -Value $hostname

            Lock-PodeObject -Object $WebEvent.Lockable {
                $hash = (Get-PodeState -Name 'hash')
               
                $hash.Remove("username")
                $hash.Remove("password")
                $hash.Remove("hostname")

                $hash.Add("username", $username)
                $hash.Add("password", $encryptedpass)
                $hash.Add("hostname", $hostname)
            }

            $forest = Get-ADForest -Credential $psCred -Server $hostname
            $userCount = (Get-ADUser -Filter * -Credential $psCred -Server $hostname).Count
            $groupCount = (Get-ADGroup -Filter * -Credential $psCred -Server $hostname).Count
            $computerCount = (Get-ADComputer -Filter * -Credential $psCred -Server $hostname).Count
           
        }
        Debug-Log "forest = $forest, users = $userCount, groups = $groupCount, computers = $computerCount"
        Write-PodeJsonResponse -Value @{ 'forest' = $forest
            'userCount'                           = $userCount
            'groupCount'                          = $groupCount
            'computerCount'                       = $computerCount 
        }

    }

    Add-PodeRoute -Method Get -Path '/scheduleReport/:reportName/:daysSelect/:fromEmailAddress/:emailRecipients/:frequency/:smtpserver' -ScriptBlock { 
        if (Test-PodeCookie -Name 'password') {
            Debug-Log " cookie sset"
            $user = Get-PodeCookie -Name 'username' -Raw
            $pass = Get-PodeCookie -Name 'password' -Raw
            $password = $pass.Value
            $username = $user.Value
            $hostname = Get-Hostname
            $reportname = $WebEvent.Parameters['reportName']
            $daysSelect = $WebEvent.Parameters['daysSelect']
            $fromEmailAddress = $WebEvent.Parameters['fromEmailAddress']
            $emailRecipients = $WebEvent.Parameters['emailRecipients']
            # $frequency = $WebEvent.Parameters['frequency']
            $smtpserver = $WebEvent.Parameters['smtpserver']
            New-Item -Path "C:\reports" -Name "setCreds.ps1" -ItemType "file" -Force -Value "
#`$password=$($password)
#`$securepass = ConvertTo-SecureString `$password -AsPlainText -Force
#ConvertFrom-SecureString -SecureString `$securepass | set-content 'C:\reports\QufnrnX'
New-Item -Path 'C:\reports' -Name 'QufnrnX' -ItemType 'file' -Force -Value $($password)
(get-item C:\reports\QufnrnX).Attributes += 'Hidden'
            "
            $reportName = $WebEvent.Parameters['reportName']
            $reportNameTrimmed = $reportName.replace(' ', '')
            New-Item -Path "C:\reports" -Name "$($reportNameTrimmed).ps1" -ItemType "file" -Force -Value "
[System.Uri]`$Uri = 'https://localhost:$($Port)/report/$($reportName)/$($daysSelect)' # Add the Uri 
`$Cookie = New-Object System.Net.Cookie
`$Cookie.Name = 'username' # Add the name of the cookie
`$Cookie.Value = '$($username)' # Add the value of the cookie
`$Cookie.Domain = `$uri.DnsSafeHost
`$securepass = Get-Content 'C:\reports\QufnrnX' | ConvertTo-SecureString 
`$encryptedpass = ConvertFrom-SecureString -SecureString `$securepass
`$Cookie2 = New-Object System.Net.Cookie
`$Cookie2.Name = 'password' # Add the name of the cookie
`$Cookie2.Value = `$encryptedpass # Add the value of the cookie
`$Cookie2.Domain = `$uri.DnsSafeHost
`$Cookie3 = New-Object System.Net.Cookie
`$Cookie3.Name = 'hostname' # Add the name of the cookie
`$Cookie3.Value = '$($hostname)' # Add the value of the cookie
`$Cookie3.Domain = `$uri.DnsSafeHost
`$WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
`$WebSession.Cookies.Add(`$Cookie)
`$WebSession.Cookies.Add(`$Cookie2)
`$WebSession.Cookies.Add(`$Cookie3)
`$props = @{
    Uri         = `$uri.AbsoluteUri
    WebSession  = `$WebSession
}
`$users = Invoke-RestMethod @props | ConvertTo-Json | ConvertFrom-Json | Select -expand users 
Invoke-RestMethod @props | ConvertTo-Json | ConvertFrom-Json | Select-Object -expand users | Export-Csv -Path C:\reports\$($reportNameTrimmed).csv
Send-MailMessage -From 'AD Reporting Tool <$($fromEmailAddress)>' -To 'AD Report Recipients $($emailRecipients)' -Subject '$($reportNameTrimmed)' -SmtpServer $($smtpserver) -Attachments C:\reports\$($reportNameTrimmed).csv
"           
            $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument C:\reports\$reportNameTrimmed.ps1
            $trigger = New-ScheduledTaskTrigger -Daily -At 5:08pm
            $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -TaskPath "ADReportingTasks" -TaskName "$($reportNameTrimmed)" -Description "This task calls the $reportName report"
            $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument C:\reports\setCreds.ps1
            $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(4);
            $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -TaskPath "ADReportingTasks" -TaskName "setCreds" -Description "This task sets creds"
            # Start-Sleep -s 5
            # Unregister-ScheduledTask -TaskName setCreds -Confirm:$false #  TODO restore
            Write-PodeJsonResponse -Value @{ 'success' = "true" }
        }
        else {
            Debug-Log " cookie not set"
            Write-PodeJsonResponse -Value @{ 'success' = 'null'; }
        }
    }
    
    Add-PodeRoute -Method Get -Path '/disableUsers/:userList' -ScriptBlock {
        #if (Test-PodeCookie -Name 'password') {
        if (Check-Auth) {
            Debug-Log " disableUser: cookie set"
            $users = $WebEvent.Parameters['userList']
            $usersSeparated = $users.Split(",")
            foreach ($user in $usersSeparated) {
                Debug-Log " user to disable is  $user"
                Disable-ADAccount -Identity $user
                # TODO : grey out boxes of already disabled users, display success message, model partial success
            }
            Write-PodeJsonResponse -Value @{ 'success' = "true" }
        }
        else {
            Debug-Log " disableUser: user not logged in"
            Write-PodeJsonResponse -Value @{ 'success' = 'null'; }
        }
    }

    Add-PodeRoute -Method Get -Path '/getOU/:domain' -ScriptBlock {

        #Lock-PodeObject -Object $WebEvent.Lockable {
        #    $hash = (Get-PodeState -Name 'hash')
        #    $hostname = $hash.hostname
        #}


        #if (Test-PodeCookie -Name 'password') {
        #if ($hostname -ne $null) {

        if (Check-Auth) {
            Debug-Log " getOU : user is logged in"
            try {
                $psCred = Get-UserAuth
                $hostname = Get-Hostname
                $ou = Get-ADOrganizationalUnit -Filter * -Credential $psCred -Server $hostname
                #todo need to include domain
                Write-PodeJsonResponse -Value @{ 'ou' = $ou }
            }
            catch { 
                Debug-Log " error retreiving domain"
                Debug-Log $_
                Write-PodeJsonResponse -Value @{ 'ou' = 'null'; }
            }
        }
        else {
            Debug-Log " getOU : user not logged in"
            Write-PodeJsonResponse -Value @{ 'ou' = 'null'; }
        }
    }

    Add-PodeRoute -Method Get -Path '/discovergroups/:groupType' -ScriptBlock {
        if (Check-Auth) {
        #if (Test-PodeCookie -Name 'password') {
            Debug-Log "  discovergroups : user is logged in"

            $psCred = Get-UserAuth
            $hostname = Get-Hostname
            $groupType = $WebEvent.Parameters['groupType']
            Debug-Log "Group Type  $groupType"
            try { 
                $Groups = Get-ADGroup -Filter "GroupScope -eq '$($groupType)'" -Credential $psCred -Server $hostname
                Write-Host "Got Groups"
                $simplegroups = @()
                foreach ($group in $Groups) {
                    Write-Host "Group Name: $($group.name)"
                    $parentgroups = ""
                    Write-Host "Getting members"
                    $GroupMembers = @(Get-ADGroupMember -Identity $group -Credential $psCred -Server $hostname)
                    Write-Host "Got members"
                    $membercount = $GroupMembers.count
                    Write-Host "Group Member Count: $($membercount)"
                    $GroupMembership = Get-ADPrincipalGroupMembership -Identity $group -Credential $psCred -Server $hostname
                    foreach ($parentgroup in $GroupMembership) {
                        Write-Host "Parent Group: $($parentgroup.name)"
                        $parentgroups += $parentgroup.name + ", " # TODO remove trailing semicolon
                    }
                    $simplegroups += @{Groupname = $group.name; Membercount = $membercount; ParentGroups = $parentgroups }
                }
                Debug-Log " Groups : $simplegroups"
                Write-PodeJsonResponse -Value @{ 'groups' = $simplegroups; }
            }
            catch { 
                Debug-Log " error retreiving groups"
                Debug-Log $_
                Write-PodeJsonResponse -Value @{ 'groups' = 'null'; }
            }
        }
        else {
            Debug-Log " discovergroups : user not logged in"
            Write-PodeJsonResponse -Value @{ 'groups' = 'null'; }
        }
    }
	
    <#
    Add-PodeRoute -Method Get -Path '/group/:groupName' -ScriptBlock {
        if (Check-Auth) {
            Debug-Log " getgroups : the user is logged in"
            $psCred = Get-UserAuth
            $hostname = Get-Hostname
            $group = $WebEvent.Parameters['groupName']

            try {
                $GroupMembers = Get-ADGroupMember -Identity $group -Credential $psCred -Server $hostname
		
                $users = @()
                foreach ($user in $GroupMembers) {
                    if ($user.objectClass -eq "user") {
                        $LastLogonDate = Get-ADUser -Identity $user.SamAccountName -Properties "LastLogonDate" | Select-Object LastLogonDate -Credential $psCred -Server $hostname
                        $users += @{Username = $user.name; Type = $user.objectClass; LastLogonDate = $LastLogonDate.LastLogonDate }
                    }
                    else {
                        $users += @{Username = $user.name; Type = $user.objectClass }
                    }
                }
		
                # return the users
                Write-PodeJsonResponse -Value @{
                    users = $users
                }
             
            }
            catch { 
                Debug-Log " error retreiving group members"
                Debug-Log " $_"
                Write-PodeJsonResponse -Value @{ 'users' = 'null'; }
            }
        }
        else {
            Debug-Log " getgroups : user not logged in"
            Write-PodeJsonResponse -Value @{ 'users' = 'null'; }
        }
    }
    #>
    Add-PodeRoute -Method Get -Path '/groups/:groupNames' -ScriptBlock {
        if (Check-Auth) {

            Debug-Log " getgroups : user is logged in"
            # get the users
            try {
                $psCred = Get-UserAuth
                $hostname = Get-Hostname
                $groups = $WebEvent.Parameters['groupNames']
                $groupsSeparated = $groups.Split(",")
                $totalUsers = @()
                foreach ($group in $groupsSeparated) {
                    $GroupMembers = Get-ADGroupMember -Identity $group -Credential $psCred -Server $hostname
                    $users = @()
                    foreach ($user in $GroupMembers) {
                        if ($user.objectClass -eq "user") {
                            $LastLogonDate = Get-ADUser -Identity $user.SamAccountName -Credential $psCred -Server $hostname -Properties "LastLogonDate" | Select-Object LastLogonDate 
                            $users += @{Username = $user.name; Type = $user.objectClass; LastLogonDate = $LastLogonDate.LastLogonDate }
                        }
                        else {
                            $users += @{Username = $user.name; Type = $user.objectClass }
                        }
                    }
                    $totalUsers += @{GroupName = $group; Group = $users }
                }

                Debug-Log " Users :$totalUsers"
                # return the users
                Write-PodeJsonResponse -Value @{
                    users = $totalUsers
                }
            }
            catch { 
                Debug-Log " error retreiving group members"
                Debug-Log " $_"
                Write-PodeJsonResponse -Value @{ 'users' = 'null'; }
            }
        }
        else {
            Debug-Log " getgroups : user not logged in"
            Write-PodeJsonResponse -Value @{ 'users' = 'null'; }
        }
        
    }
	
    Add-PodeRoute -Method Get -Path '/report/:reportName/:daysFilter/:quickQuery' -ScriptBlock {
        #$Views = $WebEvent.Session.Data.username

        #Write-Host "views = $views"
        

        if (Check-Auth) {

       
            Debug-Log " Computers : user is logged in"
       

            Debug-Log " getting users"
            $psCred = Get-UserAuth
            $hostname = Get-Hostname

            <#
            if (Test-PodeCookie -Name 'password') {  
                Debug-Log " users : cookie is set"
                $psCred = Get-UserAuth
                $hostname = Get-Hostname
            }
            else {
                Debug-Log " users : the cookie is not set, using local creds"
                Write-Host $Localinstall
                Write-Host $Localinstall
                Write-Host $HttpsEnabled

                if ($Localinstall) {
                    $psCred   = "null"
                    $hostname = "null"
                    Debug-Log " users : local install is true"
                
                }
                else {
                    Debug-Log " users : local install is false"
                    Write-PodeJsonResponse -Value @{ users = 'null'; 

                }

                }
            }
            #>

                try {
                    $queryStart = (Get-Date)
                    $reportName = $WebEvent.Parameters['reportName']
                    $daysFilter = $WebEvent.Parameters['daysFilter']
                    $quickQuery = $WebEvent.Parameters['quickQuery']
                    Write-Host "Quick Query: $($quickQuery)"
                    Write-Host "Report name is: $($reportName)"
                
                    $UserList = Get-Filter $reportName $daysFilter $psCred $hostname
                    $users = @()
                    foreach ($user in $UserList) {
                        if ($user.objectClass -eq "user") {
                            if ($quickQuery -eq "false") {    
                                $MembersOfList = ""
                                $GroupMembership = Get-ADPrincipalGroupMembership -Identity $user -Credential $psCred -Server $hostname
                                foreach ($parentgroup in $GroupMembership) {
                                    $MembersOfList += $parentgroup.name + "; " #TODO remove trailing semicolon
                                }
                            }
                            $users += @{Username      = $user.name;
                                Type                  = $user.objectClass;
                                LastLogonDate         = $user.LastLogonDate;
                                DistinguishedName     = $user.DistinguishedName;
                                ObjectGuid            = $user.ObjectGuid;
                                BadLogonCount         = $user.BadLogonCount;
                                Created               = $user.Created;
                                Deleted               = $user.Deleted;
                                Enabled               = $user.Enabled;
                                LockedOut             = $user.LockedOut;
                                MemberOf              = $MembersOfList;
                                PasswordLastSet       = $user.PasswordLastSet;
                                PasswordExpired       = $user.PasswordExpired;
                                PasswordNeverExpires  = $user.PasswordNeverExpires;
                                AccountExpirationDate = $user.AccountExpirationDate;
                                SamAccountName        = $user.SamAccountName
                            }
                        }
                        else {
                            $users += @{Username = $user.name; Type = $user.objectClass }
                        }
                    }
                    $queryEnd = (Get-Date)
                    $totalQueryTime = ([math]::Round((New-Timespan -Start $queryStart -End $queryEnd).TotalSeconds))
                    Debug-Log "totalQueryTime = $($totalQueryTime)"
                    Write-PodeJsonResponse -Value @{
                        users     = $users
                        queryTime = $totalQueryTime
                    }
                }
                 catch { 
                     Debug-Log " error retreiving users"
                     Debug-Log " $_"
                     Write-PodeJsonResponse -Value @{ users = 'null'; } #TODO - display error on screen?
                }
        
           }
           else {
                Debug-Log " Users : user not logged in, returing to login page"
                Write-PodeJsonResponse -Value @{ users = 'null'; } #TODO - display error on screen?
           }
       }

    

    Add-PodeRoute -Method Get -Path '/report/computers/:reportName/:daysFilter/:ou/:quickQuery' -ScriptBlock {
         #Wif (Test-PodeCookie -Name 'password') {
        if (Check-Auth) {
            Debug-Log "computers: user is logged in"
            try {
                $queryStart = (Get-Date)
                $reportName = $WebEvent.Parameters['reportName']
                $daysFilter = $WebEvent.Parameters['daysFilter']
                $ou = $WebEvent.Parameters['ou']
                $quickQuery = $WebEvent.Parameters['quickQuery']
                #Write-Host "OU: $($ou)"
                #Write-Host "Quick Query: $($quickQuery)"
                $psCred = Get-UserAuth
                $hostname = Get-Hostname
                $ComputerList = Get-Filter $reportName $daysFilter $psCred $hostname $ou
                $queryLoopStart = (Get-Date)
                $computers = @()
                foreach ($computer in $ComputerList) {

                    if ($quickQuery -eq "false") {
                        Write-Host "Quick query is false" $computer

                        $MembersOfList = ""
                        $GroupMembership = Get-ADPrincipalGroupMembership -Identity $computer -Credential $psCred -Server $hostname
                        foreach ($parentgroup in $GroupMembership) {
                            $MembersOfList += $parentgroup.name + "; " # TODO remove trailing semicolon
                        }
                        try {
                            $ip = Resolve-DnsName -Name $computer.DNSHostName -Type A -Server $hostname
                            $ipAddress = $ip.IPAddress;

                        }
                        catch {
                            Debug-Log $_
                            $ipAddress = "Not avaialable"
                            Debug-Log "IP not available for $($computer.DNSHostName)"
                        }
    
                        try {
                            $computerDetails = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName $ipAddress | 
                            Sort-Object -Property LastLogon -Descending | 
                            Select-Object -Property * -First 1 | 
                            Where-Object {$_.LastLogon -match "(\d{14})"} | 
                            Foreach-Object { New-Object PSObject -Property @{ Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}}
                            $lastLogonDate     = $computerDetails.LastLogon;
                            $lastLogonUserName = $computerDetails.Name;
                        } 
                        catch {
                            Debug-Log "Error retreiving computer details"
                            Debug-Log $_
                            $lastLogonDate = "null";
                            $lastLogonUserName = "null";

                        }



                    
                        Write-Host $computerDetails
                        Write-Host $lastLogonDate
                        Write-Host $lastLogonUserName


 
                    
                    }
                    $computers += @{ComputerName = $computer.DNSHostName;
                        LastLogonDate            = $computer.LastLogonDate;
                        DistinguishedName        = $computer.DistinguishedName;
                        ObjectGuid               = $computer.ObjectGuid;
                        BadLogonCount            = $computer.BadLogonCount;
                        Created                  = $computer.Created;
                        Deleted                  = $computer.Deleted;
                        Enabled                  = $computer.Enabled;
                        LockedOut                = $computer.LockedOut;
                        MemberOf                 = $MembersOfList;
                        PasswordLastSet          = $computer.PasswordLastSet;
                        PasswordExpired          = $computer.PasswordExpired;
                        PasswordNeverExpires     = $computer.PasswordNeverExpires;
                        IPv4Address              = $ipAddress;
                        OperatingSystem          = $computer.OperatingSystem;
                        OperatingSystemVersion   = $computer.OperatingSystemVersion;
                        LastLogonUserDate        = $lastLogonDate;
                        LastLogonUserName        = $lastLogonUserName;
                    }
                }
                $queryEnd = (Get-Date)
                $totalQueryTime = ([math]::Round((New-Timespan -Start $queryStart -End $queryEnd).TotalSeconds))
                $loopQueryTime = ([math]::Round((New-Timespan -Start $queryLoopStart -End $queryEnd).TotalSeconds))
                Debug-Log "totalQueryTime = $($totalQueryTime)"
                Debug-Log "loopQueryTime = $($loopQueryTime)"
                Write-PodeJsonResponse -Value @{
                    computers = $computers
                    queryTime = $totalQueryTime
                }
            }
             catch { 
                 Debug-Log " error retreiving computers"
                 Debug-Log " $_"
                 Write-PodeJsonResponse -Value @{ computers = 'null'; } #TODO - display error on screen?
            }
        }
        else {
            Debug-Log "computers: user not logged in, redirecting to login page"
            Write-PodeJsonResponse -Value @{ computers = 'null'; }
        }
    }

    Add-PodeRoute -Method Get -Path '/report/gpo/:reportName/:daysFilter' -ScriptBlock {
         # if (Test-PodeCookie -Name 'password') {  
        if (Check-Auth) {
            Debug-Log "gpo : user is logged in"
            try { 
                $reportName = $WebEvent.Parameters['reportName']
                $daysFilter = $WebEvent.Parameters['daysFilter']
                # $ou = $WebEvent.Parameters['ou']
                # Write-Host "OU: " + $ou
                $psCred = Get-UserAuth
                $hostname = Get-Hostname
                Debug-Log "report is $($reportName)"
                $GPOList = Get-Filter $reportName $daysFilter $psCred $hostname
                $gpos = @()
                foreach ($gpo in $GPOList) {                
                    $gpoDetail = Get-GPOReport -Name $gpo.DisplayName -ReportType HTML # S-Server $hostname
                    $gpos += @{DisplayName = $gpo.DisplayName;
                        DomainName         = $gpo.DomainName;
                        CreationTime       = $gpo.CreationTime;
                        ModificationTime   = $gpo.ModificationTime;
                        GpoStatus          = $gpo.GpoStatus;
                        Description        = $gpo.Description;
                        GPODetail          = $gpoDetail;
                    }    
                }
                Write-PodeJsonResponse -Value @{
                    gpo = $gpos
                }
            }
             catch { 
                 Debug-Log " error retreiving domain"
                 Debug-Log " $_"
                 Write-PodeJsonResponse -Value @{ gpo = 'null'; }
    }
        }
        else {
            Debug-Log "gpo : user is not logged in, redirecting to login page"
            Write-PodeJsonResponse -Value @{ gpo = 'null'; }
        }
    }

    <#
     Add-PodeRoute -Method Get -Path '/extended/:computerName' -ScriptBlock {
         #if (Test-PodeCookie -Name 'password') {   
            $computerName = $WebEvent.Parameters['computerName']
            #TODO need to pass creds
           
            $computerDetails = Get-WmiObject -Class Win32_NetworkLoginProfile -ComputerName $computerName | 
            Sort-Object -Property LastLogon -Descending | 
            Select-Object -Property * -First 1 | 
            Where-Object {$_.LastLogon -match "(\d{14})"} | 
            Foreach-Object { New-Object PSObject -Property @{ Name=$_.Name;LastLogon=[datetime]::ParseExact($matches[0], "yyyyMMddHHmmss", $null)}}


           
            Write-PodeJsonResponse -Value @{
                computerDetails = $computerDetails
             }
         #}
        # else {
         #    Write-Host "cookie is not set, redirecting to login page"
         #    Write-PodeJsonResponse -Value @{ computerDetails  = 'null'; }
        # }
    }
    #>

}

function Get-UserAuth {

    Lock-PodeObject -Object $WebEvent.Lockable {
        $hash = (Get-PodeState -Name 'hash')
        $user = $hash.username
        $passwd = $hash.password
    }

    Write-Host "the user is : $($user)"
    Write-Host "the passwd is : $($passwd)"


    #$user = Get-PodeCookie -Name 'username' -Raw
    #$passwd = Get-PodeCookie -Name 'password' -Raw
    $host1 = Get-PodeCookie -Name 'hostname' -Raw
    #$password = ConvertTo-SecureString $passwd.Value

    $password = ConvertTo-SecureString $passwd

    Write-Host "user is : $($user)"
    Write-Host "host is : $($host1)"

    Write-Host "password is : $($password)"

    #$username = "DOMAIN\$($user.Value)" # TODO need to add domain here   logoncount
    $username = "DOMAIN\$($user)"


    $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
    Write-Host "psCred created"
    return $psCred
}

function Check-Auth {


    Lock-PodeObject -Object $WebEvent.Lockable {
        $hash = (Get-PodeState -Name 'hash')
        $hostname = $hash.hostname
    }
    Debug-Log "hostname is  $hostname"


    if ($hostname -ne $null) {
        Debug-Log " Check-Auth : user is logged in"
        return $true
    }
    else {
        Debug-Log " Check-Auth : user is not logged in"
        return $false
    }

}


function Get-Hostname {
    Lock-PodeObject -Object $WebEvent.Lockable {
        $hash = (Get-PodeState -Name 'hash')
        $hostname = $hash.hostname
    }

    #$host1 = Get-PodeCookie -Name 'hostname' -Raw
    #$hostname = $host1.Value
    return $hostname
}

function Debug-Log {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $data
    )
    Write-Host $data
    $date = Get-Date -Format "dd/MM/yyyy HH:mm"
    $output = -join($date, " ", $data);
    Add-Content -Path C:\cyber-ad-tool\logs\output.log -Value $output
}

function Get-Filter {
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        # [ValidatePattern('^Some.*')]
        [string] $report,
        [Parameter(Mandatory = $true, Position = 1)]
        # [ValidateRange(10,100)]
        [int] $days,
        [Parameter(Mandatory = $true, Position = 2)]
        $userObj,
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $hostname,
        [Parameter(Mandatory = $false, Position = 4)]
        [string] $ou
    )


    try {
        if ($userObj -eq "null") {
            Debug-Log " Get-Domain : using local creds"
            $dn = Get-ADDomain
        }
        else {
            Debug-Log " Get-Filter : using server creds to retreive Domain"
            $dn = Get-ADDomain -Credential $userObj -Server $hostname
        }
        if ($ou -eq "All") {
            $searchBase = $dn.ToString()
        }
        else {
            $searchBase = $ou
        }
    }
    catch { 
        Debug-Log " error retreiving domain"
        Debug-Log " $_"
        
    }


    $daysOffset = (get-date).adddays(-$days)
    
    Debug-Log " Report name is : $($report)"

    if ($userObj -eq "null") {
       
        $filter = switch ($report) {
            "All Users" { Get-ADUser -properties * -Filter * | sort-object name }
            "Users Never Logged On" { Get-ADUser -properties * -Filter '-not ( lastlogontimestamp -like "*")' }
            "Users Not Recently Logged On" { Get-ADUser -properties * -Filter 'lastlogondate -notlike "*" -OR lastlogondate -le $daysOffset' }
            "Locked Out Users" { Search-ADAccount -LockedOut  }
            "Disabled Users" { Search-ADAccount -AccountDisabled  }
            "Recently Created Users" { Get-ADUser -properties * -Filter 'created -ge $daysOffset' }
            "Account Expired Users" { Search-ADAccount -AccountExpired }
            "Soon-to-expire User Accounts" { $daysOffset = (get-date).adddays($days); Get-ADUser -properties * -Filter "AccountExpirationDate -le $($daysOffset)" }
            "Members of Domain Local Administrators Group" { Get-ADGroupMember  "Administrators" | Where-Object { $_.objectClass -eq "user" } }
            "Members of Domain Admins Group" { Get-ADGroupMember  "Domain Admins" | Where-Object { $_.objectClass -eq "user" } }
            "Users in more than one group" { Get-ADUser -Filter * -Properties * | Where-Object { $_.memberOf.count -gt 1 } }
            "Recently deleted users" { Get-ADObject -IncludeDeletedObjects -properties * -Filter { objectClass -eq "user" } } #TODO need to fix
            "Recently modified users" { Get-ADUser -properties * -Filter "modified -ge $($daysOffset)" }
            "Users with logon script" { Get-ADUser -Filter * -Properties * | Where-Object { $_.scriptPath.length -gt 0 } }
            "Users without logon script" { Get-ADUser -Filter * -Properties * | Where-Object { $_.scriptPath.length -eq 0 } }
            "Account never expires users" { Get-ADUser -Filter * -Properties * | Where-Object { $_.accountExpirationDate.length -eq 0 } }
            "Recently logged on users" { Get-ADUser -properties * -Filter "lastLogondate -ge $($daysOffset)" }
            "Dial in allowed users" { Get-ADUser -properties * -Filter * | Where-Object { $_.msNPAllowDialin -eq $true } }
            "Users with non restricted logon times" { Get-ADUser -properties logonHours  -Filter * | Where-Object { $null -eq $_.logonHours } }
            "Admin users with expired passwords" { get-ADGroup -Filter "Name -like '*Admin*'"  | Get-ADGroupMember | Where-Object { $_.objectClass -eq "user" } | Get-ADUser -properties PasswordExpired | Where-Object { $_.PasswordExpired -ne $false } | sort-object -unique name }
            "All Computers" { Get-ADComputer -properties * -Filter * -SearchBase $searchBase }
            "Computers Not Recently Logged On" { Get-ADComputer -properties * -Filter { LastLogonTimeStamp -lt $daysOffset } -SearchBase $searchBase }
            "Recently Created Computers" { Get-ADComputer -properties * -Filter "created -ge $($daysOffset)" }
            "All GPOs" { Invoke-Command  -ComputerName localhost -ScriptBlock { Get-GPO -All } }   
        }
    }
    else {
        
        $filter = switch ($report) {
            "All Users" { Get-ADUser -properties * -Filter * -Credential $userObj -Server $hostname | sort-object name }
            "Users Never Logged On" { Get-ADUser -properties * -Filter '-not ( lastlogontimestamp -like "*")' -Credential $userObj -Server $hostname }
            "Users Not Recently Logged On" { Get-ADUser -properties * -Filter 'lastlogondate -notlike "*" -OR lastlogondate -le $daysOffset' -Credential $userObj -Server $hostname }
            "Locked Out Users" { Search-ADAccount -LockedOut -Credential $userObj -Server $hostname }
            "Disabled Users" { Search-ADAccount -AccountDisabled -Credential $userObj -Server $hostname }
            "Recently Created Users" { Get-ADUser -properties * -Filter 'created -ge $daysOffset' -Credential $userObj -Server $hostname }
            "Account Expired Users" { Search-ADAccount -AccountExpired -Credential $userObj -Server $hostname }
            "Soon-to-expire User Accounts" { $daysOffset = (get-date).adddays($days); Get-ADUser -properties * -Filter "AccountExpirationDate -le $($daysOffset)" -Credential $userObj -Server $hostname }
            "Members of Domain Local Administrators Group" { Get-ADGroupMember  "Administrators" -Credential $userObj -Server $hostname | Where-Object { $_.objectClass -eq "user" } }
            "Members of Domain Admins Group" { Get-ADGroupMember  "Domain Admins" -Credential $userObj -Server $hostname | Where-Object { $_.objectClass -eq "user" } }
            "Users in more than one group" { Get-ADUser -Filter * -Properties * -Credential $userObj -Server $hostname | Where-Object { $_.memberOf.count -gt 1 } }
            "Recently deleted users" { Get-ADObject -IncludeDeletedObjects -properties * -Filter { objectClass -eq "user" } -Credential $userObj -Server $hostname } #TODO need to fix
            "Recently modified users" { Get-ADUser -properties * -Filter "modified -ge $($daysOffset)" -Credential $userObj -Server $hostname }
            "Users with logon script" { Get-ADUser -Filter * -Properties * -Credential $userObj -Server $hostname | Where-Object { $_.scriptPath.length -gt 0 } }
            "Users without logon script" { Get-ADUser -Filter * -Properties * -Credential $userObj -Server $hostname | Where-Object { $_.scriptPath.length -eq 0 } }
            "Account never expires users" { Get-ADUser -Filter * -Properties * -Credential $userObj -Server $hostname | Where-Object { $_.accountExpirationDate.length -eq 0 } }
            "Recently logged on users" { Get-ADUser -properties * -Filter "lastLogondate -ge $($daysOffset)" -Credential $userObj -Server $hostname }
            "Dial in allowed users" { Get-ADUser -properties * -Filter *  -Credential $userObj -Server $hostname | Where-Object { $_.msNPAllowDialin -eq $true } }
            "Users with non restricted logon times" { Get-ADUser -properties logonHours  -Filter *  -Credential $userObj -Server $hostname | Where-Object { $null -eq $_.logonHours } }
            "Admin users with expired passwords" { get-ADGroup -Credential $userObj -Server $hostname -Filter "Name -like '*Admin*'"  | Get-ADGroupMember -Credential $userObj -Server $hostname | Where-Object { $_.objectClass -eq "user" } | Get-ADUser -properties PasswordExpired -Credential $userObj -Server $hostname | Where-Object { $_.PasswordExpired -ne $false } | sort-object -unique name }
            "All Computers" { Get-ADComputer -properties * -Filter * -SearchBase $searchBase -Credential $userObj -Server $hostname }
            "Computers Not Recently Logged On" { Get-ADComputer -properties * -Filter { LastLogonTimeStamp -lt $daysOffset } -SearchBase $searchBase -Credential $userObj -Server $hostname }
            "Recently Created Computers" { Get-ADComputer -properties * -Filter "created -ge $($daysOffset)" -Credential $userObj -Server $hostname }
            "All GPOs" { Invoke-Command -Credential $userObj  -ComputerName localhost -ScriptBlock { Get-GPO -All -Server $hostname } }
        }

    
    }
    Debug-Log " Result : $($filter)"
 
    return $filter
}