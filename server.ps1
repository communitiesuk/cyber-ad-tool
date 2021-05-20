#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
#Install-WindowsFeature RSAT-AD-PowerShell
#Install-Module -Name Pode

Import-Module -Name 'Pode'
Import-Module ActiveDirectory

Start-PodeServer {
	New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging
	New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging
	
    Add-PodeEndpoint -Address * -Port 8080 -Protocol Http

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
		$username = $WebEvent.Parameters['username']
		$password = ConvertTo-SecureString $WebEvent.Parameters['password'] -AsPlainText -Force
		$psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
		$hostname = $WebEvent.Parameters['hostname']
		
		Set-PodeCookie -Name 'username' -Value $username

        $password = $WebEvent.Parameters['password']
        $securepass = ConvertTo-SecureString $password -AsPlainText -Force
        $encryptedpass = ConvertFrom-SecureString -SecureString $securepass

        Set-PodeCookie -Name 'password' -Value  $encryptedpass  -Duration 6000 -Discard
		Set-PodeCookie -Name 'hostname' -Value $hostname

		$domain=Get-ADDomain -Credential $psCred
		$forest=Get-ADForest -Credential $psCred -Server $hostname
        
        $userCount = (Get-ADUser -Filter * -Credential $psCred -Server $hostname).Count
        $groupCount = (Get-ADGroup -Filter * -Credential $psCred -Server $hostname).Count
        $computerCount = (Get-ADComputer -Filter * -Credential $psCred -Server $hostname).Count

		Write-PodeJsonResponse -Value @{ 'forest' = $forest
                                         'userCount' = $userCount
                                         'groupCount' = $groupCount
                                         'computerCount' = $computerCount }



    }
	
    Add-PodeRoute -Method Get -Path '/scheduleReport/:reportName/:daysSelect/:fromEmailAddress/:emailRecipients/:frequency/:smtpserver' -ScriptBlock { 
	    if (Test-PodeCookie -Name 'password') {

			$psCred = User-Auth

            
            $user=Get-PodeCookie -Name 'username' -Raw
	        $pwd=Get-PodeCookie -Name 'password' -Raw
	        $host=Get-PodeCookie -Name 'hostname' -Raw
            $pass = ConvertTo-SecureString $pwd.Value -AsPlainText -Force
            $password = $pwd.Value

            $username = $user.Value

            $hostname =  Get-Hostname
            $reportname = $WebEvent.Parameters['reportName']
            $daysSelect = $WebEvent.Parameters['daysSelect']
            $fromEmailAddress = $WebEvent.Parameters['fromEmailAddress']
            $emailRecipients = $WebEvent.Parameters['emailRecipients']
            $frequency = $WebEvent.Parameters['frequency']
            $smtpserver = $WebEvent.Parameters['smtpserver']



            New-Item -Path "C:\reports" -Name "setCreds.ps1" -ItemType "file" -Force -Value "
#`$password=$password
#`$securepass = ConvertTo-SecureString `$password -AsPlainText -Force
#ConvertFrom-SecureString -SecureString `$securepass | set-content 'C:\reports\QufnrnX'
New-Item -Path 'C:\reports' -Name 'QufnrnX' -ItemType 'file' -Force -Value $password
(get-item C:\reports\QufnrnX).Attributes += 'Hidden'
            "
            

		    $reportName = $WebEvent.Parameters['reportName']
            $reportNameTrimmed = $reportName.replace(' ','')
		    
            New-Item -Path "C:\reports" -Name "$reportNameTrimmed.ps1" -ItemType "file" -Force -Value "
[System.Uri]`$Uri = 'http://localhost:8080/report/$reportName/$daysSelect' # Add the Uri 
`$Cookie = New-Object System.Net.Cookie
`$Cookie.Name = 'username' # Add the name of the cookie
`$Cookie.Value = '$username' # Add the value of the cookie
`$Cookie.Domain = `$uri.DnsSafeHost

`$securepass = Get-Content 'C:\reports\QufnrnX' | ConvertTo-SecureString 
`$encryptedpass = ConvertFrom-SecureString -SecureString `$securepass



`$Cookie2 = New-Object System.Net.Cookie
`$Cookie2.Name = 'password' # Add the name of the cookie
`$Cookie2.Value = `$encryptedpass # Add the value of the cookie
`$Cookie2.Domain = `$uri.DnsSafeHost

`$Cookie3 = New-Object System.Net.Cookie
`$Cookie3.Name = 'hostname' # Add the name of the cookie
`$Cookie3.Value = '$hostname' # Add the value of the cookie
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
Invoke-RestMethod @props | ConvertTo-Json | ConvertFrom-Json | Select -expand users | Export-Csv -Path C:\reports\$reportNameTrimmed.csv
Send-MailMessage -From 'AD Reporting Tool <$fromEmailAddress>' -To 'AD Report Recipients $emailRecipients' -Subject '$reportNameTrimmed' -SmtpServer $smtpserver  -Attachments  C:\reports\$reportNameTrimmed.csv
"
            
            $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument C:\reports\$reportNameTrimmed.ps1
            $trigger = New-ScheduledTaskTrigger -Daily -At 5:08pm
            $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -TaskPath "ADReportingTasks" -TaskName "$reportNameTrimmed" -Description "This task calls the $reportName report"


            $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument C:\reports\setCreds.ps1
            $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(4);
            
            $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -TaskPath "ADReportingTasks" -TaskName "setCreds" -Description "This task sets creds"
            #Start-Sleep -s 5
            #Unregister-ScheduledTask -TaskName setCreds -Confirm:$false #  TODO restore
            

		    Write-PodeJsonResponse -Value @{ 'success' = "true" }

		} else {
			Write-Host "cookie not set"
			Write-PodeJsonResponse -Value @{ 'success' = 'null'; }
		}
    }
    
    Add-PodeRoute -Method Get -Path '/disableUsers/:userList' -ScriptBlock {
	    if (Test-PodeCookie -Name 'password') {
			Write-Host "cookie set"
            #$psCred=Get-PodeCookie -Name 'psCred' -Raw -Secret 'hunter2'

			$psCred = User-Auth
            $hostname =  Get-Hostname

		    $users = $WebEvent.Parameters['userList']
		    $usersSeparated =$users.Split(",")
		    
		
		    foreach($user in $usersSeparated) {
                Write-Host "user to disable is " + $user
                Disable-ADAccount -Identity $user
                #TODO : grey out boxes of already disabled users, display success message, model partial success
            }

		    Write-PodeJsonResponse -Value @{ 'success' = "true" }

		} else {
			Write-Host "cookie not set"
			Write-PodeJsonResponse -Value @{ 'success' = 'null'; }
		}
    }

    Add-PodeRoute -Method Get -Path '/getOU/:domain' -ScriptBlock {
	    if (Test-PodeCookie -Name 'password') {
			Write-Host "cookie set"
			$psCred = User-Auth
            $hostname =  Get-Hostname
		    $ou=Get-ADOrganizationalUnit -Filter * -Credential $psCred -Server $hostname

           

            #todo need to include domain
		    Write-PodeJsonResponse -Value @{ 'ou' = $ou }

		} else {
			Write-Host "cookie not set"
			Write-PodeJsonResponse -Value @{ 'ou' = 'null'; }
		}
    }

    Add-PodeRoute -Method Get -Path '/discovergroups/:groupType' -ScriptBlock {
		
		if (Test-PodeCookie -Name 'password') {
			Write-Host "cookie set"
			$psCred = User-Auth
            $hostname =  Get-Hostname
			
			$groupType = $WebEvent.Parameters['groupType']
			
			try { 
				$Groups= Get-ADGroup -Filter "GroupScope -eq '$groupType'" -Credential $psCred -Server $hostname
				Write-Host "Got Groups"
				$simplegroups=@()
				foreach ($group in $Groups) {
					Write-Host "Group Name : " + $group.name
					$parentgroups=""
					Write-Host "Getting members "
					$GroupMembers= @(Get-ADGroupMember -Identity $group -Credential $psCred -Server $hostname)
					Write-Host "Got members "
					$membercount = $GroupMembers.count
					Write-Host "Group Member Count =  : " + $membercount
					
					$GroupMembership = Get-ADPrincipalGroupMembership -Identity $group -Credential $psCred -Server $hostname
					foreach ($parentgroup in $GroupMembership) {
						Write-Host "Parent Group " + $parentgroup.name
						$parentgroups += $parentgroup.name + ", " #TODO remove trailing semicolon
					}
					
					$simplegroups += @{Groupname=$group.name;Membercount=$membercount;ParentGroups=$parentgroups }
				}
				Write-PodeJsonResponse -Value @{ 'groups' = $simplegroups; }
			}
			catch { 
				Write-Host "error getting groups"
				Write-Host $_
				Write-PodeJsonResponse -Value @{ 'groups' = 'null'; }
			}
		} else {
			Write-Host "cookie not set"
			Write-PodeJsonResponse -Value @{ 'groups' = 'null'; }
		}
		
    }
	
	Add-PodeRoute -Method Get -Path '/group/:groupName' -ScriptBlock {
		$psCred = User-Auth
        $hostname =  Get-Hostname
        $group = $WebEvent.Parameters['groupName']
		$GroupMembers= Get-ADGroupMember -Identity $group -Credential $psCred -Server $hostname
		
		$users=@()
		foreach ($user in $GroupMembers) {
			if ($user.objectClass -eq "user") {
				$LastLogonDate = Get-ADUser -Identity $user.SamAccountName -Properties "LastLogonDate" | Select LastLogonDate -Credential $psCred -Server $hostname
				$users += @{Username=$user.name;Type=$user.objectClass;LastLogonDate=$LastLogonDate.LastLogonDate}
			} else {
				$users += @{Username=$user.name;Type=$user.objectClass}
			}
		}
		
        # return the users
        Write-PodeJsonResponse -Value @{
			users = $users
        }
    }
	Add-PodeRoute -Method Get -Path '/groups/:groupNames' -ScriptBlock {
        # get the users
        
		$psCred = User-Auth
        $hostname =  Get-Hostname
		
		$groups = $WebEvent.Parameters['groupNames']
		$groupsSeparated =$groups.Split(",")
		$totalUsers=@()
		
		foreach ($group in $groupsSeparated) {
			$GroupMembers= Get-ADGroupMember -Identity $group -Credential $psCred -Server $hostname
			
			$users=@()
			foreach ($user in $GroupMembers) {
				if ($user.objectClass -eq "user") {
					$LastLogonDate = Get-ADUser -Identity $user.SamAccountName -Credential $psCred -Server $hostname -Properties "LastLogonDate" | Select LastLogonDate 
					$users += @{Username=$user.name;Type=$user.objectClass;LastLogonDate=$LastLogonDate.LastLogonDate}
				} else {
					$users += @{Username=$user.name;Type=$user.objectClass}
				}
			}
			$groupElement="GroupName="+$group
			$totalUsers+= @{GroupName=$group;Group=$users}
			
		}

        # return the users
        Write-PodeJsonResponse -Value @{
			users = $totalUsers
        }
    }
	
	Add-PodeRoute -Method Get -Path '/report/:reportName/:daysFilter/:quickQuery' -ScriptBlock {
         if (Test-PodeCookie -Name 'password') {
           
            $queryStart=(GET-DATE)


            $reportName = $WebEvent.Parameters['reportName']
            $daysFilter = $WebEvent.Parameters['daysFilter']
            $quickQuery = $WebEvent.Parameters['quickQuery']

            Write-Host "Quick Query: " + $quickQuery
            Write-Host "REPORT NAME IS : " + $reportName
            $psCred = User-Auth
            $hostname =  Get-Hostname
           
            $UserList = Get-Filter $reportName $daysFilter $psCred $hostname

          
            

            $users=@()
		    foreach ($user in $UserList) {
			    if ($user.objectClass -eq "user") {
				    
                    if ($quickQuery -eq "false") {    
                        $MembersOfList=""
                        $GroupMembership = Get-ADPrincipalGroupMembership -Identity $user -Credential $psCred -Server $hostname
					    foreach ($parentgroup in $GroupMembership) {
						    
						        $MembersOfList += $parentgroup.name + "; " #TODO remove trailing semicolon
				        }
                    }
                
				    $users += @{Username=$user.name;
                            Type=$user.objectClass;
                            LastLogonDate=$user.LastLogonDate;
                            DistinguishedName=$user.DistinguishedName;
                            ObjectGuid=$user.ObjectGuid;
                            BadLogonCount=$user.BadLogonCount;
                            Created=$user.Created;
                            Deleted=$user.Deleted;
                            Enabled=$user.Enabled;
                            LockedOut=$user.LockedOut;
                            MemberOf=$MembersOfList;
                            PasswordLastSet=$user.PasswordLastSet;
                            PasswordExpired=$user.PasswordExpired;
                            PasswordNeverExpires=$user.PasswordNeverExpires;
                            AccountExpirationDate=$user.AccountExpirationDate;
                            SamAccountName=$user.SamAccountName
                            }

                     

			    } else {
				    $users += @{Username=$user.name;Type=$user.objectClass}
			    }
		    }
            $queryEnd=(GET-DATE)
            $totalQueryTime = ([math]::Round((NEW-TIMESPAN –Start $queryStart –End $queryEnd).TotalSeconds))

            Write-Host " totalQueryTime = $totalQueryTime"

        
            Write-PodeJsonResponse -Value @{
			    users = $users
                queryTime = $totalQueryTime
            }

        } else {
			Write-Host "cookie is not set"
			Write-PodeJsonResponse -Value @{ users = 'null'; }
		}
    }

    Add-PodeRoute -Method Get -Path '/report/computers/:reportName/:daysFilter/:ou/:quickQuery' -ScriptBlock {
         if (Test-PodeCookie -Name 'password') {
        
            $queryStart=(GET-DATE)




            $reportName = $WebEvent.Parameters['reportName']
            $daysFilter = $WebEvent.Parameters['daysFilter']
            $ou = $WebEvent.Parameters['ou']
            $quickQuery = $WebEvent.Parameters['quickQuery']

            Write-Host "OU: " + $ou
            Write-Host "Quick Query: " + $quickQuery

            $psCred = User-Auth
            $hostname =  Get-Hostname
           

            $ComputerList = Get-Filter $reportName $daysFilter $psCred $hostname $ou

          
            $queryLoopStart=(GET-DATE)

            $computers=@()
		    foreach ($computer in $ComputerList) {
			    #if ($user.objectClass -eq "user") {
				    
                    
                if ($quickQuery -eq "false") {    
                    $MembersOfList=""
                    $GroupMembership = Get-ADPrincipalGroupMembership -Identity $computer -Credential $psCred -Server $hostname
					    foreach ($parentgroup in $GroupMembership) {
						    
						    $MembersOfList += $parentgroup.name + "; " #TODO remove trailing semicolon
				    }
                    try {
                         $ip=Resolve-DnsName -Name $computer.DNSHostName -Type A -Server $hostname
                         $ipAddress=$ip.IPAddress;
                    }
                    catch {
                        $ipAddress="Not avaialable"
                        Write-Host "IP not available for $computer.DNSHostName"
                    }
                }

				    $computers += @{ComputerName=$computer.DNSHostName;
                            LastLogonDate=$computer.LastLogonDate;
                            DistinguishedName=$computer.DistinguishedName;
                            ObjectGuid=$computer.ObjectGuid;
                            BadLogonCount=$computer.BadLogonCount;
                            Created=$computer.Created;
                            Deleted=$computer.Deleted;
                            Enabled=$computer.Enabled;
                            LockedOut=$computer.LockedOut;
                            MemberOf=$MembersOfList;
                            PasswordLastSet=$computer.PasswordLastSet;
                            PasswordExpired=$computer.PasswordExpired;
                            PasswordNeverExpires=$computer.PasswordNeverExpires;
                            IPv4Address=$ipAddress;
                            OperatingSystem=$computer.OperatingSystem;
                            OperatingSystemVersion=$computer.OperatingSystemVersion;
                            #IPv4Address=$computer.IPv4Address
                            }

                     

			    #} else {
				#    $users += @{Username=$user.name;Type=$user.objectClass}
			    #}
		    }
       
            $queryEnd=(GET-DATE)
            $totalQueryTime = ([math]::Round((NEW-TIMESPAN –Start $queryStart –End $queryEnd).TotalSeconds))
            $loopQueryTime = ([math]::Round((NEW-TIMESPAN –Start $queryLoopStart –End $queryEnd).TotalSeconds))

            

            Write-Host " totalQueryTime = $totalQueryTime"
            Write-Host " loopQueryTime = $loopQueryTime"


            Write-PodeJsonResponse -Value @{
			    computers = $computers
                queryTime = $totalQueryTime
            }

        } else {
			Write-Host "cookie is not set, redirecting to login page"
			Write-PodeJsonResponse -Value @{ computers = 'null'; }
		}
    }


    Add-PodeRoute -Method Get -Path '/report/gpo/:reportName/:daysFilter' -ScriptBlock {
         if (Test-PodeCookie -Name 'password') {
        
            $reportName = $WebEvent.Parameters['reportName']
            $daysFilter = $WebEvent.Parameters['daysFilter']
            #$ou = $WebEvent.Parameters['ou']
            #Write-Host "OU: " + $ou
            $psCred = User-Auth
            $hostname =  Get-Hostname
           
            Write-Host "report is $reportName "

            $GPOList = Get-Filter $reportName $daysFilter $psCred $hostname

          
            

            $gpos=@()
		    foreach ($gpo in $GPOList) {
			   
                   
                    
                    $gpoDetail = Get-GPOReport -Name $gpo.DisplayName -ReportType HTML #S-Server $hostname

				    $gpos += @{DisplayName=$gpo.DisplayName;
                            DomainName=$gpo.DomainName;
                            CreationTime=$gpo.CreationTime;
                            ModificationTime=$gpo.ModificationTime;
                            GpoStatus=$gpo.GpoStatus;
                            Description=$gpo.Description;
                            GPODetail=$gpoDetail;
                            }

                     
		    }
       
        
            Write-PodeJsonResponse -Value @{
			    gpo = $gpos
            }

        } else {
			Write-Host "cookie is not set, redirecting to login page"
			Write-PodeJsonResponse -Value @{ gpo = 'null'; }
		}
    }

}

function User-Auth {
    
    $user=Get-PodeCookie -Name 'username' -Raw
	$pwd=Get-PodeCookie -Name 'password' -Raw
	$host=Get-PodeCookie -Name 'hostname' -Raw
    $password = ConvertTo-SecureString $pwd.Value	
    
    Write-Host "user is : $user"
    Write-Host "host is : $host"
    Write-Host "pwd is : $pwd"
    Write-Host "password is : $password"
    	
	$username="DOMAIN\"+$user.Value #TODO need to add domain here   logoncount
	$hostname=$host.Value	
			
	$psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
    Write-Host "psCred created"
    
    return $psCred
}

function Get-Hostname {
    $host=Get-PodeCookie -Name 'hostname' -Raw
    $hostname=$host.Value
    return $hostname
}

function Get-Filter {

    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         #[ValidatePattern('^Some.*')]
         [string] $report,
         [Parameter(Mandatory=$true, Position=1)]
         #[ValidateRange(10,100)]
         [int] $days,
         [Parameter(Mandatory=$true, Position=2)]
         $psCred,
         [Parameter(Mandatory=$true, Position=3)]
         [string] $hostname,
         [Parameter(Mandatory=$false, Position=4)]
         [string] $ou
    )

    $dn=Get-ADDomain -Credential $psCred -Server $hostname

    if ($ou -eq "All") {
        $searchBase=$dn.ToString()

    } else {
         $searchBase=$ou
    }

    $daysOffset = (get-date).adddays(-$days)

    Write-Host "Days Offset is  $daysOffset"

    $filter = switch ($report)
    {
        "All Users" {Get-ADUser -properties * -Filter * -Credential $psCred -Server $hostname | sort-object name}
        "Users Never Logged On" {Get-ADUser -properties * -Filter '-not ( lastlogontimestamp -like "*")' -Credential $psCred -Server $hostname}
        "Users Not Recently Logged On" {Get-ADUser -properties * -Filter 'lastlogondate -notlike "*" -OR lastlogondate -le $daysOffset' -Credential $psCred -Server $hostname}

        "Locked Out Users" {Search-ADAccount –LockedOut -Credential $psCred -Server $hostname}
        "Disabled Users" {Search-ADAccount -AccountDisabled -Credential $psCred -Server $hostname}
        "Recently Created Users" {Get-ADUser -properties * -Filter 'created -ge $daysOffset' -Credential $psCred -Server $hostname}
        "Account Expired Users" {Search-ADAccount -AccountExpired -Credential $psCred -Server $hostname}
        "Soon-to-expire User Accounts" {$daysOffset = (get-date).adddays($days) 
                                        Get-ADUser -properties * -Filter 'AccountExpirationDate -le $daysOffset' -Credential $psCred -Server $hostname}
        "Members of Domain Local Administrators Group" {Get-ADGroupMember  "Administrators" -Credential $psCred -Server $hostname | Where { $_.objectClass -eq "user" }}
        "Members of Domain Admins Group" {Get-ADGroupMember  "Domain Admins" -Credential $psCred -Server $hostname | Where { $_.objectClass -eq "user" }}
        "Users in more than one group" {Get-ADUser -Filter * -Properties * -Credential $psCred -Server $hostname | Where  { $_.memberOf.count -gt 1 }}
        "Recently deleted users" {Get-ADObject -IncludeDeletedObjects -properties * -Filter {objectClass -eq "user"} -Credential $psCred -Server $hostname} #TODO need to fix
        "Recently modified users" {Get-ADUser -properties * -Filter 'modified -ge $daysOffset' -Credential $psCred -Server $hostname}
        "Users with logon script" {Get-ADUser -Filter * -Properties * -Credential $psCred -Server $hostname | Where  { $_.scriptPath.length -gt 0 }}
        "Users without logon script" {Get-ADUser -Filter * -Properties * -Credential $psCred -Server $hostname | Where  { $_.scriptPath.length -eq 0 }}
        "Account never expires users" {Get-ADUser -Filter * -Properties * -Credential $psCred -Server $hostname | Where  { $_.accountExpirationDate.length -eq 0 }}
        "Recently logged on users" {Get-ADUser -properties * -Filter 'lastLogondate -ge $daysOffset' -Credential $psCred -Server $hostname}
        "Dial in allowed users" {Get-ADUser -properties * -Filter *  -Credential $psCred -Server $hostname | Where  {$_.msNPAllowDialin -eq $true}}
        "Users with non restricted logon times" {Get-ADUser -properties logonHours  -Filter *  -Credential $psCred -Server $hostname | Where  {$_.logonHours -eq $null}}

        "Admin users with expired passwords" {get-ADGroup -Credential $psCred -Server $hostname -Filter "Name -like '*Admin*'"  | Get-ADGroupMember -Credential $psCred -Server $hostname | where { $_.objectClass -eq "user"} | Get-ADUser -properties PasswordExpired -Credential $psCred -Server $hostname | where { $_.PasswordExpired -ne $false } | sort-object -unique name}

        "All Computers" {Get-ADComputer -properties * -Filter * -SearchBase $searchBase -Credential $psCred -Server $hostname}
        "Computers Not Recently Logged On" {Get-ADComputer -properties * -Filter {LastLogonTimeStamp -lt $daysOffset} -SearchBase $searchBase -Credential $psCred -Server $hostname}
        "Recently Created Computers" {Get-ADComputer -properties * -Filter 'created -ge $daysOffset' -Credential $psCred -Server $hostname}
        "All GPOs" {Invoke-Command -Credential $psCred  -ComputerName localhost -ScriptBlock{Get-GPO -All -Server $hostname} }
    }

    Write-Host "Filter : $filter"

    return $filter
}