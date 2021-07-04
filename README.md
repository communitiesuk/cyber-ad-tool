# Active Directory Reporting Tool

This tool provides the ability to query groups in Active Directory Domains and display a list of their members.


### Prerequisites

The tool needs to be ran on a Windows instance which has connectivity to the Domain being queried. It doen't need to be ran on a Domain Controller. 

The user running the tool must have local Administrator privileges on the machine being ran on.

Git, in order to clone the repository

A modern browser such as Chrome or Firefox

Powershell 5 or above



### Installing the application

Clone this repository locally to the C:\ drive

Run the following powershell script as Administrator :

```
C:\cyber-ad-tool\install.ps1
```

Note, if you install the tool to any other location than C:\cyber-ad-tool then you will have to update the following line in install.ps1 accordingly :

```
$file = 'C:\cyber-ad-tool\server.ps1'
```

When prompted select Y

This will install the tool as a windows service called "Active Directory Reporting Tool". 

### Starting the application

Navigate to services and start the "Active Directory Reporting Tool" service

### Stopping the application

Navigate to services and stop the "Active Directory Reporting Tool" service

### Removing the service

Open a Powershell window as Administrator and run the following command :

```
nssm remove $name confirm
```


### Reports available

The following reports are available: 

| Name          | Type              | Filter by |
| :------------- |:-----------------|:---------
| All Users	         | User            |  |
| Users Never Logged On		         | User            |  |
| Users Not Logged On for nn days		         | User            |Days  |
| Locked Out Users		         | User            |  |
| Disabled Users		         | User            |  |
| Recently Created Users	         | User            | Days |	
| Account Expired Users		         | User            |  |
| Soon-to-expire User Accounts		         | User            |Days  |
| Members of Domain Local Administrators Group		         | User            |  |
| Members of Domain Admins Group	         | User            |  |	
| Users in more than one group		         | User            |  |
| Recently deleted users		         | User            | Days |
| Recently modified users		         | User            | Days |
| Users with logon script		         | User            |  |
| Users without logon script	         | User            |  |	
| Account never expires users	         | User            |  |	
| Recently logged on users		         | User            | Days |
| Dial in allowed users		         | User            |  |
| Users with non restricted logon times 		         | User            |  |
| Admin users with expired passwords		         | User            |  |
|         |            |  |	
| All Computers	         | Computer            |  |
| Recently Created Computers	         | Computer            | OU, Days |
| Computers Not Recently Logged On	         | Computer            | OU, Days |
|         |            |  |
| Domain Local	         | Group            |  |
| Global	         | Group            |  |
|         |            |  |
| All GPOs		         | GPO            |  |
| Recently Created GPOs	         | GPO            | Days |


## Architecture

The tool has the following components :

* A restful API served by Pode (server/ps1)
* A number of views (index, groups) served by HTML and JQuery. The web pages are served by asynchronous ajax API calls to the Pode API

### Application components

The main components of the application are as follows: 

| File          | Type              | Purpose |
| :------------- |:-----------------|:---------
| views         | folder            | Available views |
| public        | folder            | Public assets (stylesheets, javascript etc |
| server.ps1    | powershell script | entrypoint to the application |
| adaudit.bat   | bash script       | wrapper scrript to start the application |
| views/index.html         | html file            | Landing view containing login screen and Domain selection |
| views/groups.html         | html file           | Group selection and membership view |
| views/computers.html         | html file           | Computer reports |
| views/reports.html         | html file           | User reports |
| views/gpo.html         | html file           | Group Policy reports |


### To add another view

Add another route entry similar to the following : 

```
Add-PodeRoute -Method Get -Path '/groups' -ScriptBlock {
        Write-PodeViewResponse -Path 'groups'
    }
```

### To add another route

Add the payload of the route 
```
	Add-PodeRoute -Method Get -Path '/login/:username/:password/:hostname' -ScriptBlock {
	
        -- CODE --
		Write-PodeJsonResponse -Value @{ 'fooo' = $bar }
    }
```  
In this example login is the path, username,password and hostname are parameters which can be used via the following syntax : 

```
$WebEvent.Parameters['username']
``` 

### Channging the listener port and setting up HTTPS encryption

In server.ps1 change configuration variables (lines 10-12) at the top of the script to adjust the port number and whether HTTPS is enabled (including specifying a certificate):

```
# Configuration variables
$Port = 8080 # Port to run server
$HttpsEnabled = $false # Enable HTTPS (set to $false to disable encryption)
$Certificate = 'THUMBPRINT' # Certificate thumbprint (replace with thumbprint your own certificate)
```
For enabling HTTPS encryption you need to have a certificate in the local machine store and replace the thumbprint in the configuration (line 12).

## Built With

* [Pode](https://badgerati.github.io/Pode/) - The web framework used
* [JQuery](https://jquery.com/) - Javascript framework
* HTML


## Authors

* **Rob Brooks**
