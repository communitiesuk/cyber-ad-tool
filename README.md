# Active Directory Reporting Tool

This tool provides the ability to query groups in Active Directory Domains and display a list of their members.


### Prerequisites

The tool needs to be ran on a Windows instance which has connectivity to the Domain being queried. It doen't need to be ran on a Domain Controller. 

The user running the tool must have local Administrator privileges on the machine being ran on.

Git, in order to clone the repository

A modern browser such as Chrome or Firefox

Powershell 5 or above



### Starting the application

Clone this repository locally

Navigate to the adaudit directory and run the server.ps1 script as Administrator
When prompted select Y

### Stopping the application

Close the powershell window

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

### Channging the listener port

In server.ps1 change 8080 to the desired port on thee following line:

```
Add-PodeEndpoint -Address * -Port 8080 -Protocol Http
```


## Built With

* [Pode](https://badgerati.github.io/Pode/) - The web framework used
* [JQuery](https://jquery.com/) - Javascript framework
* HTML


## Authors

* **Rob Brooks**
