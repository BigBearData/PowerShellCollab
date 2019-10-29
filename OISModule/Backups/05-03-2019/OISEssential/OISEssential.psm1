#Move-Item "E:\repository\PowerShell\OISModule\OISEssential\OISEssential.psm1" "C:\Program Files\WindowsPowerShell\Modules\OISEssential\"
#https://powershellexplained.com/2017-05-27-Powershell-module-building-basics/ 
#https://blog.kloud.com.au/2018/05/23/creating-your-own-powershell-modules-for-azure-automation-part-1/
#Remove-Module OISEssential

#################################################################################################
#SUPPORT FUNCTIONS
Function OIS_SF_GetFileName($initialDirectory)
{   
 [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
 #$OpenFileDialog.initialDirectory = $initialDirectory
 $OpenFileDialog.filter = "All files (*.config)| *.config"
 $OpenFileDialog.ShowDialog() | Out-Null
 $OpenFileDialog.filename
 
 <#
.SYNOPSIS

Support function for the Essential install configuration check.

.DESCRIPTION

Opens up the Open File dialog window "System.windows.forms", captures file location of selected file.

.PARAMETER initialDirectory
Initial directory for the Open File window. Not mandatory. 

.EXAMPLE

C:\PS> $SourceConfigFile = OIS_SF_GetFileName "C:\Program Files\WindowsPowerShell\Modules\OISEssential\OISInstall.config"
C:\PS> $SourceConfigFile
C:\Program Files\WindowsPowerShell\Modules\OISEssential\OISInstall.config

.EXAMPLE

C:\PS> OIS_SF_GetFileName -Command Server
MSSQL-ServerName

.EXAMPLE

C:\PS> OIS_SF_GetFileName -Command Version
2016

.EXAMPLE

C:\PS> OIS_SF_GetFileName -Command RsHttps
false
#>
} #end function Get-FileName

Function OIS_SF_GetXMLFileLocation {
param(
$Path = "C:\Program Files\WindowsPowerShell\Modules\OISEssential\OISInstall.config"
)

	if (Get-Content $Path) {
		#write-host "Configuration file exists." -ForegroundColor Yellow
		$Path
	} else { 
	   $SourceConfigFile = OIS_SF_GetFileName ""C:\Program Files\WindowsPowerShell\Modules\OISEssential\OISInstall.config""
	   Copy-Item -Path $SourceConfigFile -Destination $Path -Recurse -force
	   $Path 
	}
 <#
.SYNOPSIS

Support function for the Essential install configuration check.

.DESCRIPTION

Checkes if OIS install config file (OISInstall.config) exists in PS module folder. 
If not, it will ask for a config file to use and copy it to the relevant location. 

.PARAMETER Path
Path to where the configuration file should be located.  

.EXAMPLE

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}

#>
} #end of Function OIS_SF_GetXMLFileLocation

Function OIS_SF_GetDotNetVersion {
param(
$ServerName = "localhost"
)
	$NetRegKey = Get-Childitem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
	#$NetRegKey = Invoke-Command -Computer $ServerName -ScriptBlock Get-Childitem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
	$Release = $NetRegKey.GetValue("Release")
	

 		Switch ($Release) {
		   378389 {$NetFrameworkVersion = "Net Framework version 4.5 installed"}
		   378675 {$NetFrameworkVersion = "Net Framework version 4.5.1 installed"}
		   378758 {$NetFrameworkVersion = "Net Framework version 4.5.1 installed"}
		   379893 {$NetFrameworkVersion = "Net Framework version 4.5.2 installed"}
		   393295 {$NetFrameworkVersion = "Net Framework version 4.6 installed"}
		   393297 {$NetFrameworkVersion = "Net Framework version 4.6 installed"}
		   394254 {$NetFrameworkVersion = "Net Framework version 4.6.1 installed"}
		   394271 {$NetFrameworkVersion = "Net Framework version 4.6.1 installed"}
		   394802 {$NetFrameworkVersion = "Net Framework version 4.6.2 installed"}
		   394806 {$NetFrameworkVersion = "Net Framework version 4.6.2 installed"}
		   Default {$NetFrameworkVersion = "Net Framework 4.5 or later is not installed."}
		} 
	$NetFrameworkVersion
	
 <#
.SYNOPSIS

Support function for the Essential install configuration check.

.DESCRIPTION

Gets information regarding .Net framework from Registry and displays the version name. 

.PARAMETER ServerName
Default value "localhost"  

.EXAMPLE

PS C:\> OIS_SF_GetDotNetVersion
Net Framework version 4.6.2 installed

#>
} #End of function OIS_SF_GetDotNetVersion

Function OIS_SF_TestIfRemote {
    [CmdletBinding()]
    param(
        $ServerName,
        $Credentials    
    )
$LocalComputerName = $Env:Computername
$ServerName -notmatch $LocalComputerName

 <#
.SYNOPSIS

Support function for the Essential install configuration check.

.DESCRIPTION

Tests if name of server matches with the name of the local server.
If the server is not a remote server, the script will return $false.  

.PARAMETER ServerName
  

.EXAMPLE

PS C:\> OIS_SF_TestIfRemote -ServerName salesdemo
False

#>
} #end of function OIS_SF_TestIfRemote

function OIS_SF_CheckIfSqlInstalled {
param(
$ServerName = "localhost",
[SWITCH]$RemoteCheck = $false
)

#COMMENT OUT FOR TESTING
$CheckRemote = OIS_SF_TestIfRemote -ComputerName $ServerName
$ScriptBlock = { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' }

	if ($CheckRemote) 
	{
	#$SQLInstances = Invoke-Command -ComputerName $ServerName {Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'}
	$SqlResult = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock
	}
	else
	{
	#Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
	$SqlResult = Invoke-Command -ScriptBlock $ScriptBlock

		if ($SqlResult.PSChildName -like "Microsoft SQL Server")
		{
		$InstalledInstances = $SqlResult.InstalledInstances
		#$InstalledInstances
		Write-host "MSSQL is installation on localhost $ServerName with installed instances: $InstalledInstances"
		
		}
	}

 <#
.SYNOPSIS

Support function for the Essential install configuration check.

.DESCRIPTION

Checkes if SQL server is installed on a server.  
The script will check if the server is a remote server or localhost, and uses Invoke-Command if it's a remote server.

.PARAMETER ServerName
Default value is "localhost"

.PARAMETER RemoteCheck
 The switch defaults to false. If the switch is set (true), the script will use Invoke-Command. 

.EXAMPLE

PS C:\> OIS_SF_CheckIfSqlInstalled -ServerName salesdemo
MSSQL is installation on localhost salesdemo with installed instances: MSSQLSERVER

#>
} #end of function OIS_SF_CheckIfSqlInstalled 

function OIS_TryInvokeCommand {
param(
$ServerName = "localhost"
)

Invoke-Command -ComputerName $ServerName -ScriptBlock {write-host "Invoke command $true"}


 <#
.SYNOPSIS

Support function for the Essential install configuration check.

.DESCRIPTION

Tests if Invoke-Command will work, using the -ComputerName parameter, on either localhost or remote server. 

.PARAMETER ServerName
Default value "localhost"  

.EXAMPLE

PS C:\> OIS_TryInvokeCommand
Invoke-Command does not work for localhost using the -ComputerName parameter

.EXAMPLE

PS C:\> OIS_TryInvokeCommand -ServerName salesdemo
Invoke-Command does not work for salesdemo using the -ComputerName parameter

#>
} # End of function OIS_TryInvokeCommand

#END OF SUPPORT FUNCTION SECTION
###################################################################################################
#FUNCTIONS TO READ FROM CONFIGURATION FILE

function OIS_XML_GetSQLConfig {
param(
$Command #SSISUser, MSSQLUser, SSISServer, MSSQLServer
)

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}

[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.Version.MSSQL.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the MSSQL part of the config file.
Example of parameters: SSIS, Server, Version, VersionNo, RsHttps, RsOnAppServer

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetSQLConfig -Command SSIS
SSIS-ServerName 

.EXAMPLE

C:\PS> OIS_XML_GetSQLConfig -Command Server
MSSQL-ServerName

.EXAMPLE

C:\PS> OIS_XML_GetSQLConfig -Command Version
2016

.EXAMPLE

C:\PS> OIS_XML_GetSQLConfig -Command RsHttps
false
#>
}

 function OIS_XML_GetESConfig {
param(
$Command, #ESDBUser, ESUser, ESServer, IISBinding, 
$Path = $Null
)
	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}
	
[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.Version.ES.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the Enterprise Server part of the config file.
Example of parameters: ESDBUser, ESUser, ESServer, IISBinding,

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetESConfig -Command ESDBUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetESConfig -Command IISBinding
enterpriseserver

.EXAMPLE

C:\PS> OIS_XML_GetESConfig -Command DBName
OIS
#>
}

function OIS_XML_GetOPSConfig {
param(
$Command, #OPDUser, OPDServer 
$Path = $Null
)

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}
	

[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.Version.OPS.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the OPS part of the config file.
Example of parameters: OPDUser, OPDServer 

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetOPSConfig -Command OPDUser
salesadm
#>
} 

function OIS_XML_GetODWConfig {
param(
$Command, # ADUsers, ADAuditors, ADAdmins, ODWUser, ODWServer
$Path = $Null
)

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}
	

[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.Version.ODW.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the Configuration.Version.ODW part of the config file.
Example of parameters: DBUser, ADUsers, ADAuditors, ADAdmins

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetODWConfig -Command ODWUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetODWConfig -Command ADUsers
Omada_Users
#>
} 

function OIS_XML_GetRoPEConfig {
param(
$Command = "RoPEUser", # RoPEUser, RoPEServer
$Path = $Null
)

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}
	

[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.Version.RoPE.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the Configuration.Version.RoPE part of the config file.
Default value of -Command parameter is DBUser

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetRoPEConfig -Command RoPEUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetRoPEConfig -Command RoPEServer
RoPE-server

#>
} 

function OIS_XML_GetServiceConfig {
param(
$Command = "ServiceUser", #ServiceUser, DomainExt,  
$Path = $Null
)

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}
	

[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.LocalConfiguration.Service.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the Configuration.LocalConfiguration.Service part of the config file.
Default value of -Command parameter is UserName

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetServiceConfig -Command ServiceUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetServiceConfig
salesadm

#>
} 

function OIS_XML_GetAdministratorConfig {
param(
$Command = "InstallUser", #InstallUser 
$Path = $Null
)

	if ($Path -eq $Null) {
		$ConfigPath = OIS_SF_GetXMLFileLocation
	}
	elseif ($Path) {
		$ConfigPath = $Path
	}
	

[xml]$Configuration = Get-Content $ConfigPath
$Configuration.Configuration.LocalConfiguration.Administrator.$Command

<#
.SYNOPSIS

Gets information from the Essential install configuration file.

.DESCRIPTION

Gets information related to the Configuration.LocalConfiguration.Administrator part of the config file.
Default value of -Command parameter is UserName

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetAdministratorConfig -Command InstallUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetAdministratorConfig
salesadm
#>
} 

#########################################################################################################
#GET USER COMMANDS

Function OIS_GetSSISServer {
OIS_XML_GetSQLConfig -Command SSISServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetSQLConfig -Command SSISServer

.EXAMPLE

PS C:\> OIS_GetSSISServer
localhost

#>
}

Function OIS_GetSSISUser {
OIS_XML_GetSQLConfig -Command SSISUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetSQLConfig -Command SSISUser

.EXAMPLE

PS C:\> OIS_GetSSISUser
SSISUser

#>
}

Function OIS_GetSQLServer {
OIS_XML_GetSQLConfig -Command MSSQLServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetSQLConfig -Command MSSQLServer

.EXAMPLE

PS C:\> OIS_GetSQLServer
salesdemo

#>
}

Function OIS_GetESUser {
OIS_XML_GetESConfig -Command ESUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetESConfig -Command ESUser

.EXAMPLE

PS C:\> OIS_GetESUser
salesadm

#>
}

Function OIS_GetESServerName {
OIS_XML_GetESConfig -Command ESServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetESConfig -Command ESServer

.EXAMPLE

PS C:\> OIS_GetESDBName
ESServer

#>
}

Function OIS_GetOPSUser {
OIS_XML_GetOPSConfig -Command OPDUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetOPSConfig -Command OPDUser

.EXAMPLE

PS C:\> OIS_GetOPSUser
salesadm

#>
}

Function OIS_GetOPSServer {
OIS_XML_GetOPSConfig -Command OPDServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetOPSConfig -Command OPDServer

.EXAMPLE

PS C:\> OIS_GetOPSUser
OPDServer

#>
}

Function OIS_GetODWUser {
OIS_XML_GetODWConfig -Command ODWUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetODWConfig -Command ODWUser

.EXAMPLE

PS C:\> OIS_GetODWUser
salesadm

#>
}

Function OIS_GetODServer {
OIS_XML_GetODWConfig -Command ODWServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetODWConfig -Command ODWServer

.EXAMPLE

PS C:\> OIS_GetODServer
ODWServer

#>
}

Function OIS_GetRoPEUser {
OIS_XML_GetRoPEConfig -Command RoPEUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetRoPEConfig -Command RoPEUser

.EXAMPLE

PS C:\> OIS_GetRoPEUser
salesadm

#>
}

Function OIS_GetRoPEServer {
OIS_XML_GetRoPEConfig -Command RoPEServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetRoPEConfig -Command RoPEServer

.EXAMPLE

PS C:\> OIS_GetRoPEServer
RoPEServer

#>
}

Function OIS_GetServiceUser {
OIS_XML_GetServiceConfig -Command ServiceUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetServiceConfig -Command ServiceUser

.EXAMPLE

PS C:\> OIS_GetServiceUser
salesadm

#>
}

Function OIS_GetAdminUser {
OIS_XML_GetAdministratorConfig -Command InstallUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetAdministratorConfig -Command InstallUser

.EXAMPLE

PS C:\> OIS_GetAdminUser
salesadm

#>
}

Function OIS_GetInstallUser {
OIS_XML_GetAdministratorConfig -Command InstallUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetAdministratorConfig -Command InstallUser

.EXAMPLE

PS C:\> OIS_GetInstallUser
salesadm

#>
}

#########################################################################################################
#CHECK IF IIS SERVICES IS INSTALLED. DEFAULTS TO LOCALHOST UNLESS SERVER NAME IS SPECIFIED
function OIS_CheckIIS{
    param($ServerName = "localhost")
	
		if ((Get-WindowsFeature -ComputerName $ServerName -name Web-Server).InstallState -eq "Installed") {
			Write-Host "IIS is installed on $ServerName"
		} 
		else {
			Write-Host "IIS is not installed on $ServerName"
		}
		
<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Checks if IIS server is installed on a server. 
Runs Get-WindowsFeature -ComputerName $ServerName -name Web-Server.

.PARAMETER ServerName
Default value "localhost"

.EXAMPLE

PS C:\> OIS_CheckIIS
IIS is installed on localhost

#>
} #end of function OIS_CheckIIS

function OIS_CheckTFD {
param(
$ServerName = $null, #salesdemo
$ServiceAccount = $null #salesadm
)

If (!(Get-module ActiveDirectory)) {
Import-Module ActiveDirectory
}

if ($ServerName -and $ServiceAccount) 
	{
		write-host "Cannot use both username and computername"
	}
else {
	if ($ServerName)
		{
		$ComputerInfo = Get-ADComputer $ServerName -Properties * | select TrustedForDelegation, servicePrincipalName, ServicePrincipalNames
		$TrustedForDelegation = $ComputerInfo.TrustedForDelegation
		#$TrustedForDelegation
			if ($TrustedForDelegation)
			{
			write-host "Computer $ServerName is trusted for delegation." #-ForegroundColor Yellow
			}
			elseif (!$TrustedForDelegation)
			{
			write-host "Computer $ServerName is not trusted for delegation."  -ForegroundColor red
			}
		}
		
	if ($ServiceAccount)
		{
		#https://stackoverflow.com/questions/11605893/checking-for-the-existence-of-an-ad-object-how-do-i-avoid-an-ugly-error-message
		$UserInfo = $(try {Get-ADUser $ServiceAccount -Properties * | select TrustedForDelegation, ServicePrincipalNames} catch {$null})
		if ($UserInfo -ne $null) {
			$UsrTrustForDele = $UserInfo.TrustedForDelegation
			#$UsrTrustForDele
				if ($UsrTrustForDele)
				{
				write-host "ServiceAccount $ServiceAccount is trusted for delegation." -ForegroundColor Yellow 
				}
				elseif (!$UsrTrustForDele)
				{
				write-host "ServiceAccount $ServiceAccount is not trusted for delegation." -ForegroundColor red
				}
			}
			else {
			Write-Host "User $ServiceAccount cannot be found in AD." -ForegroundColor red
				}
		}
	}

<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Checks if a user or computer account is TrustedForDelegation. 
Can be used for either user or computer objects, depending on parameters.
Depends on module ActiveDirectory.

.PARAMETER ServerName
Default value is null. 

.PARAMETER ServiceAccount
Default value is null.

.EXAMPLE

PS C:\> OIS_CheckTFD -ServerName salesdemo
Computer salesdemo is trusted for delegation.

.EXAMPLE

PS C:\> OIS_CheckTFD -ServiceAccount salesadm
ServiceAccount salesadm is not trusted for delegation.

#>
} #end of function OIS_CheckTFD

Function OIS_GetInstalledSoftware {
param($SoftwareName,
$ServerName = $null
)
	
	#IF SERVER NAME IS NOT SPECIFIED, LOCALHOST IS ASSUMED
	If ($ServerName -eq $null) {
		try
			{
				$InstalledSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -LIKE $SoftwareName } #'Microsoft SQL Server*' -OR $_.DisplayName -LIKE 'Microsoft Visual Studio*'}
				$InstalledSoftware += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -LIKE $SoftwareName } #'Microsoft SQL Server*' -OR $_.DisplayName -LIKE 'Microsoft Visual Studio*'}
			} 
		catch 
			{
				Write-warning "Error while trying to retreive installed software from inventory: $($_.Exception.Message)"
			}

		$InstalledSoftware | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table
		}
	else {
		try
			{
				$InstalledSoftware = Invoke-Command -ComputerName $ServerName {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -LIKE $SoftwareName }} #'Microsoft SQL Server*' -OR $_.DisplayName -LIKE 'Microsoft Visual Studio*'}}
				$InstalledSoftware += Invoke-Command -ComputerName $ServerName {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -LIKE $SoftwareName }} #'Microsoft SQL Server*' -OR $_.DisplayName -LIKE 'Microsoft Visual Studio*'}}
				$InstalledSoftware | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table
				
			}
		catch
			{
				Write-warning "Error while trying to retreive installed software from inventory: $($_.Exception.Message)"
			}
		}	

<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Searches the registry for installed software and returns a list based on how the switch SoftwareName is used. 
If -ServerName is used the function will use Invoke-Command.

.PARAMETER SoftwareName
For search for software name or part of a name.  

.PARAMETER ServerName
Default value is null, meaning localhost.

.EXAMPLE

PS C:\> OIS_GetInstalledSoftware -SoftwareName "*Shared Management Objects"

DisplayName                               DisplayVersion Publisher             InstallDate
-----------                               -------------- ---------             -----------
SQL Server 2016 Shared Management Objects 13.0.14500.10  Microsoft Corporation 20161215
SQL Server 2016 Shared Management Objects 13.0.14500.10  Microsoft Corporation 20161215

.EXAMPLE

PS C:\> OIS_GetInstalledSoftware -SoftwareName "*Management Studio*"

DisplayName                                                           DisplayVersion Publisher             InstallDate
-----------                                                           -------------- ---------             -----------
SQL Server 2016 Management Studio for Analysis Services               13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio                                     13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio                                     13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio Extensions                          13.0.1601.5    Microsoft Corporation 20161215
SQL Server 2016 Management Studio for Reporting Services Localization 13.0.16106.4   Microsoft Corporation 20170201
Microsoft SQL Server Management Studio - 16.5.3                       13.0.16106.4   Microsoft Corporation
SQL Server 2016 Management Studio Extensions                          13.0.1601.5    Microsoft Corporation 20161215
SQL Server 2016 Management Studio for Analysis Services               13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio for Reporting Services              13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio                                     13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio for Analysis Services Localization  13.0.16106.4   Microsoft Corporation 20170201
SQL Server 2016 Management Studio                                     13.0.16106.4   Microsoft Corporation 20170201

#>		
} #end of Function OIS_GetInstalledSoftware

#VERIFY IF POWERSHELL MODULES ARE INSTALLED ON SERVERS. USES Invoke-Command IF SERVER NAME IS SPECIFIED.
Function OIS_CheckPSModule {
param(
$ServerName = $null,
$ModuleName
)

	If ($ServerName -eq $null) {
		try
			{
				if (Get-Module -ListAvailable -Name $ModuleName) 
				{
					Write-Host "Module $ModuleName exists"
				} 
				else 
				{
					Write-Host "Module $ModuleName does not exist"
				}}
		catch 
			{
				Write-warning "Error while trying to retreive PS Module: $($_.Exception.Message)"
			}
			}
	else 
	{
		try
			{
				if (Invoke-Command -ComputerName $ServerName {Get-Module -ListAvailable -Name $ModuleName}) 
				{
					Write-Host "Module $ModuleName exists"
				} 
				else 
				{
					Write-Host "Module $ModuleName does not exist on server $ServerName"
				}}
		catch 
				{
					Write-warning "Error while trying to retreive PS Module: $($_.Exception.Message)"
				}
	}
	
<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Checks if a relevant PS module is installed on a server. 
If -ServerName is used the function will use Invoke-Command.

.PARAMETER ServerName
Default value is null. 

.PARAMETER ModuleName
For PS module name.

.EXAMPLE

PS C:\> OIS_CheckPSModule -ModuleName SqlServer
Module SqlServer exists

.EXAMPLE

PS C:\> OIS_CheckPSModule -ModuleName activedirectory
Module activedirectory exists

#>
} #end of Function OIS_CheckPSModule

#CHECK FOR ENTERPRISE USER SPNs
Function OIS_GetEntUserSPN { 
param(
$EntUserName
)

#https://gallery.technet.microsoft.com/scriptcenter/Service-Principal-Name-d44db998
$Result = Get-ADUser -LDAPFilter "(SamAccountname=$EntUserName)" -Properties name, serviceprincipalname -ErrorAction Stop | Select-Object @{Label = "Service Principal Names";Expression = {$_.serviceprincipalname}} | Select-Object -ExpandProperty "Service Principal Names" 
 
	If ($Result) { 
		Write-host " " #adds a space before the line below 
		Write-host "The Service Principal names found for $EntUserName are listed below: " -ForegroundColor Yellow  
		Write-host "" #adds a space after the line above 
		$Result  
		Write-host "" #adds a space after the result 
	} 
	 
	Else  
	{ 
		Write-host " " #adds a space before the line below 
		Write-host "No Service Principal name found for $EntUserName " -ForegroundColor Red   
		Write-host " " #adds a space before the line below 
	}  
<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Checks if a user account has any SPNs and lists them if found.  
Requires PS module ActiveDirectory to be installed. 
This command can also be used for other user objects then Enterprise User. 

.PARAMETER EntUserName
Default value is null. 

.EXAMPLE

PPS C:\> OIS_GetEntUserSPN -EntUserName salesadm
No Service Principal name found for salesadm

#> 
} #end of Function OIS_GetEntUserSPN


function OIS_CheckWinRMListener {
param(
$ServerName = "localhost"
)

	$WSMan = Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="http"} -ComputerName $ServerName
	$WSManEnabled = $WSMan.Enabled
	$WSManPort = $WSMan.Port
	$WSManListeningOn = $WSMan.ListeningOn

	if ($WSManEnabled = "true")
		{
		Write-Host "WinRM Listener is enabled on $ServerName"
		}
	
<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Checks the status of the WinRM listener and thus if the WinRM listener is enabled. 

.PARAMETER ServerName
Default value is "localhost" 

.EXAMPLE

PS C:\> OIS_CheckWinRMListener
WinRM Listener is enabled on localhost

#> 
} #end of function OIS_CheckWinRMListener

#Credit: https://gallery.technet.microsoft.com/scriptcenter/Get-SPN-Get-Service-3bd5524a 
function OIS_GetSPN
{
<#
    .SYNOPSIS
        Get Service Principal Names

    .DESCRIPTION
        Get Service Principal Names

        Output includes:
            ComputerName - SPN Host
            Specification - SPN Port (or Instance)
            ServiceClass - SPN Service Class (MSSQLSvc, HTTP, etc.)
            sAMAccountName - sAMAccountName for the AD object with a matching SPN
            SPN - Full SPN string

    .PARAMETER ComputerName
        One or more hostnames to filter on.  Default is *

    .PARAMETER ServiceClass
        Service class to filter on.
        
        Examples:
            HOST
            MSSQLSvc
            TERMSRV
            RestrictedKrbHost
            HTTP

    .PARAMETER Specification
        Filter results to this specific port or instance name

    .PARAMETER SPN
        If specified, filter explicitly and only on this SPN.  Accepts Wildcards.

    .PARAMETER Domain
        If specified, search in this domain. Use a fully qualified domain name, e.g. contoso.org

        If not specified, we search the current user's domain

    .EXAMPLE
        Get-Spn -ServiceType MSSQLSvc
        
        #This command gets all MSSQLSvc SPNs for the current domain
    
    .EXAMPLE
        Get-Spn -ComputerName SQLServer54, SQLServer55
        
        #List SPNs associated with SQLServer54, SQLServer55
    
    .EXAMPLE
        Get-SPN -SPN http*

        #List SPNs maching http*
    
    .EXAMPLE
        Get-SPN -ComputerName SQLServer54 -Domain Contoso.org

        # List SPNs associated with SQLServer54 in contoso.org

    .NOTES 
        Adapted from
            http://www.itadmintools.com/2011/08/list-spns-in-active-directory-using.html
            http://poshcode.org/3234
        Version History 
            v1.0   - Chad Miller - Initial release 
            v1.1   - ramblingcookiemonster - added parameters to specify service type, host, and specification
            v1.1.1 - ramblingcookiemonster - added parameterset for explicit SPN lookup, added ServiceClass to results

    .FUNCTIONALITY
        Active Directory             
#>
    
    [cmdletbinding(DefaultParameterSetName='Parse')]
    param(
        [Parameter( Position=0,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ParameterSetName='Parse' )]
        [string[]]$ComputerName = "*",

        [Parameter(ParameterSetName='Parse')]
        [string]$ServiceClass = "*",

        [Parameter(ParameterSetName='Parse')]
        [string]$Specification = "*",

        [Parameter(ParameterSetName='Explicit')]
        [string]$SPN,

        [string]$Domain
    )
    
    #Set up domain specification, borrowed from PyroTek3
    #https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Find-PSServiceAccounts
        if(-not $Domain)
        {
            $ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Domain = $ADDomainInfo.Name
        }
        $DomainDN = "DC=" + $Domain -Replace("\.",',DC=')
        $DomainLDAP = "LDAP://$DomainDN"
        Write-Verbose "Search root: $DomainLDAP"

    #Filter based on service type and specification.  For regexes, convert * to .*
        if($PsCmdlet.ParameterSetName -like "Parse")
        {
            $ServiceFilter = If($ServiceClass -eq "*"){".*"} else {$ServiceClass}
            $SpecificationFilter = if($Specification -ne "*"){".$Domain`:$specification"} else{"*"}
        }
        else
        {
            #To use same logic as 'parse' parameterset, set these variables up...
                $ComputerName = @("*")
                $Specification = "*"
        }

    #Set up objects for searching
        $SearchRoot = [ADSI]$DomainLDAP
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $SearchRoot
        $searcher.PageSize = 1000

    #Loop through all the computers and search!
    foreach($computer in $ComputerName)
    {
        #Set filter - Parse SPN or use the explicit SPN parameter
        if($PsCmdlet.ParameterSetName -like "Parse")
        {
            $filter = "(servicePrincipalName=$ServiceClass/$computer$SpecificationFilter)"
        }
        else
        {
            $filter = "(servicePrincipalName=$SPN)"
        }
        $searcher.Filter = $filter

        Write-Verbose "Searching for SPNs with filter $filter"
        foreach ($result in $searcher.FindAll()) {

            $account = $result.GetDirectoryEntry()
            foreach ($servicePrincipalName in $account.servicePrincipalName.Value) {
                
                #Regex will capture computername and port/instance
                if($servicePrincipalName -match "^(?<ServiceClass>$ServiceFilter)\/(?<computer>[^\.|^:]+)[^:]*(:{1}(?<port>\w+))?$") {
                    
                    #Build up an object, get properties in the right order, filter on computername
                    New-Object psobject -property @{
                        ComputerName=$matches.computer
                        Specification=$matches.port
                        ServiceClass=$matches.ServiceClass
                        sAMAccountName=$($account.sAMAccountName)
                        SPN=$servicePrincipalName
                    } | 
                        Select-Object ComputerName, Specification, ServiceClass, sAMAccountName, SPN |
                        #To get results that match parameters, filter on comp and spec
                        Where-Object {$_.ComputerName -like $computer -and $_.Specification -like $Specification}
                } 
            }
        }
    }
} #Get-Spn

#Export-ModuleMember -Function 'GetInfo'