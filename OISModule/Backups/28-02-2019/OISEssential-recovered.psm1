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
	   # The thing you really wanted to do.
	   #write-host "The configuration file is not located in C:\Temp folder." -ForegroundColor red
	   #read-host "Would you like to move/create a configuration file now? (y/n) " 
	   $SourceConfigFile = OIS_SF_GetFileName ""C:\Program Files\WindowsPowerShell\Modules\OISEssential\OISInstall.config""
	   #$SourceConfigFile
	   Copy-Item -Path $SourceConfigFile -Destination $Path -Recurse -force
	   $Path 
	}

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
} #End of function OIS_SF_GetDotNetVersion

Function OIS_SF_TestIfRemote {
    [CmdletBinding()]
    param(
        $ComputerName,
        $Credentials    
    )
$LocalComputerName = $Env:Computername
$ComputerName -notmatch $LocalComputerName
} #end of function OIS_SF_TestIfRemote

function OIS_SF_CheckIfSqlInstalled {
param(
$ServerName = "localhost",
[SWITCH]$RemoteCheck = $false
)

#COMMENT OUT FOR TESTING
#$CheckRemote = OIS_SF_TestIfRemote -ComputerName $ServerName
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

} #end of function OIS_SF_CheckIfSqlInstalled 
###################################################################################################
#FUNCTIONS TO READ FROM CONFIGURATION FILE

function OIS_XML_GetSQLConfig {
param(
$Command #SSIS, Server, Version, VersionNo, RsHttps, RsOnAppServer
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
$Command, #SourcePath, DBUser, IISBinding, DBName, 
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
Example of parameters: SourcePath, DBUser, IISBinding, DBName

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetESConfig -Command DBUser
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
$Command, #DBUser 
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
Example of parameters: DBUser

.PARAMETER Command
Used to specify which values to get from the XML file.

.EXAMPLE

C:\PS> OIS_XML_GetOPSConfig -Command DBUser
salesadm
#>
} 

function OIS_XML_GetODWConfig {
param(
$Command, # 
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

C:\PS> OIS_XML_GetODWConfig -Command DBUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetODWConfig -Command ADUsers
Omada_Users
#>
} 

function OIS_XML_GetRoPEConfig {
param(
$Command = "DBUser", # 
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

C:\PS> OIS_XML_GetRoPEConfig -Command DBUser
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetRoPEConfig -Command RoPEServiceName
RoPE1.1

.EXAMPLE

C:\PS> OIS_XML_GetRoPEConfig -Command RoPEProductDatabase
RoPE
#>
} 

function OIS_XML_GetServiceConfig {
param(
$Command = "UserName", #UserName 
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

C:\PS> OIS_XML_GetServiceConfig -Command UserName
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetServiceConfig
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetServiceConfig -Command RoPEProductDatabase
RoPE
#>
} 

function OIS_XML_GetAdministratorConfig {
param(
$Command = "UserName", #UserName 
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

C:\PS> OIS_XML_GetAdministratorConfig -Command UserName
salesadm

.EXAMPLE

C:\PS> OIS_XML_GetAdministratorConfig
salesadm
#>
} 

#########################################################################################################
#GET USER COMMANDS

Function OIS_GetSSISServer {
OIS_XML_GetSQLConfig -Command SSIS
}

Function OIS_GetSQLServer {
OIS_XML_GetSQLConfig -Command Server
}

Function OIS_GetESUser {
OIS_XML_GetESConfig -Command DBUser
}

Function OIS_GetESDBName {
OIS_XML_GetESConfig -Command DBName
}

Function OIS_GetOPSUser {
OIS_XML_GetOPSConfig -Command DBUser
}

Function OIS_GetODWUser {
OIS_XML_GetODWConfig -Command DBUser
}

Function OIS_GetRoPEUser {
OIS_XML_GetRoPEConfig -Command DBUser
}

Function OIS_GetServiceUser {
OIS_XML_GetServiceConfig -Command UserName
}

Function OIS_GetAdminUser {
OIS_XML_GetAdministratorConfig -Command UserName
}

Function OIS_GetInstallUser {
OIS_XML_GetAdministratorConfig -Command UserName
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
}

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
			write-host "Computer $ServerName is trusted for delegation." -ForegroundColor Yellow
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
}

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
}

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
	}

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
 
} 


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
}

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