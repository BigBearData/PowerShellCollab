#Move-Item "E:\repository\PowerShell\OISModule\OISEssential\OISEssential.psm1" "C:\Program Files\WindowsPowerShell\Modules\OISEssential\"
#https://powershellexplained.com/2017-05-27-Powershell-module-building-basics/ 
#https://blog.kloud.com.au/2018/05/23/creating-your-own-powershell-modules-for-azure-automation-part-1/
#Remove-Module OISEssential


#################################################################################################
#################################################################################################
#SUPPORT FUNCTIONS

Function OIS_WriteOutput {
param(
$Verbose = $False,
$MessageText,
$Color,
$MessageType, #error, info, heading, warning, text....
[switch]$LogError = $False
)
#$Verbose

	IF ($Verbose -eq $True){

			If ($MessageType -eq "error" -OR $Color -eq "red"){
				Write-Host $MessageText -ForegroundColor Red -BackgroundColor Yellow
				return $MessageText
			}
			Elseif ($MessageType -eq "heading"){
			Write-Host ""
			Write-Host $MessageText -ForegroundColor Yellow -BackgroundColor DarkGreen
			}
			Elseif ($MessageType -eq "info" -OR $MessageType -eq "warning"){
			Write-Host $MessageText -ForegroundColor Yellow
			}
			Else {
			Write-Host $MessageText
			}
	}
	Elseif ($Verbose -eq $Fales){
				If ($MessageType -eq "error" -OR $Color -eq "red"){
				#Write-Host $MessageText -ForegroundColor DarkRed -BackgroundColor Yellow
				return $MessageText
			}
	}


}

Function OIS_GetWinFeatures {
param(
$ServerName = "localhost",
$FeatureName = "*"
)

<# 		Write-host "Checking for installed features" -ForegroundColor Yellow  
		Write-host "" #adds a space after the line above  #>

$FeatureStatus = Get-WindowsFeature -ComputerName $ServerName -Name $FeatureName
$InstallState=$FeatureStatus.InstallState
	if ($FeatureName.Contains("*")) {
	$FeatureStatus
	}
	else {
		if ($InstallState -eq "Installed"){
		#$FeatureInstState = "The Windows Feature $FeatureName is installed on $ServerName."
		}
		else {
		Write-Host "The Windows Feature $FeatureName is not installed on $ServerName." -ForegroundColor Red
		$FeatureInstState = "The Windows Feature $FeatureName is not installed on $ServerName." #-ForegroundColor red
		}
		#$FeatureInstState
	}
}

Function OIS_GetInstalledPrograms {

<#PSScriptInfo 
 
.VERSION 1.0.1 
 
.GUID 46e23916-6dbe-4ad6-87d5-1a183df64758 
 
.AUTHOR Chris Carter 
 
.COMPANYNAME 
 
.COPYRIGHT 2016 Chris Carter 
 
.TAGS InstalledPrograms PowerShellRemoting 
 
.LICENSEURI http://creativecommons.org/licenses/by-sa/4.0/ 
 
.PROJECTURI https://gallery.technet.microsoft.com/Get-Programs-Installed-on-0e93f152 
 
.ICONURI 
 
.EXTERNALMODULEDEPENDENCIES 
 
.REQUIREDSCRIPTS 
 
.EXTERNALSCRIPTDEPENDENCIES 
 
.RELEASENOTES 
 
 
#>

<# 
.SYNOPSIS 
Gets the programs installed on a local or remote machine. 
.DESCRIPTION 
Get-InstalledProgram retrieves the programs installed on a local or remote machine. To specify a remote computer, use the ComputerName parameter. If the Name parameter is specified, the script gets information on any matching program's DisplayName property, and wildcards are permitted. 
 
By default, the objects returned will only include the "DisplayName" and "DisplayVersion" properties of the installed program. This can be overridden by specifying the properties desired to the Property parameter, or all properties can be retrieved by using the All switch parameter. 
.PARAMETER Name 
The name of the installed program to get. Wildcards are accepted. 
.PARAMETER Property 
The name of the property or properties to get of the installed program. The keyword "All" can be used to retrieve all the properties of an installed program. 
.PARAMETER ComputerName 
Specifies the target computer to get installed programs from. Enter a fully qualified domain name, a NetBIOS name, or an IP address. When the remote computer is in a different domain than the local computer, the fully qualified domain name is required. 
         
The default is the local computer. To specify the local computer, such as in a list of computer names, use "localhost", the local computer name, or a dot (.). 
 
This parameter relies on Windows PowerShell remoting, which uses WS-Management, and the target computer must be configured to run WS-Management commands. 
.PARAMETER All 
Tells the script to get all properties of a returned object. 
.INPUTS 
System.String 
 
You can pipe System.String objects to Get-InstalledProgram of computers to target. 
.OUTPUTS 
PSCustomObject 
.EXAMPLE 
Get-InstalledProgram 
 
This command will get all of the installed programs on the local computer. 
.EXAMPLE 
Get-InstalledProgram -ProgramName "Java 8*" 
 
This command will get all of the installed programs whose DisplayName starts with "Java 8" on the local computer. 
.EXAMPLE 
"Server1","Server2" | Get-InstalledProgram -PN "Adobe Acrobat*" 
 
This command will get all of the installed programs whose DisplayName starts with "Adobe Acrobat*" on the computers named Server1 and Server2. 
.EXAMPLE 
Get-InstalledProgram -ProgramName "Microsoft Office*" -Property DisplayName,DisplayVersion,Publisher,InstallLocation 
 
This command will get all of the installed programs whose DisplayName starts with "Microsoft Office" on the local computer and will only return the DisplayName, DisplayVersion, Publisher, and InstallLocation properties of the PSCustomObject. 
.EXAMPLE 
Get-InstalledProgram -All 
 
This command will get all of the installed programs on the local machine and return all of the properties retrieved by the command. 
.NOTES 
This script uses Get-ItemProperty and the Registry provider to retrieve keys from HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ on 32 and 64 bit computers. On 64 bit it also gets the keys from HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\. 
 
Remote commands are run using Invoke-Command, so the remote computer must be set up for PowerShell remoting. Locally, Invoke-Command is not used due to the fact that in later versions of PowerShell running Invoke-Command on the local machine required the session to be running as an administrator. 
 
Filtering properties is done using Select-Object. 
 
.LINK 
Get-ItemProperty 
.LINK 
Select-Object 
.LINK 
Invoke-Command 
#>

#Requires -Version 2.0
[CmdletBinding(HelpURI='https://gallery.technet.microsoft.com/Get-Programs-Installed-on-0e93f152')]

Param(
    [Parameter(Position=0)]
    [Alias("ProgramName","PN")]
        [String[]]$Name,

    [Parameter(Position=1,ParameterSetName="UserDefined")]
        [String[]]$Property=@("DisplayName","DisplayVersion"),
    
    [Parameter(Position=2,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("CN")]
        [String[]]$ComputerName=$env:COMPUTERNAME,

    [Parameter(Mandatory=$true,ParameterSetName="All")]
        [Switch]$All
)

	Begin {
		$ProgCmd = {
			Param($prog,$props)
			$programs = @()
			$Is64Bit = (Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit"

			if ($prog) {
				if ($Is64Bit) {
					$tempProgs = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
					foreach ($tp in $tempProgs) {
						if ($tp.DisplayName -like $prog) {$programs += $tp}
					}
				}
				else {
					$tempProgs = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
					foreach ($tp in $tempProgs) {
						if ($tp.DisplayName -like $prog) {$programs += $tp}
					}
				}
			}
			else {
				if ($Is64Bit) {$programs += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*}
				else {$programs += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*}
			}

			if ($props -eq "All" -or $props -contains "All" -or $All) {$programs}
			else {$programs | Select-Object -Property $props}
		}

		Function Choose-Invocation($ProgName, $CompName) {
			if ($CompName -eq "." -or $CompName -eq "localhost" -or $CompName -eq $env:COMPUTERNAME) {
				& $ProgCmd $ProgName $Property
			}
			else {Invoke-Command -ScriptBlock $ProgCmd -ArgumentList $ProgName,$Property -ComputerName $CompName}
		}

		Function Get-ProgramFromRegistry ($ProgName, $CompName) {
			if ($ProgName) {
				foreach ($n in $ProgName) {
					Choose-Invocation -ProgName $n -CompName $CompName
				}
			}
			else {
				Choose-Invocation -CompName $CompName
			}
		}
	}

	Process {
		foreach ($comp in $ComputerName) {
			Get-ProgramFromRegistry -ProgName $Name -CompName $comp
		}
	}

}

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
		   460798 {$NetFrameworkVersion = "Net Framework version 4.7 installed"}
		   460805 {$NetFrameworkVersion = "Net Framework version 4.7 installed"}
		   461308 {$NetFrameworkVersion = "Net Framework version 4.7.1 installed"}
		   461310 {$NetFrameworkVersion = "Net Framework version 4.7.1 installed"}
		   461808 {$NetFrameworkVersion = "Net Framework version 4.7.2 installed"}
		   461814 {$NetFrameworkVersion = "Net Framework version 4.7.2 installed"}
		   528040 {$NetFrameworkVersion = "Net Framework version 4.8 installed"}
		   528049 {$NetFrameworkVersion = "Net Framework version 4.8 installed"}
		   Default {$NetFrameworkVersion = "Net Framework 4.6 or later is not installed."}
		} 
	If ($NetFrameworkVersion -Match "not"){
		Write-Host "Net Framework 4.5 or later is not installed." -ForegroundColor Red
		}
	else {
		$NetFrameworkVersion
	}
	
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
#$LocalComputerName
#$ServerName

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
$ServerName = "localhost",
$Verbose
)

$CheckRemote = OIS_SF_TestIfRemote -ServerName $ServerName
$ScriptBlock = {Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="http"} }

	 if ($CheckRemote) { 
		$InvokeCommandCheck = Invoke-Command -ComputerName $ServerName -ScriptBlock {$True}  -ErrorAction SilentlyContinue
		$InvokeCommandCheck
		} 
	Else { 
		Write-Host "$ServerName is not a remote host, Invoke-Command will not be tested." -ForegroundColor Yellow 
		#OIS_WriteOutput -Verbose $Verbose -MessageText "$ServerName is not a remote host, Invoke-Command will not be tested."
		$InvokeCommandCheck
		}


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

function OIS_SSIS_GetSQLServer {
$SSISServer = OIS_GetSSISServer
$CheckRemote = OIS_SF_TestIfRemote -ServerName $SSISServer
$SSISConfigFileName = "MsDtsSrvr.ini.xml"
$SSISPath = OIS_XML_GetSQLConfig -Command SSISPath 
$SSISPathRemote = $SSISPath -replace ":","$"
$SSISPathRemote

$SSISConfigFile
if ($CheckRemote){
	$SSISConfigFile = "\\"+$SSISServer+"\"+$SSISPathRemote+"\"+$SSISConfigFileName
	}
elseif (!$CheckRemote) {	
	$SSISConfigFile = $SSISPath + "\"+$SSISConfigFileName
	#$SSISConfigFile
	}

	if (Get-Content $SSISConfigFile) {
		[xml]$SSISSQLServer = Get-Content $SSISConfigFile
		Write-host "SSIS is using SQL Server: "
		$SSISSQLServer.DtsServiceConfiguration.TopLevelFolders.Folder.ServerName
		#$AuthType.RSWindowsNegotiate
		#$SSISSQLServer.SelectSingleNode("//AuthenticationTypes")
	} else {
	   write-host "Cannot find file $SSISConfigFile." -ForegroundColor red 
	}
}

function OIS_SSIS_GetSQLServerConfig {
param(
$ServiceName,
$ServerName = "localhost",
$CheckRemote
)

$SSISConfigFileName = "MsDtsSrvr.ini.xml"
$SSISConfigFilePath = Join-Path -Path (OIS_GetServicePath -ServiceName $ServiceName -ServerName $ServerName -CheckRemote $CheckRemote) -ChildPath $SSISConfigFileName
#$SSISConfigFilePath

 	if (Get-Content $SSISConfigFilePath) {
		$SsisDbServer = Select-Xml -Path $SSISConfigFilePath -Xpath "/DtsServiceConfiguration/TopLevelFolders/Folder/ServerName" | select-object -ExpandProperty Node | Select-Object -Expand '#text'
		#$SsisDbServer
			If ($SsisDbServer -eq "."){
			$SsisDbServer = "localhost"
			}
			Write-Host "SSIS server $ServerName is configured to use $SsisDbServer as DB server."
	} else {
	   write-host "Cannot find file $SSISConfigFilePath." -ForegroundColor red 
	} 

}

function OIS_SSRS_GetAuthMethod {
param(
$ServerName,
$CheckRemote
)

$SSRSConfigFileName = "RSReportServer.config"
$SSRSPath = OIS_GetServicePath -ServiceName SSRS -ServerName $ServerName -CheckRemote $CheckRemote
$SSRSPath
[string]$SSRSConfigPath = $SSRSPath -Replace ("bin","RSReportServer.config")

 	if (Get-Content $SSRSConfigPath) {
		#$SSRSConfigPath
		[XML]$RSReportServerconfig = Get-Content -Path $SSRSConfigPath | out-null
		Select-Xml -Path $SSRSConfigPath -Xpath "/Configuration/Authentication/AuthenticationTypes" | select-object -ExpandProperty Node
	} else {
	   write-host "Cannot find file $SSRSConfigFile." -ForegroundColor red 
	} 


}

function OIS_SuggesteUserSPNs {
param(
$UserName,
$ServerName,
$IISBinding = $False
)

$Domain = $env:userdomain
$FQDN = $env:userdnsdomain
#setspn -s http/enterpriseserver_test rhpr\OMADA_TEST_EA 
Write-Host "Suggested SPNs for Enterprise Admin User: " -ForegroundColor Yellow
$SuggSPNTxt = "Suggested SPNs for Enterprise Admin User: " 
$SuggSPN1 = "setspn -s http/$ServerName $Domain\$UserName"
$SuggSPN2 = "setspn -s http/$ServerName.$FQDN $Domain\$UserName"
#$SuggSPNTxt
$SuggSPN1
$SuggSPN2

If ($IISBinding) {
	$SuggBindSPN1 = "setspn -s http/$IISBinding $Domain\$UserName"
	$SuggBindSPN2 = "setspn -s http/$IISBinding.$FQDN $Domain\$UserName"
	$SuggBindSPN1
	$SuggBindSPN2
	}


}#end of function OIS_SuggesteUserSPNs 

#Get path for services
function OIS_GetServicePath {
param(
$ServiceName,
$ServerName = "localhost",
$CheckRemote
)

#$CheckRemote = OIS_SF_TestIfRemote -ServerName $ServiceName

switch($ServiceName.ToUpper()) {
	SSIS {
		#$ServerName = OIS_GetSSISServer
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like '*MsDtsServer*'} | select Name, DisplayName, State, PathName }
	}
	SSRS {
		#$ServerName = OIS_GetSSRSServer
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like 'ReportServer'} | select Name, DisplayName, State, PathName }
		#$CheckRemote
	}
	MSSQL {
		#$ServerName = OIS_GetSQLServer
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like 'MSSQLSERVER'} | select Name, DisplayName, State, PathName }
	}

}

		if ($CheckRemote -eq $True) {
		Write-host ""
		Write-host "Gettig $ServiceName information from Remote Host $ServerName" -ForegroundColor Yellow
		$ServiceInfo = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock
		[string]$ServiceInfoPathName = $ServiceInfo.PathName | Select-String '^"?(.+)\.exe' | ForEach-Object {
			Split-Path $_.Matches[0].Groups[1].Value -Parent
			}
		$UNCServicePath = "\\"+$ServerName+"\"+$ServiceInfoPathName -replace (":","$")
		$UNCServicePath
		}
		else {
		Write-host ""
		Write-host "Gettig $ServiceName information from Localhost $ServerName" -ForegroundColor Yellow
		$ServiceInfo = Invoke-Command -ScriptBlock $ScriptBlock
		[string]$ServiceInfoPathName = $ServiceInfo.PathName | Select-String '^"?(.+)\.exe' | ForEach-Object {
			Split-Path $_.Matches[0].Groups[1].Value -Parent
			}
		$UNCServicePath = "\\"+$ServerName+"\"+$ServiceInfoPathName -replace (":","$")
		$UNCServicePath
		}

} #End of function OIS_GetServicePath

#END OF SUPPORT FUNCTION SECTION
###################################################################################################
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

Function OIS_GetSSRSServer {
OIS_XML_GetSQLConfig -Command SSRSServer

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetSQLConfig -Command SSRSServer

.EXAMPLE

PS C:\> OIS_GetSSRSServer
SSRSServer

#>
}

Function OIS_GetSSRSUser {
OIS_XML_GetSQLConfig -Command SSRSUser

<#
.SYNOPSIS

Short command to get specific information from OIS install config.

.DESCRIPTION

Runs the command OIS_XML_GetSQLConfig -Command SSRSUser

.EXAMPLE

PS C:\> OIS_GetSSRSUser
SSRSUser

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
param(
$ServiceName,
$ServerName = "localhost",
$CheckRemote,
$Verbose = $False
)

#OIS_XML_GetServiceConfig -Command ServiceUser
#OETSVC123, Omada ProvisioningService, RoPE1.1  
#$CheckRemote = OIS_SF_TestIfRemote -ServerName $ServiceName

switch($ServiceName.ToUpper()) {
	SSIS {
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like '*MsDtsServer*'} | select Name, StartName, State, PathName }		
	}
	SSRS {
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like 'ReportServer'} | select Name, StartName, State, PathName }
	}
	MSSQL {
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like 'MSSQLSERVER'} | select Name, StartName, State, PathName }
	}
	ES {
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like 'OETSVC123'} | select Name, StartName, State, PathName }
	}
	OPS {
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like '*ProvisioningService'} | select Name, StartName, State, PathName }
	}
	ROPE {
		$ScriptBlock = { Get-WmiObject win32_service | ?{$_.Name -like 'RoPE*'} | select Name, StartName, State, PathName }
	}

}

		if ($CheckRemote -eq $True) {
		#Write-host "Gettig $ServiceName service account from Remote Host $ServerName" #-ForegroundColor Yellow
		OIS_WriteOutput -Verbose $Verbose -MessageText "Gettig $ServiceName service account from Remote Host $ServerName" -MessageType heading
		$ServiceInfo = Invoke-Command -ComputerName $ServerName -ScriptBlock $ScriptBlock
		$ServiceInfo.StartName
			}
		else {
		#$Verbose
		OIS_WriteOutput -Verbose $Verbose -MessageText "Gettig $ServiceName service account from localhost $ServerName" -MessageType heading
		#Write-host "Gettig $ServiceName service account from Localhost $ServerName"
		$ServiceInfo = Invoke-Command -ScriptBlock $ScriptBlock
		$ServiceInfo.StartName
		}


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
    param(
	$ServerName = "localhost",
	[switch] $Silent = $null)
		#FIX: First check if the server name is correct and the server can be found. 
		if ((Get-WindowsFeature -ComputerName $ServerName -name Web-Server).InstallState -eq "Installed") {
			if ($Silent){
			$IISStatus = "IIS is installed on $ServerName"
			}
		} 
		else {
			$IISStatus = "IIS is not installed on $ServerName"
		}
		$IISStatus
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
	if ($ServerName){
		$ComputerInfo = Get-ADComputer $ServerName -Properties * | select TrustedForDelegation, servicePrincipalName, ServicePrincipalNames
		$TrustedForDelegation = $ComputerInfo.TrustedForDelegation
		#$TrustedForDelegation
			if ($TrustedForDelegation){
			Write-Host "Computer $ServerName is trusted for delegation." -ForegroundColor Yellow
			#$TrustDelText = "Computer $ServerName is trusted for delegation." 
			}
			elseif (!$TrustedForDelegation){
			Write-Host "Computer $ServerName is not trusted for delegation."  -ForegroundColor red
			#$TrustDelText = "Computer $ServerName is not trusted for delegation."  #-ForegroundColor red
			}
			$TrustDelText
		}
		
	if ($ServiceAccount)
		{
		#https://stackoverflow.com/questions/11605893/checking-for-the-existence-of-an-ad-object-how-do-i-avoid-an-ugly-error-message
		$UserInfo = $(try {Get-ADUser $ServiceAccount -Properties * | select TrustedForDelegation, ServicePrincipalNames} catch {$null})
		if ($UserInfo -ne $null) {
			$UsrTrustForDele = $UserInfo.TrustedForDelegation
			#$UsrTrustForDele
				if ($UsrTrustForDele){
				Write-Host "ServiceAccount $ServiceAccount is trusted for delegation." -ForegroundColor Yellow
				$TrustDelText = "ServiceAccount $ServiceAccount is trusted for delegation."  
				}
				elseif (!$UsrTrustForDele){
				Write-Host "ServiceAccount $ServiceAccount is not trusted for delegation." -ForegroundColor red
				$TrustDelText = "ServiceAccount $ServiceAccount is not trusted for delegation." #-ForegroundColor red
				}
			}
			else {
			Write-Host "User $ServiceAccount cannot be found in AD." -ForegroundColor red
			$TrustDelText = "User $ServiceAccount cannot be found in AD." #-ForegroundColor red
				}
				#$TrustDelText
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
param($SoftwareName = "*",
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
	elseif ($ServerName)  {
				
				#$ServerName
				#$SoftwareName
				Invoke-Command -ComputerName $ServerName {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -LIKE $SoftwareName }} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table #| Select DisplayName, DisplayVersion #'Microsoft SQL Server*' -OR $_.DisplayName -LIKE 'Microsoft Visual Studio*'}}
				#$InstalledSoftware += Invoke-Command -ComputerName $ServerName {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -LIKE $SoftwareName }} #'Microsoft SQL Server*' -OR $_.DisplayName -LIKE 'Microsoft Visual Studio*'}}
				#$InstalledSoftware | Format-Table #| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table
				
		
				
			
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
$ModuleName,
[switch] $Silent = $null
)

	If ($ServerName -eq $null) {
		try
			{
				if (Get-Module -ListAvailable -Name $ModuleName) {
					if ($Silent) {
					$PSModuleState = "Module $ModuleName exists"
					}
				} 
				else {
					$PSModuleState = "Module $ModuleName does not exist"
				}
				$PSModuleState
			}
		catch {
				Write-warning "Error while trying to retreive PS Module: $($_.Exception.Message)"
			}
		}
	else {
		try{
				if (Invoke-Command -ComputerName $ServerName {Get-Module -ListAvailable -Name $ModuleName}) {
					$PSModuleState = "Module $ModuleName exists"
				} 
				else {
					$PSModuleState = "Module $ModuleName does not exist on server $ServerName"
				}
				$PSModuleState
			}
		catch {
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
$EntUserName,
[switch]$SuggestSPN = $False
)

#https://gallery.technet.microsoft.com/scriptcenter/Service-Principal-Name-d44db998
$Result = Get-ADUser -LDAPFilter "(SamAccountname=$EntUserName)" -Properties name, serviceprincipalname -ErrorAction Stop | Select-Object @{Label = "Service Principal Names";Expression = {$_.serviceprincipalname}} | Select-Object -ExpandProperty "Service Principal Names" 
 
	If ($Result) { 
		Write-host " " #adds a space before the line below 
		Write-Host "The Service Principal names found for $EntUserName are listed below: " -ForegroundColor Yellow  
		$SPNText = "The Service Principal names found for $EntUserName are listed below: "   
		#$SPNText
		Write-host "" #adds a space after the line above 
		$Result  
		Write-host "" #adds a space after the result 
	} 
	 
	Else { 
		Write-host " " #adds a space before the line below 
		Write-Host "No Service Principal name found for $EntUserName " -ForegroundColor Red
		#$SPNText = "No Service Principal name found for $EntUserName " #-ForegroundColor Red   
		#$SPNText
		Write-host " " #adds a space before the line below 
		If ($SuggestSPN -eq $True) {OIS_SuggesteUserSPNs -UserName $EntUserName -ServerName ServerName}
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
		Write-Host "WinRM Listener is enabled on $ServerName" -ForegroundColor Yellow
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
        OIS_GetSPN -ServiceType MSSQLSvc
        
        #This command gets all MSSQLSvc SPNs for the current domain
    
    .EXAMPLE
        OIS_GetSPN -ComputerName SQLServer54, SQLServer55
        
        #List SPNs associated with SQLServer54, SQLServer55
    
    .EXAMPLE
        OIS_GetSPN -SPN http*

        #List SPNs maching http*
    
    .EXAMPLE
        OIS_GetSPN -ComputerName SQLServer54 -Domain Contoso.org

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
} #OIS_GetSPN

###############################################################################################################################################
###############################################################################################################################################
#### PREREQUISITES SCRIPTS 


#######################################################  ES 
#PREREQUISITES FOR ENTERPRISE SERVER: 
function OIS_Prerequisites_ES {
param(
	[Parameter(Mandatory=$True)]
	$ServerName, #fix: check if servename is correct.
	$UserName, #fix: check if username is correct.
	$IISBinding,
	[switch]$V = $False
)

$EnterpriseServer = $ServerName
$EnterpriseUsers = $UserName

<# 		if (!$EnterpriseServer) {
		$EnterpriseServer = OIS_GetESServerName
		} #>

		if (!$EnterpriseUsers) {
		$EnterpriseUsers = OIS_GetESUser
		}

<# 		if (!$IISBinding) {
		$IISBinding = OIS_XML_GetESConfig -Command IISBinding
		} #>

		If (!(Get-module ActiveDirectory)) {
		Import-Module ActiveDirectory #Fix: Need to check if the module is installed before import.
		}

<# If (!(Get-module .\OISEssential)) {
Import-Module .\OISEssential
} #>


If ($V -eq $False){OIS_WriteOutput -Verbose $True -MessageText "Prerequisites Summary for Enterprise Server:" -MessageType heading}

#Write-host " "
#Write-host "Checking Software Prerequisites for Enterprise Server" -ForegroundColor Yellow
OIS_WriteOutput -Verbose $V -MessageText "Checking Software Prerequisites for Enterprise Server" -MessageType heading
#Write-host " "
OIS_CheckIIS -ServerName $EnterpriseServer
OIS_SF_GetDotNetVersion #Fix: Should use server name?
OIS_CheckPSModule -ModuleName SqlServer #Fix: Should use server name?
OIS_CheckPSModule -ModuleName SQLPS #Fix: Should use server name?
OIS_CheckPSModule -ModuleName activedirectory #Fix: Should use server name?

#Check Windows Features Status
#Write-host "Checking for installed features" -ForegroundColor Yellow 
OIS_WriteOutput -Verbose $V -MessageText "Checking for installed features" -MessageType info 
#Write-host "" #adds a space after the line above

OIS_GetWinFeatures -FeatureName NET-Framework-Features
OIS_GetWinFeatures -FeatureName Web-Static-Content
OIS_GetWinFeatures -FeatureName NET-Framework-45-ASPNET
OIS_GetWinFeatures -FeatureName Web-Net-Ext45
OIS_GetWinFeatures -FeatureName Web-Mgmt-Tools
OIS_GetWinFeatures -FeatureName Web-Asp-Net45
OIS_GetWinFeatures -FeatureName Web-Basic-Auth
OIS_GetWinFeatures -FeatureName Web-Windows-Auth
OIS_GetWinFeatures -FeatureName NET-HTTP-Activation
OIS_GetWinFeatures -FeatureName Web-Static-Content

<# $MyFileName = "Get-InstalledProgram.ps1 -PN"
$GetInstalledPrg = Join-Path $PSScriptRoot $MyFileName
$GetInstalledPrg #>
$SoftwSMO = $EnterpriseServer | OIS_GetInstalledPrograms -PN "*Management Objects*" -Property DisplayName,DisplayVersion | format-table
#$SoftwSMO = $EnterpriseServer | OIS_GetInstalledPrograms -PN "*ble" -Property DisplayName,DisplayVersion | format-table
	If ($SoftwSMO) {
		#$SoftwSMO
		if ($V -eq $True){$SoftwSMO} elseif ($V -eq $False){Write-Host "Shared Management Objects is installed" -ForegroundColor Yellow}
	}
	elseif (!$SoftwSMO) {
		Write-host "Shared Management Objects software is missing on server $EnterpriseServer." -ForegroundColor Red
		Write-Host " "
	}
#OIS_GetInstalledSoftware -ServerName $SQLServer -SoftwareName "*Shared Management Objects"
OIS_WriteOutput -Verbose $V -MessageText "Checking Network Prerequisites Requirements for Enterprise Server" -MessageType heading
#Write-host "Checking Network Prerequisites Requirements for Enterprise Server" -ForegroundColor Yellow

	If ((Get-module ActiveDirectory)) {
		OIS_GetEntUserSPN -EntUserName $EnterpriseUsers -SuggestSPN
		OIS_CheckTFD -ServiceAccount $EnterpriseUsers
		Write-host ""
		#Write-host "Checking SPNs for Enterprise Server and IIS Binding" -ForegroundColor Yellow
		OIS_WriteOutput -Verbose $V -MessageText "Checking SPNs for Enterprise Server and IIS Binding" -MessageType info
		$SpnESText = "Checking SPNs for Enterprise Server and IIS Binding"
		#$SpnESText
		OIS_GetSPN -ServiceClass http -ComputerName $EnterpriseServer
		#OIS_GetSPN -ServiceClass MSSQLSvc -ComputerName $EnterpriseServer
		OIS_GetSPN -ServiceClass http -ComputerName $IISBinding
		OIS_TryInvokeCommand -ServerName $EnterpriseServer -Verbose $V
	}
	Else {
		Write-host "Cannot check SPNs for Enterprise Server and IIS Binding. AD PowerShell module missing." -ForegroundColor Red
	}


} #end of function OIS_Prerequisites_ES

############################################################### MSSQL
#PREREQUISITES FOR MSSQL SERVER:
function OIS_Prerequisites_MSSQL {
param(
	[Parameter(Mandatory=$True)]
	$ServerName,
	$UserName,
	[switch]$V = $False
)

$SQLServer = $ServerName
$SQLUser = $UserName
$CheckRemote = OIS_SF_TestIfRemote -ServerName $SQLServer

<# 		if (!$SQLServer) {
		$SQLServer = OIS_XML_GetSQLConfig -Command MSSQLServer
		} #>

		if (!$SQLUser) {
		$SQLUser = OIS_GetServiceUser -ServiceName MSSQL -ServerName $SQLServer -CheckRemote $CheckRemote
		}

$ODWUser = $SQLUser
$ScriptBlock = { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' }
$InvokeCommandCheckMSSQL = OIS_TryInvokeCommand -ServerName $SQLServer

If ($V -eq $False){OIS_WriteOutput -Verbose $True -MessageText "Prerequisites Summary for Data Warehouse (MSSQL) Server:" -MessageType heading}

If ($InvokeCommandCheckMSSQL -eq $True -Or $CheckRemote -eq $False) {
	#Write-host " "
	#Write-host "Checking Software Prerequisites for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
	OIS_WriteOutput -Verbose $V -MessageText "Checking Software Prerequisites for Data Warehouse (MSSQL) Server" -MessageType heading
	#Write-host " "

		if ($CheckRemote -eq $True) {
		#Write-host "Confirming MSSQL Installation on remote server $SQLServer" #-ForegroundColor Yellow
		OIS_WriteOutput -Verbose $V -MessageText "Confirming MSSQL Installation on remote server $SQLServer" -MessageType info
		Invoke-Command -ComputerName $SQLServer -ScriptBlock $ScriptBlock
		}
		else {
		#Write-host "Confirming MSSQL Installation on Localhost $SQLServer"
		OIS_WriteOutput -Verbose $V -MessageText "Confirming MSSQL Installation on Localhost $SQLServer" -MessageType info
		Invoke-Command -ScriptBlock $ScriptBlock
		}
	#Write-host "Checking Installed Software" -ForegroundColor Yellow
	OIS_WriteOutput -Verbose $V -MessageText "Checking Installed Software" -MessageType heading
	$SoftwMS = $SQLServer | OIS_GetInstalledPrograms -PN "*Management Studio*" -Property DisplayName,DisplayVersion | format-table
			If ($SoftwMS) {
				if ($V -eq $True){$SoftwMS} elseif ($V -eq $False){Write-Host "Management Studio is installed" -ForegroundColor Yellow}
			}
			elseif (!$SoftwMS) {
				Write-host "Management Studio software is missing on server $SQLServer." -ForegroundColor Red
				Write-Host " "
			}
	$SoftwNC = $SQLServer | OIS_GetInstalledPrograms -PN "*Native Client*" -Property DisplayName,DisplayVersion | format-table
			If ($SoftwNC) {
				if ($V -eq $True){$SoftwMS}
				$NCVersion = $SQLServer | OIS_GetInstalledPrograms -PN "*Native Client*" -Property DisplayVersion 
				$NCDisVersion = $NCVersion | Select-Object -Property DisplayVersion
				#$NCDisVersion.DisplayVersion
				If ($V -eq $False){Write-Host "Native Client version: " -NoNewline -ForegroundColor Yellow
								$NCDisVersion.DisplayVersion}#perhaps this can be made shorter.
			}
			elseif (!$SoftwNC) {
				Write-host "Native Client software is missing on server $SSRSServer." -ForegroundColor Red
				Write-Host " "
			}	
	#Write-host "Checking Network Prerequisites Requirements for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
	OIS_WriteOutput -Verbose $V -MessageText "Checking Network Prerequisites Requirements for Data Warehouse (MSSQL) Server" -MessageType heading
	#OIS_GetEntUserSPN -EntUserName $ODWUser
	[string]$ODWSpnUser = $ODWUser
	If ($ODWSpnUser -match "\\") {OIS_GetEntUserSPN -EntUserName $ODWSpnUser.split("\")[1] } ElseIf ($ODWSpnUser -match "@") {OIS_GetEntUserSPN -EntUserName $ODWSpnUser.split("@")[0] } Else {OIS_GetEntUserSPN -EntUserName $ODWSpnUser}
	OIS_CheckWinRMListener -ServerName $SQLServer #bug: pre-check
	Write-host " "
	}
else {
	Write-host " "
	Write-Host "Invoke-Command is not working for $SQLServer. Prerequisites check will not be possible." -ForegroundColor Red
	}
	
} #end of function OIS_Prerequisites_MSSQL

########################################################## SSIS 
#PREREQUISITES FOR SSIS SERVER:
function OIS_Prerequisites_SSIS {
param(
	[Parameter(Mandatory=$True)]
	$ServerName,
	$UserName,
	[switch]$V = $False
)

$SSISServer = $ServerName
$SSISUser = $UserName
$CheckRemote = OIS_SF_TestIfRemote -ServerName $SSISServer
#$CheckRemote

<# 		if (!$SSISServer) {
		$SSISServer = OIS_GetSSISServer
		} #>

		if (!$SSISUser) {
		$SSISUser = OIS_GetServiceUser -ServiceName SSIS -CheckRemote $CheckRemote -ServerName $SSISServer
		}

$ErrorActionPreference = "Stop"
$SSISresultsarray =@("Summary of prerequisites testing:")
$ODWUser = $SSISUser
$ScriptBlock = { Get-Service | Where-Object {$_.name -like "MsDtsServer130"} }
$InvokeCommandCheckSSIS = OIS_TryInvokeCommand -ServerName $SSISServer

If ($InvokeCommandCheckSSIS -eq $True -Or $CheckRemote -eq $False ) {

	if ($SSISServer -eq "localhost") {
		$CheckRemote = $fales
		$SSISServer = $Env:Computername
	}

	#Write-host " "
	OIS_WriteOutput -Verbose $V -MessageText "Checking Software Prerequisites for Data Warehouse (SSIS) Server" -MessageType heading
	#Write-host "Checking Software Prerequisites for Data Warehouse (SSIS) Server" -ForegroundColor Yellow
	#Write-host " "

		if ($CheckRemote -eq $True) {
		#Write-host "Confirming MSSQL Installation on Remote Host $SSISServer" #-ForegroundColor Yellow
		OIS_WriteOutput -Verbose $V -MessageText "Confirming MSSQL Installation on Remote Host $SSISServer" -MessageType info
		Invoke-Command -ComputerName $SSISServer -ScriptBlock $ScriptBlock
		}
		else {
		#Write-host "Confirming MSSQL Installation on Localhost $SSISServer"
		OIS_WriteOutput -Verbose $V -MessageText "Confirming MSSQL Installation on Localhost $SSISServer" -MessageType info
		Invoke-Command -ScriptBlock $ScriptBlock
		}

	#Write-host " "
	#Write-host "Checking Installed Software" -ForegroundColor Yellow
	OIS_WriteOutput -Verbose $V -MessageText "Checking Installed Software" -MessageType heading
	$SoftwDT = $SSISServer | OIS_GetInstalledPrograms -PN "*data tools*" -Property DisplayName,DisplayVersion | format-table
		If ($SoftwDT) {
			OIS_WriteOutput -Verbose $V -MessageText "Data Tools for Visual Studio is installed"
			if ($V -eq $True){$SoftwDT}
			#$SoftwDT.GetType()
		}
		elseif (!$SoftwDT) {
			Write-host "Data Tools software is missing on server $SSISServer." -ForegroundColor Red
			Write-Host " "
		}
		
	$SoftwNC = $SSISServer | OIS_GetInstalledPrograms -PN "*Native Client*" -Property DisplayName,DisplayVersion | format-table
		If ($SoftwNC) {
			OIS_WriteOutput -Verbose $V -MessageText "Native Client is installed"
			if ($V -eq $True){$SoftwNC}
		}
		elseif (!$SoftwNC) {
			Write-host "Native Client software is missing on server $SSISServer." -ForegroundColor Red
			Write-Host " "
		}
		
	#Write-host "Checking Network Prerequisites Requirements for Data Warehouse (SSIS) Server" -ForegroundColor Yellow
	OIS_WriteOutput -Verbose $V -MessageText "Checking Network Prerequisites Requirements for Data Warehouse (SSIS) Server" -MessageType heading
	Write-host " "
	OIS_CheckPSModule -ModuleName SqlServer
	OIS_CheckPSModule -ModuleName SQLPS
	
	Write-host " "
	OIS_CheckTFD -ServerName $SSISServer
	OIS_CheckWinRMListener -ServerName $SSISServer
	OIS_TryInvokeCommand -ServerName $SSISServer
	#OIS_SSIS_GetSQLServer
	OIS_SSIS_GetSQLServerConfig -ServerName $SSISServer -ServiceName SSIS -CheckRemote $CheckRemote
	Write-host " "

	<# OIS_GetEntUserSPN -EntUserName $ODWUser
	OIS_CheckWinRMListener -ServerName $SSISServer #>
}
else {
	Write-host " "
	Write-Host "Invoke-Command is not working for $SSISServer. Prerequisites check will not be possible." -ForegroundColor Red
	$SSISresultsarray = $SSIRSresultsarray += OIS_WriteOutput -Verbose $V -MessageText "Invoke-Command is not working for $SSRSServer. Prerequisites check will not be possible." -MessageType error
}
$SSISresultsarray
} # end of function OIS_Prerequisites_SSIS

######################################
#PREREQUISITES FOR SSRS SERVER:
function OIS_Prerequisites_SSRS {
param(
	[Parameter(Mandatory=$True)]
	$ServerName,
	$UserName,
	[switch]$V = $False
)

$SSRSServer = $ServerName
$SSRSUser = $UserName
$CheckRemote = OIS_SF_TestIfRemote -ServerName $SSRSServer

<# 		if (!$SSRSServer) {
		$SSRSServer = OIS_XML_GetSQLConfig -Command SSRSServer
		} #>

		if (!$SSRSUser) {
		$SSRSUser = OIS_GetServiceUser -ServiceName SSRS -ServerName $SSRSServer -Verbose $V -CheckRemote $CheckRemote #OIS_GetSSRSUser
		}

#$ErrorActionPreference = "Stop"

$SSRSresultsarray =@("Summary of prerequisites testing:")
#$CheckRemote #= $false

$ScriptBlock = { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' }
$InvokeCommandCheckSSRS = OIS_TryInvokeCommand -ServerName $SSRSServer
#$InvokeCommandCheckSSRS

	If ($InvokeCommandCheckSSRS -eq $True -Or $CheckRemote -eq $False) {

		#Write-host " "
		OIS_WriteOutput -Verbose $V -MessageText "Checking Software Prerequisites for Data Warehouse (MSSQL) Server" -MessageType heading
		#Write-host "Checking Software Prerequisites for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
		#Write-host " "

			if ($CheckRemote) {
			#Write-host "Confirming MSSQL Installation on Remote Host $SSRSServer" #-ForegroundColor Yellow
			OIS_WriteOutput -Verbose $V -MessageText "Confirming MSSQL Installation on Remote Host $SSRSServer" -MessageType info
			Invoke-Command -ComputerName $SSRSServer -ScriptBlock $ScriptBlock
			}
			else {
			#Write-host "Confirming MSSQL Installation on Localhost $SSRSServer"
			OIS_WriteOutput -Verbose $V -MessageText "Confirming MSSQL Installation on Localhost $SSRSServer" -MessageType info
			Invoke-Command -ScriptBlock $ScriptBlock
			}


		#Write-host "Checking Installed Software" -ForegroundColor Yellow
		OIS_WriteOutput -Verbose $V -MessageText "Checking Installed Software" -MessageType heading
		$SoftwMS = $SSRSServer | OIS_GetInstalledPrograms -PN "*Management Studio*" -Property DisplayName,DisplayVersion | format-table
			If ($SoftwMS) {
				$SoftwMS
			}
			elseif (!$SoftwMS) {
				Write-host "Management Studio software is missing on server $SSRSServer." -ForegroundColor Red
				#$SSRSresultsarray = $SSRSresultsarray += OIS_WriteOutput -Verbose $V -MessageText "Management Studio software is missing on server $SSRSServer" -MessageType error
				#Write-Host " "
			}
				
		$SoftwNC = $SSRSServer | OIS_GetInstalledPrograms -PN "*Native Client*" -Property DisplayName,DisplayVersion | format-table
			If ($SoftwNC) {
				$SoftwNC
				#$NCVersion = $SoftwNC.DisplayVersion
				#$NCVersion #not working
			}
			elseif (!$SoftwNC) {
				#$SoftwNC
				Write-host "Native Client software is missing on server $SSRSServer." -ForegroundColor Red
				#$SSRSresultsarray = $SSRSresultsarray += OIS_WriteOutput -Verbose $V -MessageText "Native Client software is missing on server $SSRSServer." -MessageType error
				#Write-Host " "
			}
			
		#Write-host "Checking Authentication Methods: $AuthMethod " -ForegroundColor Yellow
		OIS_WriteOutput -Verbose $V -MessageText "Checking Authentication Methods: $AuthMethod " -MessageType heading
		#Write-host " "
		OIS_SSRS_GetAuthMethod -ServerName $SSRSServer -CheckRemote $CheckRemote | format-list
		Start-Sleep -s 1
		#Write-host "Checking Network Prerequisites Requirements for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
		OIS_WriteOutput -Verbose $V -MessageText "Checking Network Prerequisites Requirements for Data Warehouse (MSSQL) Server" -MessageType heading
		[string]$SSRSSpnUser = $SSRSUser 
		If ($SSRSSpnUser -match "\@") {OIS_GetEntUserSPN -EntUserName $SSRSSpnUser.split("@")[0] } Elseif ($SSRSSpnUser -match "\\") {OIS_GetEntUserSPN -EntUserName $SSRSSpnUser.split("\")[1] } Else {OIS_GetEntUserSPN -EntUserName $SSRSSpnUser}  #-ErrorAction SilentlyContinue 
		OIS_CheckWinRMListener -ServerName $SSRSServer

		#Write-host "Checking SPNs for SSRS Server $SSRSServer"
		OIS_WriteOutput -Verbose $V -MessageText "Checking SPNs for SSRS Server $SSRSServer" -MessageType info
		OIS_GetSPN -ServiceClass MSSQLSvc -ComputerName $SSRSServer
	}
	else {
	#Write-host " "
	Write-Host "Invoke-Command is not working for $SSRSServer. Prerequisites check will not be possible." -ForegroundColor Red
	#$SSRSresultsarray = $SSRSresultsarray += OIS_WriteOutput -Verbose $V -MessageText "Invoke-Command is not working for $SSRSServer. Prerequisites check will not be possible." -MessageType error
	OIS_GetSPN -ServiceClass MSSQLSvc -ComputerName $SSRSServer
	OIS_GetEntUserSPN -EntUserName $SSRSUser
	}
#Write-Host "Summary of prerequisites testing:"
#needs to have pause for few seconds bofore using:
#OIS_WriteOutput -Verbose $True -MessageText $SSRSresultsarray -MessageType error
$SSRSresultsarray
}# end of function OIS_Prerequisites_SSRS

#Export-ModuleMember -Function 'GetInfo'