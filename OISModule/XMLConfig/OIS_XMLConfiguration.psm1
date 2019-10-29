#https://superuser.com/questions/560329/how-to-modify-create-values-in-xml-files-using-powershell
function OIS_SF_GetXMLContent {
	$XMLFile = OIS_SF_GetXMLFileLocation
	#[xml]$myXML = Get-Content $XMLFile
	Get-Content $XMLFile
}




function OIS_XML_SetESUser {
param(
[Parameter(Mandatory=$True)]
[string]$UserName
)
	$XMLFileLocation = OIS_SF_GetXMLFileLocation
	[XML]$XMLConfig = OIS_SF_GetXMLContent
	$CurrentUser = $XMLConfig.Configuration.Version.ES.DBUser
	Write-Host "The current user is $CurrentUser"
	Read-host "Confirm changing user name to $UserName"
	$XMLConfig.Configuration.Version.ES.DBUser = $UserName
	$XMLConfig.Save($XMLFileLocation)
	Write-Host "The username has been changed from $CurrentUser to $UserName." -ForegroundColor Yellow
}

function OIS_XML_SetSQLUser {
param(
[Parameter(Mandatory=$True)]
[string]$UserName
)
	$XMLFileLocation = OIS_SF_GetXMLFileLocation
	[XML]$XMLConfig = OIS_SF_GetXMLContent
	$CurrentUser = $XMLConfig.Configuration.Version.ODW.DBUser
	Write-Host "The current user is $CurrentUser"
	Read-host "Confirm changing user name to $UserName"
	$XMLConfig.Configuration.Version.ODW.DBUser = $UserName
	$XMLConfig.Save($XMLFileLocation)
	Write-Host "The username has been changed from $CurrentUser to $UserName." -ForegroundColor Yellow
}

function OIS_XML_SetOPSUser {
param(
[Parameter(Mandatory=$True)]
[string]$UserName
)
	$XMLFileLocation = OIS_SF_GetXMLFileLocation
	[XML]$XMLConfig = OIS_SF_GetXMLContent
	$CurrentUser = $XMLConfig.Configuration.Version.OPS.DBUser
	Write-Host "The current user is $CurrentUser"
	Read-host "Confirm changing user name to $UserName"
	$XMLConfig.Configuration.Version.OPS.DBUser = $UserName
	$XMLConfig.Save($XMLFileLocation)
	Write-Host "The username has been changed from $CurrentUser to $UserName." -ForegroundColor Yellow
}

function OIS_XML_SetSSISServer {
param(
[Parameter(Mandatory=$True)]
[string]$ServerName,
[switch]$Test
)
	$XMLFileLocation = OIS_SF_GetXMLFileLocation
	[XML]$XMLConfig = OIS_SF_GetXMLContent
	$CurrentServer = $XMLConfig.Configuration.Version.MSSQL.SSIS
	Write-Host "The current servername is $CurrentServer"
	if (!$Test) {
		Read-host "Confirm changing user name to $CurrentServer"
		$XMLConfig.Configuration.Version.MSSQL.SSIS = $ServerName
		$XMLConfig.Save($XMLFileLocation)
		Write-Host "The servername has been changed from $CurrentServer to $ServerName." -ForegroundColor Yellow
		}
}

function OIS_XML_SetSQLServer {
param(
[Parameter(Mandatory=$True)]
[string]$ServerName,
[switch]$Test
)
	$XMLFileLocation = OIS_SF_GetXMLFileLocation
	[XML]$XMLConfig = OIS_SF_GetXMLContent
	$CurrentServer = $XMLConfig.Configuration.Version.MSSQL.Server
	Write-Host "The current servername is $CurrentServer"
	if (!$Test) {
		Read-host "Confirm changing user name to $CurrentServer"
		$XMLConfig.Configuration.Version.MSSQL.Server = $ServerName
		$XMLConfig.Save($XMLFileLocation)
		Write-Host "The servername has been changed from $CurrentServer to $ServerName." -ForegroundColor Yellow
		}
}

function OIS_XML_SetSQLServer {
param(
[Parameter(Mandatory=$True)]
[string]$ServerName,
[switch]$Test
)
	$XMLFileLocation = OIS_SF_GetXMLFileLocation
	[XML]$XMLConfig = OIS_SF_GetXMLContent
	$CurrentServer = $XMLConfig.Configuration.Version.MSSQL.Server
	Write-Host "The current servername is $CurrentServer"
	if (!$Test) {
		Read-host "Confirm changing user name to $CurrentServer"
		$XMLConfig.Configuration.Version.MSSQL.Server = $ServerName
		$XMLConfig.Save($XMLFileLocation)
		Write-Host "The servername has been changed from $CurrentServer to $ServerName." -ForegroundColor Yellow
		}
}




<# [xml]$myXML = Get-Content C:\blah\settings.xml
$myXML.settings.musicplayer.crossfade = 2
$myXML.Save("C:\blah\settings.xml") #>


<#  function OIS_XML_GetESConfig {
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
} #>