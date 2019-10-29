


If (!(Get-module ActiveDirectory)) {
Import-Module ActiveDirectory
}

<# If (!(Get-module .\OISEssential)) {
Import-Module .\OISEssential
} #>

#$EnterpriseServer = "localhost"
$EnterpriseServer = $Env:Computername
$EnterpriseUsers = OIS_GetESUser
#COMMENT OUT FOR TESTING
#$EnterpriseUsers = "srvc_omada"
$IISBinding = OIS_XML_GetESConfig -Command IISBinding


Write-host " "
Write-host "Checking Software Prerequisites for Enterprise Server" -ForegroundColor Yellow
Write-host " "
OIS_CheckIIS -ServerName $EnterpriseServer
OIS_SF_GetDotNetVersion
OIS_CheckPSModule -ModuleName SqlServer
OIS_CheckPSModule -ModuleName activedirectory
OIS_GetInstalledSoftware -SoftwareName "*Shared Management Objects"
Write-host "Checking Network Prerequisites Requirements for Enterprise Server" -ForegroundColor Yellow
OIS_GetEntUserSPN -EntUserName $EnterpriseUsers
OIS_CheckTFD -ServiceAccount $EnterpriseUsers

OIS_GetSPN -ServiceClass http -ComputerName $EnterpriseServer
OIS_GetSPN -ServiceClass http -ComputerName $IISBinding