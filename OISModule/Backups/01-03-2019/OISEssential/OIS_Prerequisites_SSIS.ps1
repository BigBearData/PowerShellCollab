



$ErrorActionPreference = "Stop"

$SSISServer = OIS_GetSSISServer
#$SSISServer #= "salesdemo"
#COMMENT OUT FOR TESTING
$CheckRemote = OIS_SF_TestIfRemote -ServerName $SSISServer
#$CheckRemote = $false
$ODWUser = OIS_GetODWUser 
$ScriptBlock = { Get-Service | Where-Object {$_.name -like "SSIS*"} }

if ($SSISServer -eq "localhost") {
	$CheckRemote = $fales
	$SSISServer = $Env:Computername
}

Write-host " "
Write-host "Checking Software Prerequisites for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
Write-host " "

	if ($CheckRemote) {
	Write-host "Confirming MSSQL Installation on Remote Host $SSISServer" #-ForegroundColor Yellow
	Invoke-Command -ComputerName $SSISServer -ScriptBlock $ScriptBlock
	}
	else {
	Write-host "Confirming MSSQL Installation on Localhost $SSISServer"
	Invoke-Command -ScriptBlock $ScriptBlock
	}

OIS_GetInstalledSoftware "*data tools*"
OIS_GetInstalledSoftware -SoftwareName "*Native Client*"
OIS_CheckPSModule -ModuleName SqlServer
Write-host "Checking Network Prerequisites Requirements for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
Write-host " "
OIS_CheckTFD -ServerName $SSISServer
OIS_CheckWinRMListener -ServerName $SSISServer
OIS_TryInvokeCommand -ServerName $SSISServer
Write-host " "

<# OIS_GetEntUserSPN -EntUserName $ODWUser
OIS_CheckWinRMListener -ServerName $SSISServer #>