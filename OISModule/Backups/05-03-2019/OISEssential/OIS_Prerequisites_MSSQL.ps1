



#$ErrorActionPreference = "Stop"

$SQLServer = OIS_XML_GetSQLConfig -Command MSSQLServer
#$SQLServer = "salesdemo"
#COMMENT OUT FOR TESTING
$CheckRemote = OIS_SF_TestIfRemote -ServerName = $SQLServer
$CheckRemote = $false
$ODWUser = OIS_GetODWUser 
$ScriptBlock = { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' }

Write-host " "
Write-host "Checking Software Prerequisites for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
Write-host " "

	if ($CheckRemote) {
	Write-host "Confirming MSSQL Installation on Remote Host $SQLServer" #-ForegroundColor Yellow
	Invoke-Command -ComputerName $SQLServer -ScriptBlock $ScriptBlock
	}
	else {
	Write-host "Confirming MSSQL Installation on Localhost $SQLServer"
	Invoke-Command -ScriptBlock $ScriptBlock
	}

OIS_GetInstalledSoftware -SoftwareName "*Management Studio*"
OIS_GetInstalledSoftware -SoftwareName "*Native Client*"
Write-host "Checking Network Prerequisites Requirements for Data Warehouse (MSSQL) Server" -ForegroundColor Yellow
OIS_GetEntUserSPN -EntUserName $ODWUser
OIS_CheckWinRMListener -ServerName $SQLServer
Write-host " "