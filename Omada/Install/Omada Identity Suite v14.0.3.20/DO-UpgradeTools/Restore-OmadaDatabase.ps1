
Function Restore-OmadaDataBase {
    <#
    .SYNOPSIS
        Script restores databases used by Omada components
    .DESCRIPTION
        Script restores databases used by Omada components based on configuration file
    .PARAMETER XMLPath
        Path to xml file with configuration
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Restore-OmadaDB -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\installv12.config" -backupSubPath "DBsBackup"
    #>
    [cmdletbinding()]
    Param(
    [Parameter (Mandatory)]
    [string]$XMLPath,
    [string]$restoreAll = "false",
    [string]$backupSubPath,
    $ErrorActionPreference = "stop",

    [Boolean]$IsCI = $false
    )
    if (Test-Path $XMLPath){
        [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
    }
    else{
        Show-Info -IsCI $IsCI -Message "Configuration file is missing" -ForegroundColor Red
        break
    }

    $backupPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/BackupPath").Path
    $demoDBs = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/DBS")
    $cfgVersion = $xmlcfg.SelectNodes("/Configuration/Version")
    $esDBUser = $cfgVersion.ES.DBUser
    $SQLInstance = $cfgVersion.MSSQL.Server
    $MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL")
    $SQLAdmUser = $MSSQLSecurity.Administrator
    $SQLAdmPass = $MSSQLSecurity.AdministratorPassword
    if (![string]::IsNullOrEmpty($backupSubPath)) {
        $backupPath = Join-Path -Path $backupPath -ChildPath $backupSubPath
    }


    if ($restoreAll -eq "false"){
        $DBs = $demoDBs.DB | Where-Object{$_.Omada -eq "true" -and $_.Restore -eq "true"}
    }
    else{
        $DBs = $demoDBs.DB | Where-Object{$_.Omada -eq "true" -or $_.Restore -eq "true"}
    }

    foreach($adb in $DBs){
        Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $adb.Name) -ForegroundColor Yellow
        $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($adb.Name + ".bak")
        Restore-OmadaDatabaseTask -DBName $adb.Name -BackupPath $dbBackupPath -IsCI $IsCI
        Add-UserToDatabase -DBLogin $esDBUser -Instance $SQLInstance -DBName $adb.Name -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -IsCI $IsCI
    }


}