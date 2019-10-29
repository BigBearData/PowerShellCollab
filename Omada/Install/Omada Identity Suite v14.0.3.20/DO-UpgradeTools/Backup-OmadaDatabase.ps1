
Function Backup-OmadaDatabase {
    <#
    .SYNOPSIS
        Script backups databases used by Omada components
    .DESCRIPTION
        Script backups databases used by Omada components based on configuration file
    .PARAMETER XMLPath
        Path to xml file with configuration

    .EXAMPLE
        Backup-OmadaDatabase -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\installv12.config"
    #>
    [cmdletbinding()]
    Param(
    [Parameter (Mandatory)]
    [string]$XMLPath,
    [ValidateSet("false", "true")]
    [string]$backupAll = "false",
    [string]$backupSubPath = "DBsBackup",
    $ErrorActionPreference = "stop"
    )
    if (Test-Path $XMLPath){
        [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
    }
    else{
        Write-Host "Configuration file is missing" -ForegroundColor Red
        break
    }

    $backupPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/BackupPath").Path
    $t = Join-Path -Path $backupPath -ChildPath $backupSubPath
    Backup-Databases -Xml $xmlcfg -BackupPath $t -BackupAll ([System.Convert]::ToBoolean($backupAll))

}