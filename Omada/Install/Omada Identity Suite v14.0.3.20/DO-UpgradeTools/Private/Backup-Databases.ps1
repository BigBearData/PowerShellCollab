function Backup-Databases{
<#
    .SYNOPSIS
        Backup databases 
    .DESCRIPTION
        Function backups databases to specified location
    .PARAMETER BackupPath
        Path where backup files should be placed
    .PARAMETER xml
        Xml with configuration
    .PARAMETER backupAll
        If all DBs from xml should be backed up - or only those of Omada products
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
       Backup-Databases -Xml $xmlcfg -BackupPath $BackupPath -IsCI $IsCI
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$BackupPath,
        [Parameter(Mandatory=$true)]
        [Xml]$xml,
        [boolean]$backupAll = $false,
		[Boolean]$IsCI = $false

    )
        $cfgVersion = $xml.SelectNodes("/Configuration/Version")
        $databaseInstance = $cfgVersion.MSSQL.Server
        $SQLAdmUser = $cfgVersion.MSSQL.Administrator
        if ($SQLAdmUser.length -gt 0){
            $useSQLUser = $true
        }
        $SQLAdmPass = $cfgVersion.MSSQL.AdministratorPassword
        $demoDBs = $xml.SelectNodes("/Configuration/LocalConfiguration/DBS")
        if ($backupAll -eq $true){
            Show-Info -IsCI $IsCI -Message "All DBs in configuration file will be backed up" -ForegroundColor Yellow
            $dbs = $demoDBs.DB | where { $_.Backup -eq "true" -or $_.Omada -eq "true"}
        }
        else{
            Show-Info -IsCI $IsCI -Message "Only Omada product DBs will be backed up" -ForegroundColor Yellow
            $dbs = $demoDBs.DB | where { $_.Omada -eq "true"}
        }
        if ($dbs.ChildNodes.Count -gt 0){
            if ((Test-Path -Path $backupPath) -eq $true){
               Show-Info -IsCI $IsCI -Message "Cleaning old backup files..." -ForegroundColor Yellow
               Get-ChildItem $backupPath -include *.bak -recurse | foreach ($_) {remove-item $_.fullname}
            }
            else{
                $t = New-Item -ItemType directory -Path $backupPath
            }
            $sqlserver = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $databaseInstance
            $dbsList = $sqlserver.Databases
            $dbsNamesList = $dbsList.Name

            $i = 1
            foreach($node in $dbs){
                $dbName = $node.Name
                if (($dbsNamesList -contains $dbName) -eq $true){
                    $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($dbName + ".bak")
                    Show-Info -IsCI $IsCI -Message ("Starting backup of {0} to {1}, {2} of {3}" -F $dbNAme,$dbBackupPath,$i,$dbs.Count) -ForegroundColor Yellow
                    $c = ("
                        if db_id('{0}') is not null
                        begin
                           BACKUP DATABASE [{1}] TO  DISK = N'{2}' WITH NOFORMAT, NOINIT,  NAME = N'{3}', SKIP, NOREWIND, NOUNLOAD,  STATS = 10
                        end
                        " -F $dbName, $dbName, $dbBackupPath, ($dbName + " backup"))
                    if ($useSQLUser){
                        invoke-sqlcmd -query $c -database "master" -Username $SQLAdmUser -Password $SQLAdmPass -QueryTimeout 600
                    }
                    else{
                        invoke-sqlcmd -query $c -database "master" -QueryTimeout 600
                    }
                }
                else{
                    Show-Info -IsCI $IsCI -Message ('DB with name "{0}" does not exist, skipping, {1} of {2}' -F $dbName, $i,$dbs.Count) -ForegroundColor Yellow
                }
                $i++
            }
            Show-Info -IsCI $IsCI -Message "DBs backed up" -ForegroundColor Green
        }
        else{
           Show-Info -IsCI $IsCI -Message "No DBs to backup" -ForegroundColor Green
        }

}