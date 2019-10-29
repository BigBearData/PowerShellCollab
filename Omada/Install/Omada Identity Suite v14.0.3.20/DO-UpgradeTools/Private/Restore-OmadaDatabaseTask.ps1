function Restore-OmadaDatabaseTask{
    <#
    .SYNOPSIS
        Restores DB from file
    .DESCRIPTION
        Scripts restores DB from backup file
    .PARAMETER DBName
        NAme of DB
    .PARAMETER BackupPath
        PAth to backup file
    .PARAMETER IsCI
        If this a manual install or CI triggered		

    .EXAMPLE
       Restore-OmadaDatabaseTask -DBName "TestDB" -BackupPath "C:\Temp\TestDB.bak"
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$DBName,
        [Parameter(Mandatory=$true)]
        [String]$BackupPath,
		[Boolean]$IsCI = $false
    )

    $t = Test-Path -Path $BackupPath
    if ($t -eq $true){
        $sqlserver = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $databaseInstance
        $dbsList = $sqlserver.Databases
        $dbsNamesList = $dbsList.Name
        if (($dbsNamesList -contains $DBName) -eq $true){
            invoke-sqlcmd -query ("
	            ALTER DATABASE [{0}] SET OFFLINE WITH ROLLBACK IMMEDIATE
	            DROP DATABASE [{0}] 
	            RESTORE DATABASE [{0}] FROM DISK = '{1}'  WITH REPLACE
            " -F $DBName, $BackupPath) -database "master" | select -expand value_data
        }
        else{
            Show-Info -IsCI $IsCI -Message ("DB '{0}' to restore does not exists, aborting" -F $DBName) -ForegroundColor Red
            throw
        }
    }
    else{
        Show-Info -IsCI $IsCI -Message ("Backup file to restore DB '{0}' does not exists, aborting" -F $DBName) -ForegroundColor Red
        throw
    }
}



