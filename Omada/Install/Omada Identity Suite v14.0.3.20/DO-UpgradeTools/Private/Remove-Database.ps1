 Function Remove-Database {

    <#
    .SYNOPSIS
        Removes DB
    .DESCRIPTION
        Removes DB from given instance
    .PARAMETER User
        DB user name
    .PARAMETER Password
        Password of DB user
    .PARAMETER Instance
        Instance of DB server
    .PARAMETER DBName
        Name of DB
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Remove-Database -User sa -Password sa -Instance "." -DBName "testDB"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$User,
    
    [Parameter (Mandatory)]
    [string]$Password,

    [Parameter (Mandatory)]
    [string]$Instance,

    [Parameter (Mandatory)]
    [string]$DBName,

    [Parameter ()]
    [bool]$useSQLUser = $true,
    [Boolean]$IsCI = $false
    )
    try
    {
        $c1 = "USE MASTER;if db_id('$DBNAME') is not null BEGIN alter database [$DBName] set single_user with rollback immediate; END"
        $c2 = "USE MASTER;if db_id('$DBNAME') is not null BEGIN DROP DATABASE [$DBName]; END"    

        if ($useSQLUser){
            $targetConn = New-Object ('Microsoft.SqlServer.Management.Common.ServerConnection') ($Instance, $User, $Password)
            $sqlserver = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $targetConn
        }
        else{
            $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
            $SqlConnection.ConnectionString = ("Server={0};Database=master;Integrated Security=True" -F $Instance)
            $sqlserver = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $SqlConnection
        }
        $path = $sqlserver.Databases["msdb"].FileGroups[0].Files[0].FileName | Split-Path -Parent
        Show-Info -IsCI $IsCI -Message "Dropping Database '$dbName' " -foregroundcolor yellow;
        if ($useSQLUser){
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c1
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c2
        }
        else{
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c1
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c2
        }
        Show-Info -IsCI $IsCI -Message "Database '$dbName' dropped " -foregroundcolor Green
    }
    catch
    {
        Show-Info -IsCI $IsCI -Message "Database $DBName does not exist, skipping" -ForegroundColor Yellow
    }    
}
