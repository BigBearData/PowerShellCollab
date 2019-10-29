Function Create-Database {

    <#
    .SYNOPSIS
        Creates DB
    .DESCRIPTION
        Creates DB in given instance
    .PARAMETER User
        DB user name
    .PARAMETER Password
        Password of DB user
    .PARAMETER Instance
        Instance of DB server
    .PARAMETER DBName
        Name of DB
    .PARAMETER SnapshotIsolation
        Snapshots ISO isolation
    .PARAMETER IsCI
        If this a manual install or CI triggered
		
    .EXAMPLE
        Create-Database -User sa -Password 'P@55word' -Instance "demodb" -DBName "testDB" -SnapshotIsolation $false -DBLogin 'megamart\srvc_omada' -DBAdmin 'sa' -DBPass 'Omada12345'
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

    [Parameter (Mandatory)]
    [string]$SnapshotIsolation,

    [Parameter ()]
    [string]$DBLogin,

    [Parameter (Mandatory)]
    [string]$DBAdmin,

    [Parameter (Mandatory)]
    [string]$DBPass, 

    [Parameter ()]
    [bool]$useSQLUser = $false,
    
	[Boolean]$IsCI = $false


    )
    if ($useSQLUser){
        $targetConn = New-Object ('Microsoft.SqlServer.Management.Common.ServerConnection') ($Instance, $DBAdmin, $DBPass)
        $sqlserver = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $targetConn
    }
    else{
         $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
         $SqlConnection.ConnectionString = ("Server={0};Database=master;Integrated Security=True" -F $Instance)
         $sqlserver = New-Object ("Microsoft.SqlServer.Management.Smo.Server") $SqlConnection
    }
    $path = $sqlserver.Databases["msdb"].FileGroups[0].Files[0].FileName | Split-Path -Parent

    $log = ($DBName + "_log")
    $c = "
        if db_id('$DBName') is null
        begin
            CREATE DATABASE [$DBName]
            CONTAINMENT = NONE
            ON  PRIMARY 
            ( NAME = N'$DBName', FILENAME = N'$path\$DBName.mdf' , FILEGROWTH = 1024KB )
            LOG ON 
            ( NAME = N'$log', FILENAME = N'$path\$log.ldf' , SIZE = 1024KB , FILEGROWTH = 10%)
            ;
        end
            "
            if ($useSQLUser){
                Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c
            }
            else{
                Invoke-Sqlcmd -ServerInstance $Instance -Query $c
            }

            $c = "
            USE [$DBName]
            declare @dbname varchar(256)
            declare @sql nvarchar(256)
            select @dbname=db_name(dbid) from master..sysprocesses where spid=@@SPID
            set @sql = 'ALTER DATABASE [' + @dbname + '] SET ALLOW_SNAPSHOT_ISOLATION ON'
            exec sp_executesql @sql
            set @sql = 'ALTER DATABASE [' + @dbname + '] SET READ_COMMITTED_SNAPSHOT ON'
            exec sp_executesql @sql
            ;
            
       "
       if ($useSQLUser){
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c
        }
        else{
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c
        }

    if ($DBLogin.Length -gt 0){
        Show-Info -IsCI $IsCI -Message ("Creating user {0} in DB" -F $DBLogin) -ForegroundColor Yellow
        $c = "
        IF NOT EXISTS 
            (SELECT name  
            FROM master.sys.server_principals
            WHERE name = '$DBLogin')
        BEGIN
            CREATE LOGIN [$DBLogin] FROM WINDOWS WITH DEFAULT_LANGUAGE=[us_english]
        END
        "
        if ($useSQLUser){
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c
        }
        else{
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c
        }

        Add-UserToDatabase -DBLogin $DBLogin -Instance $Instance -DBName $DBName -Role "db_owner" -User $user -Password $Password -useSQLUser $useSQLUser

    }
    

    Show-Info -IsCI $IsCI -Message "Finished creating '$dbName' " -foregroundcolor Green
}
