Function Add-UserToDatabase {

    <#
    .SYNOPSIS
        Adds user to DB
    .DESCRIPTION
        Adds user to role in DB
    .PARAMETER User
        DB user name
    .PARAMETER Role
        Name of role
    .PARAMETER Instance
        Instance of DB server
    .PARAMETER DBName
        Name of DB
    .PARAMETER IsCI
        If this a manual install or CI triggered
		
    .EXAMPLE
        Add-UserToDatabase -DBLogin 'megamart\srvc_omada' -Instance "." -DBName "testDB" -Role "db_owner -User sa -Password "Omada12345"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$User,

    [Parameter (Mandatory)]
    [string]$Password,

    [Parameter (Mandatory)]
    [string]$Role,

    [Parameter (Mandatory)]
    [string]$Instance,

    [Parameter (Mandatory)]
    [string]$DBName,

    [Parameter (Mandatory)]
    [string]$DBLogin, 

    [Parameter ()]
    [bool]$useSQLUser = $false,
    
	[Boolean]$IsCI = $false

    )

        Show-Info -IsCI $IsCI -Message ("Adding {0} as {1} to {2}" -F $DBLogin,$Role, $DBName) -ForegroundColor Yellow

        $c = "

        USE [$DBName]
        GO
        IF NOT EXISTS 
            (SELECT name  
            FROM master.sys.server_principals
            WHERE name = '$DBLogin')
        BEGIN
            CREATE LOGIN [$DBLogin] FROM WINDOWS WITH DEFAULT_LANGUAGE=[us_english]
        END
        
		BEGIN TRY 
			IF EXISTS 
				(SELECT name 
				FROM sys.database_principals
				WHERE name = '$DBLogin')
			BEGIN
				DROP USER [$DBLogin] 
				;
			END
        END TRY  
		BEGIN CATCH 
			print 'error'
		END CATCH


        IF NOT EXISTS 
            (SELECT name 
            FROM sys.database_principals
            WHERE name = '$DBLogin')
        BEGIN
            CREATE USER [$DBLogin] FOR LOGIN [$DBLogin]
            ;
            ALTER ROLE [db_owner] ADD MEMBER [$DBLogin]
            ;
        END
        
        "    
        if ($useSQLUser){
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c
        }
        else{
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c
        }

    Show-Info -IsCI $IsCI -Message ("Finished adding {0}" -F $DBLogin) -foregroundcolor Green
}
