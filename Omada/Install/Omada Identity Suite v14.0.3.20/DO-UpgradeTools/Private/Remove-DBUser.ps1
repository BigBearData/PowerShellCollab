Function Remove-DBUser {

    <#
    .SYNOPSIS
        Removes login 
    .DESCRIPTION
        Removes login from given SQL instance
    .PARAMETER Domain
        DB user name
    .PARAMETER UserToRemove
        DB user name
    .PARAMETER User
        DB user name
    .PARAMETER Password
        Password of DB user
    .PARAMETER Instance
        Instance of DB server
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Remove-DBUser -Domain "megamart -UserToRemove srvc_omada -User sa -Password sa -Instance "." 
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter ()]
    [string]$Domain = "",
    
    [Parameter (Mandatory)]
    [string]$UserToRemove,

    [Parameter (Mandatory)]
    [string]$User,

    [Parameter (Mandatory)]
    [string]$Password,

    [Parameter (Mandatory)]
    [string]$Instance,

    [Parameter ()]
    [bool]$useSQLUser = $true,
	
    [Boolean]$IsCI = $false

    )

    if ($Domain.Length -gt 0){
        $Login = ("{0}\{1}" -F $Domain, $UserToRemove)
    }
    else{
        $Login = $UserToRemove
    }
    try{
        Show-Info -IsCI $IsCI -Message "Removing DB Login $Login" -ForegroundColor Yellow
        $c = "
        USE [master];
        IF EXISTS 
            (SELECT name  
            FROM master.sys.server_principals
            WHERE name = '$Login')
        BEGIN
            DROP LOGIN [$Login]
        END"
        if ($useSQLUser){
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c
        }
        else{
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c
        }

        Show-Info -IsCI $IsCI -Message "User removed" -ForegroundColor Green
     }
    catch{
        #Show-Info -IsCI $IsCI -Message "Database $DBName did not exist"
    }
}
