function Run-SqlFromFile{
    <#
    .SYNOPSIS
        Runs sql query from file
    .DESCRIPTION
        Runs sql guery from file
    .PARAMETER UserName
        User name for SQL
    .PARAMETER UserPassword
        User password for SQL 
    .PARAMETER InstanceName
        Name of SQL instance
    .PARAMETER dbName
        DBName
    .PARAMETER sqlFile
        File to be executed
    .PARAMETER sqlVariables
        parameters for script
    .PARAMETER IsCI
        If this a manual install or CI triggered
    .EXAMPLE
        RunSqlFromFile "user" "Password" "testInst" "master" "C:\ODW\SQL\setupReports.sql"    
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [string]$Username, 
    [string]$Password, 
    [string]$InstanceName, 
    [string]$dbName, 
    [string]$sqlFile,
    [string]$sqlVariables,
    [Boolean]$IsCI = $false

)

    Show-Info -IsCI $IsCI -Message "Running sqlfile: $sqlFile on the database: $dbName" -ForegroundColor Yellow
    
    
    if ($sqlVariables -eq "")
    {
        Invoke-Sqlcmd -Username $Username -Password $Password -ServerInstance $InstanceName -Database $dbName -inputfile $sqlFile -QueryTimeout 300
    }

    if ($sqlVariables -ne "")
    {
    #Show-Info -IsCI $IsCI -Message "$sqlVariables"
    Invoke-Sqlcmd -Username $Username -Password $Password -ServerInstance $InstanceName -Database $dbName -inputfile $sqlFile -QueryTimeout 300 -Variable $sqlVariables
    }

    Show-Info -IsCI $IsCI -Message "Running script $sqlFile finished" -ForegroundColor Green
}