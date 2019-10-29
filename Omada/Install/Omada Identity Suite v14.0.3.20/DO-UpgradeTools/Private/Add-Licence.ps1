Function Add-Licence{
    <#
    .SYNOPSIS
        Adds licence 
    .DESCRIPTION
        Adds\updates licence of Omada ES
    .PARAMETER User
        DB user name
    .PARAMETER Password
        Password of DB user
    .PARAMETER DBInstance
        Instance of DB
    .PARAMETER DBName
        Name of DB
    .PARAMETER LicenseKey
        License key
    .PARAMETER IsCI
        If this a manual install or CI triggered    

    .EXAMPLE
       Add-Licence -DBInstance "" -DBName "" -LicenseKey "" -User sa -Password sa
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$User,
    
    [Parameter (Mandatory)]
    [string]$Password,
    
    [Parameter (Mandatory)]
    [string]$DBInstance,
    
    [Parameter (Mandatory)]
    [string]$DBName,

    [Parameter (Mandatory)]
    [string]$LicenseKey,

    [Parameter ()]
    [bool]$useSQLUser = $true,
    
	[Boolean]$IsCI = $false

    )

    if ($useSQLUser){
        $t = Invoke-Sqlcmd -Username $User -Password $Password  -ServerInstance $DBInstance -Database $DBName -Query "Select * from tblcustomersetting where [key]='LicenseKey'"
    }
    else{
        $t = Invoke-Sqlcmd -ServerInstance $DBInstance -Database $DBName -Query "Select * from tblcustomersetting where [key]='LicenseKey'"
    }

    if (!$t.ValueStr) {
        $sql="insert into tblcustomersetting ([key], name, description, valuestr,type,category) values ('LicenseKey','License key', '','$LicenseKey',4,'Other');"
        if ($useSQLUser){
            $t = Invoke-Sqlcmd -Username $User -Password $Password  -ServerInstance $DBInstance -Database $DBName -Query "$sql"
        }
        else{
            $t = Invoke-Sqlcmd -ServerInstance $DBInstance -Database $DBName -Query "$sql"
        }
        Show-Info -IsCI $IsCI -Message "Licensekey Added" -ForegroundColor Green
    }
    else {
        $sql="UPDATE tblcustomersetting SET valuestr='$LicenseKey' WHERE [key]='LicenseKey'"
        if ($useSQLUser){
            $t = Invoke-Sqlcmd -Username $User -Password $Password  -ServerInstance $DBInstance -Database $DBName -Query "$sql"
        }else{
            $t = Invoke-Sqlcmd -ServerInstance $DBInstance -Database $DBName -Query "$sql"
        }
        
        Show-Info -IsCI $IsCI -Message "Licensekey updated" -ForegroundColor Green
    }



}
