function Get-SoftwareGUID{

    <#
    .SYNOPSIS
        Gets Guid of installed software
    .DESCRIPTION
        Gets Guid of installed software base on software name
    .PARAMETER Name
        Name of software
     
    .EXAMPLE
        Get-SoftwareGUID -Name 'Omada Provisioning Service'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$Name
    
    )
    $properties = "identifyingnumber","name","vendor","version"
    (Get-ChildItem HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products | ForEach-Object {
    $root  = $_.PsPath
    $_.GetSubKeyNames() | ForEach-Object {
        try {
            $RegKeyPath = (Join-Path -Path (Join-Path -Path $root -ChildPath $_) -ChildPath InstallProperties)
            $obj = Get-ItemProperty -Path $RegKeyPath -ErrorAction Stop
            if ($obj.UninstallString) {
                [PSCustomObject]@{
                    Path = $RegKeyPath;
                    Name = $obj.DisplayName ;
                    Vendor = $obj.Publisher ;
                    Version = $obj.DisplayVersion ; 
                    IdentifyingNumber = ($obj.UninstallString -replace "msiexec\.exe\s/[IX]{1}","")
                }
            }
        } catch {
        }
    }
    } | Select -Property $properties | Where {$_.Name -eq $Name}).IdentifyingNumber

    return $result
    
}

#Get-SoftwareGUID -Name 'Omada Identity Suite Data Warehouse'