Function Get-LatestSoftwareVersion {

    <#
    .SYNOPSIS
        Gets latest version from drop folder
    .DESCRIPTION
        Gets the latest release version of software based on parent folder
    .PARAMETER DropFolder
        Parent folder of drops to look into...
     
    .EXAMPLE
        Get-LatestSoftwareVersion -DropFolder ""
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$DropFolder,
    [string]$version = "12",
    [Parameter (Mandatory)]
    [System.Management.Automation.CredentialAttribute()]
    $Credential
    )
    $x = New-PSDrive -Name P -PSProvider FileSystem -Root $DropFolder -Credential $Credential
    $result = (Get-ChildItem -Path "p:\" | Where { $_.PSIsContainer -and $_.Name.StartsWith($version) } | Sort CreationTime -Descending | Select -First 1).Name
    Remove-PSDrive -Name P

    return $result
    }
