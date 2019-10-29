Function Push-ConnStringToRegistry {

    <#
    .SYNOPSIS
        Script reads or sets connection string to\from registry
    .DESCRIPTION
        Script creates entries to registry (when needed) or updates the value - when needed, or just reads it.
    .PARAMETER MajorVersion
        Major version of Omada software
    .PARAMETER Action
        Read\Write
    .PARAMETER ConnectionString
        Connection string
    .PARAMETER IsCI
        If this a manual install or CI triggered
    .EXAMPLE
        Push-ConnStringToRegistry -Action "Read" -MajorVersion "12.0"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [ValidateSet("Read", "Write")]
    [string]$Action,

    [Parameter (Mandatory)]
    [string]$MajorVersion,

    [Parameter()]
    [string]$ConnectionString,
    [Boolean]$IsCI = $false
    )


    $t = New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
    if($Action -eq "Read"){
        Show-Info -IsCI $IsCI -Message "Reading connection string from registry" -ForegroundColor Yellow
        if ((Test-Path "HKCR:\Software\Omada\Omada Enterprise\$MajorVersion") -eq $true){
            $Result = (Get-ItemProperty -Path ("HKCR:\Software\Omada\Omada Enterprise\{0}" -F $MajorVersion)).ConnStr
            Show-Info -IsCI $IsCI -Message "Connection string read" -ForegroundColor Green
        }
        else{
            Show-Info -IsCI $IsCI -Message "Required path in registry is missing. Read failed" -ForegroundColor Red
            break
        }
    }
    else{
        Show-Info -IsCI $IsCI -Message "Adding connection string to registry" -ForegroundColor Yellow
        if ((Test-Path "HKCR:\Software\Omada") -eq $false){
            New-Item -Path "HKCR:\Software" -Name "\Omada" -ErrorAction SilentlyContinue
        }
        if ((Test-Path "HKCR:\Software\Omada\Omada Enterprise") -eq $false){
            New-Item -Path "HKCR:\Software\Omada" -Name "\Omada Enterprise" -ErrorAction SilentlyContinue
        }
        if ((Test-Path "HKCR:\Software\Omada\Omada Enterprise\$MajorVersion") -eq $false){
            New-Item -Path "HKCR:\Software\Omada\Omada Enterprise" -Name "$MajorVersion" -ErrorAction SilentlyContinue
        }
        Set-ItemProperty -Path "HKCR:\Software\Omada\Omada Enterprise\$MajorVersion" -Name ConnStr -Value $ConnectionString -ErrorAction SilentlyContinue
        Show-Info -IsCI $IsCI -Message "Connection string added" -ForegroundColor Green
        
    }
    $t = Remove-PSDrive -Name HKCR

    return $ConnectionString

}