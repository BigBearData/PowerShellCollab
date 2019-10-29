function Get-DtexecPath{

<#
    .SYNOPSIS
        Gets path to dtexec file
    .DESCRIPTION
        
    .PARAMETER SQLVersion
        MS SQL version
	.PARAMETER IsCI
        If this a manual install or CI triggered
     
    .EXAMPLE
        Get-DtexecPath -SQLVersion "2012"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$SQLVersion,

	[Parameter (Mandatory)]
    [string]$SQLVersionNo,

    [Parameter ()]
    [string]$Server = 'localhost',

    $Credential = $null,
    [Boolean]$IsCI = $false
    )

    $ScriptBlock = {
        $version = $args[0]
        $t = New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
        $result = (Get-ItemProperty -Path ("HKCR:\SOFTWARE\Microsoft\Microsoft SQL Server\{0}0\SSIS\Setup\DTSPath" -F $version)).'(default)'
        Remove-PSDrive -Name HKCR
        #Show-Info -IsCI $IsCI -Message ("Resutl is {0}" -F $result)
        if ($result.EndsWith("DTS\")){
            $result += "Binn\"
        }
        $result
    }

    if ($Server -eq 'localhost' -or $Server -eq $env:ComputerName){
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $SQLVersionNo
    }
    else{
        Invoke-Command -ComputerName $Server -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $SQLVersionNo
    }

}
