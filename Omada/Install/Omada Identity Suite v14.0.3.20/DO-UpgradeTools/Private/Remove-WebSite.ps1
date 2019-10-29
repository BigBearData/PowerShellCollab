Function Remove-FullWebSite{
    <#
    .SYNOPSIS
        Removes web site from local iis
    .DESCRIPTION
        Removes web site and may remove also app pool
    .PARAMETER IISAppPoolName
        App Pool Name
    .PARAMETER IISWebSite
        Web site name
    .PARAMETER Full
        If app pool should be also removed
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Remove-FullWebSite -IISAppPoolName "" -IISAppName "" -Full $true
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$IISWebSite,
    
    [Parameter ()]
    [string]$IISAppPoolName,

    [Parameter ()]
    [string]$Full = $false,
    [Boolean]$IsCI = $false

    )
	try 
	{
		$t = (Get-Website –Name $IISWebSite)
		if ($t -eq $null){
			Show-Info -IsCI $IsCI -Message ("Web site {0} does not exist, skipping..." -F $IISWebSite) -ForegroundColor Yellow
		}
		else{
			Show-Info -IsCI $IsCI -Message ("Removing web site {0}..." -F $IISWebSite) -ForegroundColor Yellow
			Get-Website -Name $IISWebSite | Remove-Website
			Show-Info -IsCI $IsCI -Message "Web site removed" -ForegroundColor Green
		}

		if ($Full -eq $true){
			if(Test-Path IIS:\AppPools\$IISAppPoolName){
				Show-Info -IsCI $IsCI -Message ("Removing app pool {0}..." -F $IISAppPoolName) -ForegroundColor Yellow
				Remove-WebAppPool -Name $IISAppPoolName
				Show-Info -IsCI $IsCI -Message "App pool removed" -ForegroundColor Green
			}else{
				Show-Info -IsCI $IsCI -Message ("App pool {0} does not exist, skipping..." -F $IISAppPoolName) -ForegroundColor Yellow
			}
		}
	}
	catch
	{
		Show-Info -IsCI $IsCI -Message "There was a problem with Get-WebSite function, minor error - not aborting"
	}
}
