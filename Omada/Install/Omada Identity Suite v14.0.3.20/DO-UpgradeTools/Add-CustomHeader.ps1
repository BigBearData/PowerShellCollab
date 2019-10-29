
Function Add-CustomHeader {
    <#
    .SYNOPSIS
        Script adds custom header
    .DESCRIPTION
        Script adds custom headers to a web site
    .PARAMETER WebSiteName
        Name of the web site
	.PARAMETER HeaderName
        Name of the header
	.PARAMETER HeaderValue
        Valie of the header
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Add-CustomHeader -WebSiteName "Enterprise Server" -HeaderName "X-Content-Type-Options" -HeaderValue "nosniff"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
   [string]$WebSiteName,

   [Parameter (Mandatory)]
   [string]$HeaderName,

   [Parameter (Mandatory)]
   [string]$HeaderValue,

    [Boolean]$IsCI = $false
    )
		try
		{
            Import-Module WebAdministration;
			Add-WebConfigurationProperty //system.webServer/httpProtocol/customHeaders  "IIS:\sites\$WebSiteName"  -Name collection -Value @{name=$HeaderName;value=$HeaderValue}
		    Show-Info -IsCI $IsCI -Message ("Header {0} for web site {1} updated" -f $WebSiteName, $HeaderName) -ForegroundColor Yellow
		}
		Catch [System.Exception]
		{
			Show-Info -IsCI $IsCI -Message  $_.Exception.Message  -ForegroundColor Red
		}

}