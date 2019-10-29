function Start-WebSite{

    <#
    .SYNOPSIS
        Pings web site
    .DESCRIPTION
        Is used to spin up a web page. This is usefull on Enterprise Server if you want to import changesets before accessing the it.

        When you spin up Enterprise Server for the first time.

        1. When you spin up the web page for the first time the database will be uddated with the latest scripts.
        2. You are able to import changesets.

    .PARAMETER Url
        Web site url
    .PARAMETER User
        Username for web site
    .PARAMETER Password
        Password for web site
    .PARAMETER Domain
        User Domain
    .PARAMETER IsCI
        If this a manual install or CI triggered
     
    .EXAMPLE
        Start-WebSite -Url "http://enterpriseserver/" -User "Administrator" -Password "Omada12345" -Domain "Megamart"
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$Url,
        [String]$User,
        [String]$Password,
        [String]$Domain,
		[Boolean]$IsCI = $false
    )
Show-Info -IsCI $IsCI -Message "Starting website" -foregroundcolor yellow;

   $web = New-Object system.Net.WebClient
    $web.UseDefaultCredentials=$true
    Try{
        #$web.Credentials
        $web.credentials = new-object system.net.networkcredential($User,$Password,$Domain)
        $t = $web.Downloadstring("$url")
        Show-Info -IsCI $IsCI -Message ("Web site {0} correctly loaded" -F $url) -ForegroundColor Green
        }
    Catch { 
    Write-Warning "$($error[0])" 
    }
}
