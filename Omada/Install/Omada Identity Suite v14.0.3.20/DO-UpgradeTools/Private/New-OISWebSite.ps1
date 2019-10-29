Function New-OISWebSite{
    <#
    .SYNOPSIS
        Creates web site in local iis
    .DESCRIPTION
        Creates web site and may remove also app pool
    .PARAMETER IISAppPoolName
        App Pool Name
    .PARAMETER IISWebSite
        Web site name
    .PARAMETER WebSitePath
        PAth to web site
    .PARAMETER WebSiteBinding
        Binding added to web site
    .PARAMETER Full
        If app pool should be also created
    .PARAMETER IsCI
        If this a manual install or CI triggered
	.PARAMETER Port
		Port number of web site binding - if needed
	.PARAMETER SetAuthenticationSettings
		If the default authentication settings of web site should be changed
	.PARAMETER isDemo
		If this a demo creation - then remove default bindings
	.PARAMETER isTA
		if this is a special case of demo creation - TA

    .EXAMPLE
        New-OISWebSite -IISAppPoolName "Enterprise server" -IISWebSite "Enterprise Server" -AppPool $true -WebSitePath "C:\Program Files\Omada Identity Suite\Enterprise Server 12\website" -WebSiteBinding "enterpriseserver" -Firewall $true -AppPoolUser "megamart\srvc_omada" -AppPoolUserPassword "Omada12345" -CertThumbprint '629159577035C3939AE852EB29468DEB116424E8'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$IISWebSite,
    
    [Parameter (Mandatory)]
    [string]$IISAppPoolName,

    [Parameter (Mandatory)]
    [string]$WebSitePath,

    [Parameter (Mandatory)]
    [string]$WebSiteBinding,

    [Parameter ()]
    [string]$AppPool = $false,

    [Parameter ()]
    [string]$Firewall = $false,

    [Parameter (Mandatory)]
    [string]$AppPoolUser,

    [Parameter (Mandatory)]
    [string]$AppPoolUserPassword,

	[string]$CertThumbprint = '',
    [Boolean]$IsCI = $false,
	[Parameter ()]
    [int]$Port = 80,
	
	[Parameter ()]
    [bool]$SetAuthenticationSettings = $true,

	[bool]$isDemo = $false,
	[bool]$isTA = $false
    )

    if ($AppPool -eq $true){
        if(Test-Path IIS:\AppPools\$IISAppPoolName){
            Show-Info -IsCI $IsCI -Message ("App pool {0} exists, skipping." -F $IISAppPoolName) -ForegroundColor Red
        }else{
            Show-Info -IsCI $IsCI -Message ("Creating app pool {0}..." -F $IISAppPoolName) -ForegroundColor Yellow
            $t = New-WebAppPool -Name $IISAppPoolName
            Set-ItemProperty iis:\apppools\$IISAppPoolName -name processModel -value @{userName=$AppPoolUser;password=$AppPoolUserPassword;identitytype=3}
            Sleep -Seconds 5
            Show-Info -IsCI $IsCI -Message "App pool created" -ForegroundColor Green
        }
    }

    $t = (Get-Website –Name $IISWebSite)
    if ($t -eq $null){
        Show-Info -IsCI $IsCI -Message ("Creating web site {0}..." -F $IISWebSite) -ForegroundColor Yellow
        if ($CertThumbprint.Length -gt 0){
            Show-Info -IsCI $IsCI -Message "Adding https binding" -ForegroundColor Yellow 
            Get-Item IIS:\SslBindings\*!443 | Remove-Item
			$certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $CertThumbprint}
			$t = New-Item iis:\Sites\$IISWebSite -PhysicalPath $WebSitePath -ApplicationPool $IISAppPoolName -AutoStart $true -Bindings @{protocol="http";bindingInformation="*:" + [string]$Port + ":$WebSiteBinding"}
			New-WebBinding -Name $IISWebSite  -Protocol "https" -Port 443 -HostHeader $WebSiteBinding -SslFlags 1
            $t = Get-Item -Path ("IIS:\SslBindings\*!443!{0}" -F $WebSiteBinding)
			if ($t -eq $null){
				$t = New-Item -Path ("IIS:\SslBindings\!443!{0}" -F $WebSiteBinding) -Value $certificate -SSLFlags 1
			}
			
		}
		else{
			Show-Info -IsCI $IsCI -Message "Adding http binding" -ForegroundColor Yellow 
			Show-Info -IsCI $IsCI -Message ("Adding binding for {0}" -f $ip) -ForegroundColor Yellow 
			$t = New-Item iis:\Sites\$IISWebSite -PhysicalPath $WebSitePath -Bindings @{protocol="http";bindingInformation="*:" + [string]$Port + ":$WebSiteBinding"} -ApplicationPool $IISAppPoolName -AutoStart $true
			if ((Get-NetIPAddress | Where-Object {$_.PrefixOrigin -eq 'Dhcp'}) -ne $null){
				$ip = ((Get-NetIPAddress -PrefixOrigin "dhcp").IPAddress | Where-Object {$_ -ne "127.0.0.1"})
				Show-Info -IsCI $IsCI -Message ("Adding binding for {0}" -f $ip) -ForegroundColor Yellow 
				if ($ip -ne $null){
					Show-Info -IsCI $IsCI -Message ("Binding added {0}" -f $ip) -ForegroundColor Green
					New-WebBinding -Name $IISWebSite -IPAddress $ip -Port 80 -HostHeader '' | Out-Null
				}else{
					Show-Info -IsCI $IsCI -Message ("Binding not added {0}" -f $ip) -ForegroundColor Red
					Show-Info -IsCI $IsCI -Message "Unable to add binding to ES web site" -ForegroundColor Yellow
				}
			}else{
				Show-Info -IsCI $IsCI -Message "Unable to add binding to ES web site, dhcp address not found" -ForegroundColor Yellow
			}
			
		}		
        Show-Info -IsCI $IsCI -Message "Web site created" -ForegroundColor Green
    
    }
    else{
        Show-Info -IsCI $IsCI -Message ("Web site {0} exists, skipping" -F $IISWebSite) -ForegroundColor red
    }

	if($isDemo){
        #change bindings so ES portal will be the "default" page
		try{
			$t = Get-item 'IIS:\Sites\Default Web Site'
		}catch{}
		if($t -ne $null){
			try{
				Remove-WebBinding -Name $t.name -Protocol 'https'
			}catch{}
			try{
				Remove-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader '*'
			}catch{}
			try{
				Remove-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader '127.0.0.1'
			}catch{}
			Show-Info -IsCI $IsCI -Message "Removed default bindings for Default Web Page" -ForegroundColor Green
			#add binding for "default" address - FQDN of computer, workaround so exchange will be still working
			$defaultBinding = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
			$tt = Get-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader $defaultBinding
			if ($tt -eq $null){
				New-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader $defaultBinding
			}
			$tt = Get-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader (Get-WmiObject win32_computersystem).DNSHostName
			if ($tt -eq $null){
				New-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader (Get-WmiObject win32_computersystem).DNSHostName
			}
        
		}

		$t = (Get-Website –Name $IISWebSite)
		if($t -ne $null){
			#New-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader '*'
			$ip = ((Get-NetIPAddress -PrefixOrigin "dhcp").IPAddress | Where-Object {$_ -ne "127.0.0.1"})
			New-WebBinding -Name $t.name -Protocol 'http' -Port 80 -HostHeader $ip
			if ($CertThumbprint.Length -gt 0){
				$certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $CertThumbprint}
				New-WebBinding -Name $t.name  -Protocol "https" -Port 443 -HostHeader '*' -SslFlags 1
				Show-Info -IsCI $IsCI -Message ("Added '*' bindings for {0}" -f $IISWebSite) -ForegroundColor Green
			}
			
		}
		Remove-WebConfigurationProperty //defaultDocument ("IIS:\sites\" + $IISWebSite) -name files.collection -atIndex 0
		Add-WebConfiguration //defaultDocument/files ("IIS:\sites\" +  $IISWebSite) -atIndex 0 -Value @{value="main.aspx"}
    }
	if ($SetAuthenticationSettings)
	{
		if (!($isTA)){
			Show-Info -IsCI $IsCI -Message "Disable anonymous authentication" -ForegroundColor Yellow
			$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/AnonymousAuthentication" -name Enabled -location $IISWebSite -Value $false
		}else{
			Show-Info -IsCI $IsCI -Message "This is demo installation, anonymous authentication will be enabled" -ForegroundColor Yellow
		}
    	

    	Show-Info -IsCI $IsCI -Message "Enable and configure windows authentication" -ForegroundColor Yellow
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication" -name Enabled -location $IISWebSite -Value $true
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication/extendedProtection" -name tokenChecking -location $IISWebSite -Value "Require"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication/extendedProtection" -name flags -location $IISWebSite -Value "None"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication" -name useKernelMode -location $IISWebSite -Value $true

		Show-Info -IsCI $IsCI -Message "Enable basic authentication" -ForegroundColor Yellow
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/BasicAuthentication" -name Enabled -location $IISWebSite -Value $true
		Show-Info -IsCI $IsCI -Message "Add web site to trusted zone" -ForegroundColor Yellow
		$t = New-PSDrive -name HKCU -PSProvider Registry -root HKEY_CURRENT_USER -ErrorAction SilentlyContinue
		if ((Test-Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\{0}" -f $WebSiteBinding)) -eq $true){
	        Show-Info -IsCI $IsCI -Message "No need to update registry, skipping" -ForegroundColor Green
    	}
		else{
			#sometimes the key "EscDomains" is missing from the registry - check, so it will not cause error
			if (!(Test-Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"))) {
				$t = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\" -Name "EscDomains"
				Show-Info -IsCI $IsCI -Message "Added registry key: EscDomains" -ForegroundColor Green
			}
			$t = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains" -Name $WebSiteBinding
			$t = New-ItemProperty -Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\{0}" -f $WebSiteBinding) -PropertyType DWORD -Name "http" -Value "1"
			Show-Info -IsCI $IsCI -Message "Value added to registry" -ForegroundColor Green
		}
		$t = Remove-PSDrive -Name HKCU
	}

	if ($Firewall -eq $true){
        if ($CertThumbprint.Length -gt 0){
    	    $t = New-NetFirewallRule -DisplayName "Allow HTTPS In" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow
         	Show-Info -IsCI $IsCI -Message "Added firewall rule for incoming HTTPS traffic" -ForegroundColor Green
    	}
    	else{
        	$t = New-NetFirewallRule -DisplayName "Allow HTTP In" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
        	Show-Info -IsCI $IsCI -Message "Added firewall rule for incoming HTTP traffic" -ForegroundColor Green
    	}
    }
		
}
