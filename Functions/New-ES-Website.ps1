
Function New-ES-Website {
param(
	$WebSiteName,
	$serviceUser,
	$serviceUserPassword,
	$esDBName,
	$SQLInstance,
	$WebSitesNumber,
	$esInstallationPath,
	$Hostheaders,
	$WebSiteBinding,
	$IISAppPoolName
	)

 if(-not $IISAppPoolName){
 $IISAppPoolName = $WebSiteName}
 
 if(-not $WebSiteBinding){
 $WebSiteBinding = "enterpriseserver"}
 
 $serviceUserDomain=$env:UserDomain
 $AppPoolUser=$serviceUser
 $IISWebSite=$WebSiteName
 $Port=80

import-module webadministration
#New-ES-Website -serviceUser Administrator -serviceUserPassword -IISAppPoolName -esInstallationPath -WebSiteName -WebSiteBinding
 
<# 	#For testing only!
	$c = ("Update tblUser set UserName=UPPER('{0}') where UserName='ADMINISTRATOR'" -F $env:USERNAME)
	invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database $esDBName #>
	
	$esWebSitePath = $esInstallationPath # (Join-Path -Path $esInstallationPath -ChildPath "website")
	$u = ("{0}\{1}" -F $serviceUserDomain, $serviceUser)
	

        if(Test-Path IIS:\AppPools\$IISAppPoolName){
            #$ES_Install_Output.text +="App pool {0} exists, skipping.`r`n" -F $IISAppPoolName 
			write-host "App pool exists"
        }else{
            #$ES_Install_Output.text +="Creating app pool {0}...`r`n" -F $IISAppPoolName
			Write-host "Crating App Pool $IISAppPoolName"
            $t = New-WebAppPool -Name $IISAppPoolName
            Set-ItemProperty iis:\apppools\$IISAppPoolName -name processModel -value @{userName=$AppPoolUser;password=$serviceUserPassword;identitytype=3}
            Sleep -Seconds 5
            #$ES_Install_Output.text +="App pool created`r`n" 
			write-host "App Pool $IISAppPoolName created."
        }
$WSexists=get-website $IISWebSite
	
    #$ws = Get-Website –Name $IISWebSite
    if ($WSexists -eq $null){
			#$ES_Install_Output.text += "Adding http binding" 
			#Show-Info -IsCI $IsCI -Message ("Adding binding for {0}" -f $ip) -ForegroundColor Yellow 
			write-host "Creating Website $IISWebSite with binding"
			$t = New-Item iis:\Sites\$IISWebSite -PhysicalPath $esWebSitePath -Bindings @{protocol="http";bindingInformation="*:" + [string]$Port + ":$WebSiteBinding"} -ApplicationPool $IISAppPoolName -AutoStart $true
			
				$ip = ((Get-NetIPAddress -PrefixOrigin "dhcp").IPAddress | Where-Object {$_ -ne "127.0.0.1"})
				#$ip
				#$ES_Install_Output.text +="Adding binding for {0}`r`n" -f $ip
				write-host "Adding binding for $ip"
				if ($ip -ne $null){
					#$ES_Install_Output.text += "Binding added {0}`r`n" -f $ip
					write-Host "Binding added for $ip"
					New-WebBinding -Name $IISWebSite -IPAddress $ip -Port 80 -HostHeader '' | Out-Null
				}else{
					#Show-Info -IsCI $IsCI -Message ("Binding not added {0}" -f $ip) -ForegroundColor Red
					#$ES_Install_Output.text += "Unable to add binding to ES web site!!`r`n" 
					write-host "Unable to add binding to ES web site!!"
				}
		
	}
	else{
        #$ES_Install_Output.text +="Web site {0} exists, skipping`r`n" -F $IISWebSite
		write-host "Web site $IISWebSite exists."
    }

		Write-host "Creating default document main.aspx"
		Remove-WebConfigurationProperty //defaultDocument ("IIS:\sites\" + $IISWebSite) -name files.collection -atIndex 0
		Add-WebConfiguration //defaultDocument/files ("IIS:\sites\" +  $IISWebSite) -atIndex 0 -Value @{value="main.aspx"}
		
		
		#$ES_Install_Output.text += "Disable anonymous authentication`r`n" 
		Write-host "Disabling anonymous authentication."
		$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/AnonymousAuthentication" -name Enabled -location $IISWebSite -Value $false
			
    	#$ES_Install_Output.text += "Enable and configure windows authentication`r`n" 
		Write-host "Enable and configure windows authentication"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication" -name Enabled -location $IISWebSite -Value $true
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication/extendedProtection" -name tokenChecking -location $IISWebSite -Value "Require"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication/extendedProtection" -name flags -location $IISWebSite -Value "None"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication" -name useKernelMode -location $IISWebSite -Value $true

		#$ES_Install_Output.text += "Enable basic authentication`r`n" 
		write-Host "Enabling basic authentication."
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/BasicAuthentication" -name Enabled -location $IISWebSite -Value $true

}

New-ES-Website -serviceUser "Administrator" -serviceUserPassword "SuperSecret123" -IISAppPoolName "Enterprise Server2" -esInstallationPath "C:\Program Files\Omada Identity Suite\Enterprise Server\website" -WebSiteName "Enterprise Server2" -WebSiteBinding "enterpriseserver2"