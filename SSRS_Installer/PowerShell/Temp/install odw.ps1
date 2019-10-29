



		$serviceUser = "s-es"
		$serviceUserDomain
		$SQLVersionNo = "13"
		$SQLInstanceWithout = $SQLServer
		$credDB = "s-es"  					#$credDB = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
		#$cred								#$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
		#$esBinding
		#$serviceUserFullDomain
		
			#set-dcomsecurity
			#Set-DCOMSecurity -UserName "administrator" -Domain "megamart" -SQLVersion "11" -SQLServer "localhost" -Credential $null
		    Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SQLInstanceWithout -Credential $credDB -IsCI $IsCI
            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SSISInstance -Credential $credDB -IsCI $IsCI
            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -IsCI $IsCI
			
					#Set-KerberosSecurity - NO NEED
					#Set-KerberosSecurity -ESBinding 'enterpriseserver' -ServiceUser 'srvc_omada' -Domain 'ldl' -FullDomain 'ldl.com' -ComputerName 'testIS' -Credential $cred -SQLNo '13'
					Set-KerberosSecurity -ESBinding $esBinding -ServiceUser $serviceUser -Domain $serviceUserDomain -FullDomain $serviceUserFullDomain -ComputerName 'localhost' -Credential $cred -SQLNo $SQLVersionNo -IsCI $IsCI
					
			
			$t = Invoke-Command -ScriptBlock {Restart-Service -ServiceName "MSDTC"}
		 
		 ##################################################################################################################################################################################

               if ($installODW -eq $true){

		Show-Info -IsCI $IsCI -Message "3.1 DCOM configuration" -ForegroundColor DarkGreen
        try{

            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SQLInstanceWithout -Credential $credDB -IsCI $IsCI
            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SSISInstance -Credential $credDB -IsCI $IsCI
            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -IsCI $IsCI

            $secstr = New-Object -TypeName System.Security.SecureString
            $administratorUserPassword.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr

            Set-KerberosSecurity -ESBinding $esBinding -ServiceUser $serviceUser -Domain $serviceUserDomain -FullDomain $serviceUserFullDomain -ComputerName 'localhost' -Credential $cred -SQLNo $SQLVersionNo -IsCI $IsCI
            if (($SSISInstance -ne 'localhost') -or (!$SSISInstance.startswith($env:ComputerName)) -or ($SSISInstance -ne '.') -or (($pos -gt 0 -and ($SQLInstanceWithout.Substring(0,$SQLInstanceWithout.IndexOf(".")) -eq $env:COMPUTERNAME.ToLower())) -or $SQLInstanceWithout.ToLower() -eq $env:ComputerName.ToLower())){
			    Set-KerberosSecurity -ESBinding $esBinding -ServiceUser $serviceUser -Domain $serviceUserDomain -FullDomain $serviceUserFullDomain -ComputerName $SSISInstance -Credential $credDB -SQLNo $SQLVersionNo -IsCI $IsCI
            }
            if ($SQLInstanceWithout -ne $SSISInstance){
                Set-KerberosSecurity -ESBinding $esBinding -ServiceUser $serviceUser -Domain $serviceUserDomain -FullDomain $serviceUserFullDomain -ComputerName $SQLInstanceWithout -Credential $credDB -SQLNo $SQLVersionNo -IsCI $IsCI
            }

            Show-Info -IsCI $IsCI -Message "Restart Distributed Transaction Coordinator (MSDTC) service" -ForegroundColor Yellow
            if ($SQLInstance -eq 'localhost'){
                    $t = Invoke-Command -ScriptBlock {Restart-Service -ServiceName "MSDTC"}  #USE THIS ONE
                }
                else{
                    $t = Invoke-Command -ScriptBlock {Restart-Service -ServiceName "MSDTC"}
                    $t = Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock {Restart-Service -ServiceName "MSDTC"}
                    $t = Invoke-Command -ComputerName $SQLInstanceWithout -Credential $credDB -ScriptBlock {Restart-Service -ServiceName "MSDTC"}
                }

            Show-Info -IsCI $IsCI -Message "DCOM configured" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "31" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        try{
		
		###############################################################################################################################
		
			$SQLInstance = $MSSQLServer
			$SQLAdmUser = 'unknown'
			$SQLAdmPass = '404'
			$ODWProductDB = 'Omada Data Warehouse'
			$ODWProductDBStaging = 'Omada Data Warehouse Staging'
			$ODWProductDBMaster = 'Omada Data Warehouse Master'
			$odwName = "Omada Identity Suite Data Warehouse"
			$logPath = "D:\Omada_Install\BG(bankgirot)\Omada Identity Suite v14.0.3.20\Logs"
			$odwInstallerPath = "D:\Omada_Install\BG(bankgirot)\Omada Identity Suite v14.0.3.20" #Read-Host
			$ODWexe = "Omada Data Warehouse.x64 SQL 2016.exe"
			$LicenseKey  #Read-Host
			$odwInstallationPath = "C:\Program Files\Omada Identity Suite\Datawarehouse" #Read-Host
			
			
			#####
			
			$a = ("/qn /l*v \""{0}\installlog_odw.log\""" -F $logPath)   #D:\Omada_Install\BG(bankgirot)\Omada Identity Suite v14.0.3.20\Logs

            $a +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            $a +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            $a +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""	#'unknown'
            $a +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""	#'404'

            $a +=  (" SSISSERVER=\""{0}\""" -F $SQLInstance) #$MSSQLServer

            $a += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $ODWProductDB)  	#'Omada Data Warehouse'
            $a += (" ODWSTAGINGDB=\""{0}\""" -F $ODWProductDBStaging)		#'Omada Data Warehouse Staging'
            $a += (" ODWMASTER=\""{0}\""" -F $ODWProductDBMaster)			#'Omada Data Warehouse Master'
            #$a += " OISXCONN=\""$ConnectionString\"""#removed from installer from version rel 12.0.4
	        $a += (" LICENSEKEY=\""{0}\""" -F $cfgVersion.OIS.LicenseKey) #ask for this info

            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse installation starting..." -ForegroundColor Yellow
            $ScriptBlock = {

                $f = Join-Path -Path $args[0] -ChildPath $args[1]  #$odwInstallerPath, $ODWexe
                #(" /V""{0} /qn"" " -F $args[2])
                $t = Start-Process -Wait -FilePath $f -ArgumentList (" /V""{0} /qn"" " -F $args[2]) -PassThru  #-WorkingDirectory $args[0] 
				if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $args[3]} ) -eq $null -or !(Test-Path -Path $args[5])){
					Write-Host -Message ("{0} was not installed. Please check installation on {2} log for details - {1}\installlog_odw.log" -f $args[3], $logPath, $args[4]) -ForegroundColor Red
					break
				}
            }
            
            if (!$remoteDB){
				Show-Info -IsCI $IsCI -Message "Installation on local machine" -ForegroundColor Yellow 
                $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, "local machine", $odwInstallationPath
            }	#	

#####################################################################################################################################################################################3			
			
			Arguments:
			ODW\install\SQL....[version...]
			Omada Data Warehouse.x64 SQL 2016.exe
			$a arguments
			Omada Identity Suite Data Warehouse
			"local machine"
			C:\Program Files\Omada Identity Suite\Datawarehouse
			
			Ask for this info:
			$odwInstallerPath
			$ODWexe
			LicenseKey
			
			
			
		if ($SQLAdmUser.length -eq 0){
            $useSQLUser = $false
            $SQLAdmUser = 'unknown'
			$SQLAdmPass = '404'
        }