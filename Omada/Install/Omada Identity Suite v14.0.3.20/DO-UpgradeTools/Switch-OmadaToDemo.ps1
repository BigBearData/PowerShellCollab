function Switch-OmadaToDemo{
 <#
    .SYNOPSIS
        Invokes additionall updates to create demo environment
    .DESCRIPTION
        Function performs additional updates in order to make hr onboarding (type "Simple" in configuration xml), full demo creation (type "full" in configuration xml), manual upgrade from "simple"
        to "full" (parameter $isManual is set to true)
    .PARAMETER Manual
        If script is run manually - if so, then upgrade from "simple" to "full"
    .PARAMETER xml
        Xml with configuration
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Switch-OmadaToDemo -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\installv12.config" -isManual $true
           #>
           [CmdletBinding()]
    Param
    (
    [Parameter (Mandatory)]
    [string]$XMLPath,
    $ErrorActionPreference = "stop",
    [boolean]$isManual = $false,

    [Boolean]$IsCI = $false,

	[string]$logPath

    )

    if (Test-Path $XMLPath){
        [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
    }
    else{
        Show-Info -IsCI $IsCI -Message "Configuration file is missing" -ForegroundColor Red
        break
    }

    $demoEnabled = $xmlcfg.SelectNodes("/Configuration/Demo").Enabled
    #demoType: Simple (only HR), Full (Legacy, HR, AD, Exchange (dependent on config)), Empty (no systems, just suggested packages instead of core)
    $demoType = $xmlcfg.SelectNodes("/Configuration/Demo").Type
	if ($logPath.Length -eq 0){
		$logPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/LogPath").Path
		$logPath = Join-Path -Path $logPath -ChildPath (Get-Date -Format yyyyMMddHHmm).ToString()
	}
	#create folder for logs, new folder for each intallation run
	if(!(Test-Path -Path $logPath)){
		$t = New-Item -Path $logPath -ItemType Directory
	}

    if($demoEnabled -eq $false){
        Show-Info -IsCI $IsCI -Message "Demo creation is disabled, skipping" -ForegroundColor Green
    }
    elseif($demoEnabled -and $demoType -eq 'Empty'){
        Show-Info -IsCI $IsCI -Message "Demo creation is disabled, skipping - suggested packages were installed" -ForegroundColor Green
    }
    else{
        $demoTA = [System.Convert]::ToBoolean($xmlcfg.SelectNodes("/Configuration/Demo").TA)
        $cfgVersion = $xmlcfg.SelectNodes("/Configuration/Version")
        $odwConfigurationPackages = $cfgVersion.ODW.ConfigurationPackages
        $installES = [System.Convert]::ToBoolean($cfgVersion.ES.Enabled)
        $installChangesets = [System.Convert]::ToBoolean($cfgVersion.ES.Changesets.Enabled)
        $esTimerService = $cfgVersion.ES.TimerServiceName
		$esInstallationPath = $cfgVersion.ES.InstallationPath
		#$esChangesetsPath = $cfgVersion.ES.ChangesetsPath
        $backupPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/BackupPath").Path
        $backupPath = Join-Path -Path $backupPath -ChildPath "cleanSystemBackup"
        $esDBUser = $cfgVersion.ES.DBUser
        $SQLVersion = $cfgVersion.MSSQL.Version
		$SQLVersionNo = $cfgVersion.MSSQL.VersionNo
        $SQLInstance = $cfgVersion.MSSQL.Server
        $SSISInstance = $cfgVersion.MSSQL.SSIS
        $MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL")
        $SQLAdmUser = $MSSQLSecurity.Administrator
        $SQLAdmPass = $MSSQLSecurity.AdministratorPassword
        $useSQLUser = $true
        if ($SQLAdmUser.length -eq 0){
            $useSQLUser = $false
        }
        $changesetsSkipErrors = [System.Convert]::ToBoolean($cfgVersion.ES.Changesets.SkipErrors)
        if (($cfgVersion.ES.Changesets.Merge).Length -gt 0){
			$noChangesetsMerge = (![System.Convert]::ToBoolean($cfgVersion.ES.Changesets.Merge))
		}
		else{
			$noChangesetsMerge = $true
		}
        $changesetsCustomer = $cfgVersion.ES.ChangesetsCustomer
        $odwConfigurationPackages = $cfgVersion.ODW.ConfigurationPackages
        $ODWProductDB = $cfgVersion.ODW.ODWProductDatabase
		$majorVersion = $xmlcfg.SelectNodes("/Configuration/Version/OIS").Version
        $localConfiguration = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration")
        $esDBUserDomain = $localConfiguration.Service.Domain
        $esDBName = $cfgVersion.ES.DBName
        $encKey = $localConfiguration.EncryptionKey
        $opsConfiguration = $xmlcfg.SelectNodes("/Configuration/Version/OPS")
        $administratorUser = $localConfiguration.Administrator.UserName
        $administratorUserPassword = $localConfiguration.Administrator.Password
        $pushServiceUrl = $opsConfiguration.PushConfigurationWebService
        $RoPEInstallationPath = $cfgVersion.RoPE.InstallationPath
		$secstr = New-Object -TypeName System.Security.SecureString
        $administratorUserPassword.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $serviceUser = $localConfiguration.Service.UserName

		$changesetsSkipErrors = [System.Convert]::ToBoolean($cfgVersion.ES.Changesets.SkipErrors)

        $credDB = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
        $dtexecDir = Get-DtexecPath -SQLVersion $SQLVersion -Server $SSISInstance -Credential $credDB -SQLVersionNo $SQLVersionNo -IsCI $IsCI

        $ODWAuditorsGroup = $cfgVersion.ODW.ADAuditors

        if ($isManual -eq $false){
            Show-Info -IsCI $IsCI -Message ("7 Demo data upload, demo type: {0}" -F $demoType) -ForegroundColor Yellow
            #sometimes Exchange ssl binding is missing - workaround so imports will work...
			$IISWebSite = 'Exchange Back End'
			$t = (Get-Website –Name $IISWebSite)
			if ($null -ne $t){
				$tt = Get-WebBinding -Name $t.name -Protocol 'https' -Port 444 #-HostHeader (Get-WmiObject win32_computersystem).DNSHostName
				if ($null -eq $tt){
					New-WebBinding -Name $t.name -Protocol 'https' -Port 444 #-HostHeader (Get-WmiObject win32_computersystem).DNSHostName
				}
			}



			try{
                Show-Info -IsCI $IsCI -Message "7.1 DBs restore to baseline" -ForegroundColor Yellow
                if ($demoType -eq "Full"){

                    Restore-OmadaDatabase -XMLPath $XMLPath -IsCI $IsCI

                    Show-Info -IsCI $IsCI -Message "DBs Restored" -ForegroundColor Green
                    Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
                }
                else{
                    try{
                        Add-UserToDatabase -DBLogin ("{0}\{1}" -f $esDBUserDomain, $esDBUser) -Instance $SQLInstance -DBName 'Omada Data Warehouse HR' -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
                    }
                    catch {
						Show-Info -IsCI $IsCI -Message "Failed to add user to HR db, skipping" -ForegroundColor Yellow
					}
                        Show-Info -IsCI $IsCI -Message "Only HR onboard, no need to restore DBs" -ForegroundColor Green
                }
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

            Show-Info -IsCI $IsCI -Message "7.2. Main demo changesets import" -ForegroundColor DarkGreen

			try{

				Show-Info -IsCI $IsCI -Message "Updating password in changesets" -ForegroundColor Yellow
				$encryptorPath = Join-Path -Path $esInstallationPath -ChildPath 'website\bin\StringEncrypter.exe'
				$nPass = & $encryptorPath "DefaultEncryptionKey" $administratorUserPassword
				$computerName = $env:ComputerName + '.megamart.com'
				$arrayChangesets = @(
					New-Object PSObject -Property @{Name = "sob-ad.xml"; OldValue = 'PASSWORDTOBEREPLACED'; NewValue = $nPass}
                    New-Object PSObject -Property @{Name = "sob-exchange.xml"; OldValue = 'PASSWORDTOBEREPLACED'; NewValue = $nPass}
                    New-Object PSObject -Property @{Name = "configchanges_201806041357_AD_Scope.xml"; OldValue = 'PASSWORDTOBEREPLACED'; NewValue = $nPass}
					New-Object PSObject -Property @{Name = "sob-exchange.xml"; OldValue = 'COMPUTERNAMETOBEREPLACED'; NewValue = $computerName}
				)
				foreach ($changeset in $arrayChangesets){
					Show-Info -IsCI $IsCI -Message ("Updating {0}" -f $changeset.Name) -ForegroundColor Yellow
					$p = Join-Path -Path $esInstallationPath -ChildPath $changeset.Name
					if (Test-Path -Path $p){
						$c = Get-Content -Encoding UTF8 -Path $p
						$c.Replace($changeset.OldValue,$changeset.NewValue) | Set-Content $p -Force
					}

				}
				Show-Info -IsCI $IsCI -Message "Changesets updated" -ForegroundColor Green

				Show-Info -IsCI $IsCI -Message "Adding encryption key to registry" -ForegroundColor Yellow
				New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue | Out-Null
				if ((Test-Path "HKCR:\Software\Omada\Omada Enterprise") -eq $false){
					New-Item -Path "HKCR:\Software\Omada" -Name "\Omada Enterprise" -ErrorAction SilentlyContinue
				}
				if ((Test-Path "HKCR:\Software\Omada\Omada Enterprise\$MajorVersion") -eq $false){
					New-Item -Path "HKCR:\Software\Omada\Omada Enterprise" -Name "$MajorVersion" -ErrorAction SilentlyContinue
				}
				Set-ItemProperty -Path "HKCR:\Software\Omada\Omada Enterprise\$MajorVersion" -Name PswEncryptionKey -Value "DefaultEncryptionKey" -ErrorAction SilentlyContinue
				Remove-PSDrive -Name HKCR  | Out-Null
				Show-Info -IsCI $IsCI -Message "Encryption key added" -ForegroundColor Yellow



			}
			catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }



			try{
                if (($installChangesets -eq $true) -and ($installES -eq $true)){
                    Show-Info -IsCI $IsCI -Message "Changesets enabled and Enterprise Server was installed" -ForegroundColor Yellow
                    if ($demoType -eq "Simple"){
                        $t = "7.2.1"
                    }
                    else{
                        $t = "7.2.2"
                    }
                    Invoke-ChangeSet -Step $t -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge

                }
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

            Show-Info -IsCI $IsCI -Message "7.3. Additional changesets import and DB scripts run" -ForegroundColor DarkGreen
            try{
                if (($installChangesets -eq $true) -and ($installES -eq $true)){
                    Invoke-ChangeSet -Step "7.3.1" -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					if ($enableCustomization -eq $true){
						Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
						Invoke-ChangeSet -Step "7.3.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					}
                }
                #add 7.3 odw script
                Show-Info -IsCI $IsCI -Message "Running additional SQL scripts..." -ForegroundColor Yellow
                $additionalODWScripts = $xmlcfg.SelectNodes("/Configuration/Version/ODW/DBScripts")
                if ($enableCustomization -eq $true){
                    Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
                    $nodes = $additionalODWScripts.ChildNodes | Where-Object { $_.Step -eq "7.3.1" -or $_.Step -eq "7.3.2"}
                }
                else{
                    $nodes = $additionalODWScripts.ChildNodes | Where-Object { $_.Step -eq "7.3.1"}
                }
                $i = 0
                foreach($node in $nodes){
                    $sqlFile = $node.ScriptPath
                    $sqlDB = $node.DBName

                        if ($sqlFile.Length -gt 0){
                            Show-Info -IsCI $IsCI -Message ("Running {0} of {1} script(s) in {3}: {2}" -F ($i + 1),$nodes.Count, $sqlFile, $sqlDB) -ForegroundColor Yellow
                            if ((Test-Path $sqlFile) -eq $true){
                                $c = Get-Content -Encoding UTF8 -Path $sqlFile -Raw
                                $c = $c.Replace("DOMAIN",$serviceUserDomain).Replace("[Omada Data Warehouse]",("[{0}]" -F $sqlDB))
                                if ($useSQLUser){
                                    Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $sqlDB -Query $c -QueryTimeout 300 #-inputfile $sqlFile
                                }
                                else{
                                    Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $sqlDB -Query $c -QueryTimeout 300
                                }
                            }
                            else{
                                Show-Info -IsCI $IsCI -Message "SQL script is missing ($sqlFile), aborting..." -ForegroundColor Red
                                throw
                            }
                        }
                        else{
                            Show-Info -IsCI $IsCI -Message ("Missing information regarding script no. {0}, skipping" -F ($i + 1)) -ForegroundColor Yellow
                        }

                    $i++ #
                 }
                Show-Info -IsCI $IsCI -Message "Omada Data Warehouse and Enterprise Server additionally configured" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

            Show-Info -IsCI $IsCI -Message "7.4. Configuration package" -ForegroundColor DarkGreen
            try{
				#as from v12 demo firstly hr needs to be imported, then other systems
                #if ($demoType -eq "Simple"){
                   $t = "7.4.1"
                #}
                #else{
                #    $t = "7.4.2"
                #}
                $nodes = $odwConfigurationPackages.ChildNodes | Where-Object {($_.Step -eq "$t")}
                if ($null -ne $nodes){
                    Start-PackageExcution -nodes $nodes -SSISInstance $SSISInstance -encKey $encKey -logPath $logPath -step $t -dtexecDir $dtexecDir -Credential $credDB
                }
					if ($demoType -ne "Simple"){
						#as RoPE sometimes get stuck - firstly onboard hr and the all other systems
						if (($installChangesets -eq $true) -and ($installES -eq $true)){
                            #don't know why, but there was some issue with Exchange onboard when changesets are merged
							Invoke-ChangeSet -Step "7.4.2" -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $true #$noChangesetsMerge
						}
						Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
						$t = "7.4.2"
						$nodes = $odwConfigurationPackages.ChildNodes | Where-Object {($_.Step -eq "$t")}
                        if ($null -ne $nodes){
                            Start-PackageExcution -nodes $nodes -SSISInstance $SSISInstance -encKey $encKey -logPath $logPath -step $t -dtexecDir $dtexecDir -Credential $credDB
                        }
					}

                    #update for v14 which will allow basic auth
                    $encryptorPath = Join-Path -Path $esInstallationPath -ChildPath 'website\bin\Omada.CommonLib.dll'
                    $salt='TARocksEveryday'
                    $iterations=10000
                    [Reflection.Assembly]::LoadFile($encryptorPath) | Out-Null
                    $nPass = [Omada.CommonLib.CryptoLibrary]::GetPasswordHashValue($administratorUserPassword, $salt, $iterations)

                    $c = ("USE [OIS];
                    UPDATE [dbo].[tblUser] SET [Password] = '{0}', [PswSalt] =  '{1}', [LastPasswordChange] = CURRENT_TIMESTAMP WHERE [UserName] not in ('SRVC_OMADA', 'SYSTEM', 'NONE', 'ACTUSR', 'UNRESOLVED');
                    " -f $nPass.ToString(), $salt)
                    if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
                    }
                    if ($demoTA){
                        $c = "UPDATE [dbo].[tblMasterSetting] SET [ValueBool] = '1' WHERE [Key] = 'OISXBasicAuth';
                        UPDATE [dbo].[tblMasterSetting] SET [ValueBool] = '1' WHERE [Key] = 'FormsLogon';"
                        if ($useSQLUser){
                            Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
                        }
                        else{
                            Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
                        }
                    }

                    Show-Info -IsCI $IsCI -Message "Added SSRS user to ODW DB" -ForegroundColor Yellow


                Show-Info -IsCI $IsCI -Message "Systems populated" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

            Show-Info -IsCI $IsCI -Message "7.5. Data Objects import" -ForegroundColor DarkGreen
            try{
				Import-DataObject -Step "7.5" -xml $xmlcfg -IsCI $IsCI -logPath $logPath
				Show-Info -IsCI $IsCI -Message "Additional DataObjects imported" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }
            Show-Info -IsCI $IsCI -Message "7.6. Additional changesets import" -ForegroundColor DarkGreen
            try{
                if (($installChangesets -eq $true) -and ($installES -eq $true)){
                    Invoke-ChangeSet -Step "7.6.1" -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					if ($enableCustomization -eq $true){
						Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
						Invoke-ChangeSet -Step "7.6.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					}
				}
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }
			if ($demoType -ne "Simple"){
				Show-Info -IsCI $IsCI -Message "7.7. Pushing configuration to OPS" -ForegroundColor DarkGreen
				try{
					$ws = New-WebServiceProxy -uri $pushServiceUrl -UseDefaultCredential
					$t = $ws.PushConfiguration()

					Show-Info -IsCI $IsCI -Message "Configuration pushed" -ForegroundColor Green
					Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
				}
				catch{
					Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
					Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
					break
				}
				Show-Info -IsCI $IsCI -Message "7.8. Additional changesets import" -ForegroundColor DarkGreen
				try{
					if (($installChangesets -eq $true) -and ($installES -eq $true)){
						Invoke-ChangeSet -Step "7.8.1" -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
						if ($enableCustomization -eq $true){
							Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
							Invoke-ChangeSet -Step "7.8.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
						}
					}
				}
				catch{
					Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
					Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
					break
				}
			}
			Show-Info -IsCI $IsCI -Message "7.9 Updates in RoPE engine configuration file" -ForegroundColor DarkGreen
			try{
				$engineConfigPath = Join-Path -Path $RoPEInstallationPath -ChildPath "Service\ConfigFiles\EngineConfiguration.config"
				[xml]$engineConfigXml = Get-Content -Encoding UTF8 $engineConfigPath
				#change logging
				$engineConfigXml.engineConfiguration.executor.loggingLevel = "3"
                $engineConfigXml.engineConfiguration.executor.batchSize = "500"
				#$a = (1,2),(3,4)
				#remove nodes in file
				$entries = ("AD Account:MBOXSIZE","/#ASSIGNMENTS_PER_RESOURCETYPE/Mailbox size:[MBOXSIZE]")
				foreach($i in $entries){
					if($i[0].length -ne 0){
						$node = ($engineConfigXml.SelectNodes("//engineConfiguration/executor/extensions/add") | Where-Object {$_.Type -eq 'Omada.RoPE.Controller.OISX.Extensions.ReferencePathAttributeValueResolver, Omada.RoPE.Controller.OISX'}).settings.add | Where-Object {$_.key -eq $i[0]}
						try {
						$node.ParentNode.RemoveChild($node)
						}
						catch{
							Show-Info -IsCI $IsCI -Message "Node not found, skipping" -ForegroundColor Yellow
						}
					}
				}
				$engineConfigXml.Save($engineConfigPath)
		  		[xml]$engineConfigXml = Get-Content -Encoding UTF8 $engineConfigPath
				$entries =  ("Exchange User Mailbox:ISSUEWARNINGQUOTA","/#ASSIGNMENTS_PER_RESOURCETYPE/Exchange Mailbox Option:[ISSUEWARNINGQUOTA]"),
				("Exchange User Mailbox:PROHIBITSENDQUOTA","/#ASSIGNMENTS_PER_RESOURCETYPE/Exchange Mailbox Option:[PROHIBITSENDQUOTA]"),
				("Exchange User Mailbox:PROHIBITSENDRECEIVEQUOTA","/#ASSIGNMENTS_PER_RESOURCETYPE/Exchange Mailbox Option:[PROHIBITSENDRECEIVEQUOTA]"),
				("Exchange User Mailbox:PRIMARY_EMAIL","/#IDENTITY:[EMAIL]"),("Exchange User Mailbox:WEBMAIL","/#ASSIGNMENTS_PER_RESOURCETYPE/Exchange Mailbox Option:[WEBMAIL]"),
				("Exchange User Mailbox:HIDEINADDRESSLIST","/#ASSIGNMENTS_PER_RESOURCETYPE/Exchange Mailbox Option:[HIDEINADDRESSLIST]")
				$node = ($engineConfigXml.SelectNodes("//engineConfiguration/executor/extensions/add") | Where-Object {$_.Type -eq 'Omada.RoPE.Controller.OISX.Extensions.ReferencePathAttributeValueResolver, Omada.RoPE.Controller.OISX'})
				$node2 = $node.ChildNodes
				if ($null -ne $node){
                    foreach($i in $entries){
					    if($i[0].length -ne 0){
						    $t = $node2.ChildNodes | Where-Object {$_.key -eq $i[0] -and $_.value -eq $i[1] }
                            if ($null -eq $t){
                                $newNode = $engineConfigXml.CreateElement("add")
						        $newNode.SetAttribute("key",$i[0])
						        $newNode.SetAttribute("value",$i[1])
						        $node2.AppendChild($newNode)
                            }
                            else{
                                Show-Info -IsCI $IsCI -Message ("Key {0} already exists, skipping" -f $i[0]) -ForegroundColor Yellow
                            }
					    }
				    }
                }
				$engineConfigXml.Save($engineConfigPath)
		  		[xml]$engineConfigXml = Get-Content -Encoding UTF8 $engineConfigPath
				$entries =  ("Omada.OE.Custom.OIMDEMO.PolicyEngineExtension.PolicyEngineExtension, Omada.OE.Custom.OIMDEMO.PolicyEngineExtension",""),("","")
				$node = $engineConfigXml.SelectNodes("//engineConfiguration/executor/extensions")
				$node2 = $node.ChildNodes
				foreach($i in $entries){
                    $t = ($engineConfigXml.SelectNodes("//engineConfiguration/executor/extensions/add") | Where-Object {$_.Type -eq $i[0]})

                    if ($null -eq $t -and $i[0].length -ne 0){
						$newNode = $engineConfigXml.CreateElement("add")
						$newNode.SetAttribute("type",$i[0])
                        try{
						    $node.AppendChild($newNode)
                        }catch{
							Show-Info -IsCI $IsCI -Message "Node not found, skipping" -ForegroundColor Yellow
						}
                    }
                    elseif ($null -ne $t){
                        Show-Info -IsCI $IsCI -Message ("Key {0} already exists, skipping" -f $i[0]) -ForegroundColor Yellow
                    }
				}
				$engineConfigXml.Save($engineConfigPath)

			}
			catch{
					Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
					Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
					break
            }
            Show-Info -IsCI $IsCI -Message "7.10. Adding Reporting services user to ODW" -ForegroundColor DarkGreen
            try{
                $ssrsUser = (Get-CimInstance -ClassName Win32_Service | Where-Object {$_.Name -eq "ReportServer" -or $_.Name -eq "SQLServerReportingServices" } | Select-Object StartName).StartName
                if ($null -ne $ssrsUser){
                    if ($ssrsUser -eq $serviceUser){
                        Show-Info -IsCI $IsCI -Message ("Adding {0} as SSRS user to ODW DB" -f $ssrsUser) -ForegroundColor Yellow
                        $c = ("Update [{0}].dbo.tblApplicationSetting set ValueStr='{1}' where [Key]='ssrsServiceAccount'" -f $ODWProductDB, $ssrsUser)
                    }else{
                        Show-Info -IsCI $IsCI -Message ("Adding {0} as SSRS user to ODW DB" -f $serviceUser) -ForegroundColor Yellow
                        $c = ("Update [{0}].dbo.tblApplicationSetting set ValueStr='{1}' where [Key]='ssrsServiceAccount'" -f $ODWProductDB, $serviceUser)
                    }
                    if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $ODWProductDB -QueryTimeout 300 -query $c #-inputfile $sqlFile
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $ODWProductDB -QueryTimeout 300 -query $c #-inputfile $sqlFile
                    }
                    Show-Info -IsCI $IsCI -Message "Added SSRS user to ODW DB" -ForegroundColor Yellow
                }
                else{
                    Show-Info -IsCI $IsCI -Message "Reporting services were not found on this machine, skipping (Reporting services user has to be added manually)" -ForegroundColor Yellow
                }
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

            Show-Info -IsCI $IsCI -Message "7.11. Turning WebDAV feature off in ES portal" -ForegroundColor DarkGreen
            try{
                $esWebConfig = Join-Path -Path $esInstallationPath -ChildPath 'website\web.config'
                [xml]$webConfig = Get-Content -Path $esWebConfig
                $handlersNode = $webConfig.SelectSingleNode("//configuration/system.webServer/handlers")

                $config1 = $webConfig.CreateNode('element',"remove","")
                $config1.SetAttribute('name','WebDAV')
                $handlersNode.AppendChild($config1) | Out-Null

                $modulesNode = $webConfig.SelectSingleNode("//configuration/system.webServer/modules")
                $config2 = $webConfig.CreateNode('element',"remove","")
                $config2.SetAttribute('name','WebDAVModule')
                $modulesNode.AppendChild($config2) | Out-Null

                $webConfig.Save($esWebConfig)
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

            Show-Info -IsCI $IsCI -Message "7.12. Adding BWAD to auditors group" -ForegroundColor DarkGreen
            try{
                Import-Module ActiveDirectory
                $group = Get-ADGroup -Filter {Name -eq $ODWAuditorsGroup}
                $user = Get-ADUser -Identity 'BWAD'
                if ($null -ne $group -and $null -ne $user){
                    $group | Add-ADGroupMember -Members $user | Out-Null
                }
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }
        }

        if ($isManual -eq $true -or $demoType -eq "Full"){
            Show-Info -IsCI $IsCI -Message "8. Converting environment into full demo" -ForegroundColor Yellow
            try{
                if (($installChangesets -eq $true) -and ($installES -eq $true)){
                    Invoke-ChangeSet -Step "8.1.1" -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -SkipErrors $changesetsSkipErrors -IsCI $IsCI -noMerge $noChangesetsMerge
					if ($enableCustomization -eq $true){
						Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
						Invoke-ChangeSet -Step "8.1.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					}
				}
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

                Show-Info -IsCI $IsCI -Message "Importing data sets" -ForegroundColor Yellow
                if ($isManual -eq $true){
                    Import-DataObject -Step "8.2.1" -xml $xmlcfg -IsCI $IsCI -logPath $logPath
                }
                else{
                    Import-DataObject -Step "8.2.2" -xml $xmlcfg -IsCI $IsCI -logPath $logPath
                }
                Show-Info -IsCI $IsCI -Message "Dataobjects imported" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

                Show-Info -IsCI $IsCI -Message "8.3 Importing additional changesets" -ForegroundColor Yellow
                if (($installChangesets -eq $true) -and ($installES -eq $true)){
                    Invoke-ChangeSet -Step "8.3.1" -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -SkipErrors $changesetsSkipErrors -IsCI $IsCI -noMerge $noChangesetsMerge
					if ($enableCustomization -eq $true){
						Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
						Invoke-ChangeSet -Step "8.3.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					}
				}
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

                Show-Info -IsCI $IsCI -Message "Importing additional data sets" -ForegroundColor Yellow
                if ($isManual -eq $true){
                    Import-DataObject -Step "8.4.1" -xml $xmlcfg -IsCI $IsCI -logPath $logPath
                }
                else{
                    Import-DataObject -Step "8.4.2" -xml $xmlcfg -IsCI $IsCI -logPath $logPath
                }
                Import-DataObject -Step "8.4.3" -xml $xmlcfg -IsCI $IsCI -logPath $logPath
                Show-Info -IsCI $IsCI -Message "Additional dataobjects imported" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

                Show-Info -IsCI $IsCI -Message "8.5. Pushing configuration to OPS" -ForegroundColor Yellow

                if ($installChangesets -eq $true){
                    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
                    $ws = New-WebServiceProxy -uri $pushServiceUrl -Credential $cred
                    $t = $ws.PushConfiguration()
                }
                Show-Info -IsCI $IsCI -Message "Configuration pushed" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

				if (($installChangesets -eq $true) -and ($installES -eq $true)){
                    Invoke-ChangeSet -Step "8.6" -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
                }
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green


                Show-Info -IsCI $IsCI -Message "   " -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "Demo environment data loaded" -ForegroundColor Green
            }
            catch{
                Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
                break
            }

        }
    }

}