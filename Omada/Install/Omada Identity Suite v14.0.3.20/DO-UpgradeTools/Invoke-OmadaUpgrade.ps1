#upgrade from 11 to 12 - nothing really was done yey
#this is only upgrade to a newer version

Function Invoke-OmadaUpgrade {

    <#
    .SYNOPSIS
        Triggers install\uninstall of Omada software installed on current machine
    .DESCRIPTION
        Triggers install\uninstall of Omada software installed on current machine. Becouse of change of way how configuration is held (from file based to DB based), no 1 step upgrade is possible now.
    .PARAMETER Action
        What script should do - actions: Update, Uninstall, Install
    .PARAMETER XMLPath
        Path to xml file with configuration
    .PARAMETER IsCI
        If this a manual install or CI triggered
	.PARAMETER startIE
        If IE strould be started after installation is finished

    .EXAMPLE
        Invoke-OmadaUpgrade -Action Upgrade -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\install.config"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$XMLPath,
    [Parameter (Mandatory)]
    [ValidateSet("Uninstall", "Upgrade", "Install", "Update")]
    [string]$Action,
    [Boolean]$IsCI = $false,
	[Boolean]$startIE = $true
    )

	$moduleVersion = ("{0}.{1}.{2}.{3}" -f (Get-Module -Name "DO-UpgradeTools").Version.Major,(Get-Module -Name "DO-UpgradeTools").Version.Minor, (Get-Module -Name "DO-UpgradeTools").Version.Build, (Get-Module -Name "DO-UpgradeTools").Version.Revision)
	Show-Info -IsCI $IsCI -Message ("OISIT version: {0}" -f $moduleVersion) -ForegroundColor Green

    if (Test-Path $XMLPath){
        [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
    }
    else{
        Show-Info -IsCI $IsCI -Message "Configuration file is missing" -ForegroundColor Red
        break
    }
	if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
				if ($myInvocation.Line) {
			&"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile $myInvocation.Line
		}else{
			&"$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -file "$($myInvocation.InvocationName)" $args
		}
		exit $lastexitcode
	}

    $cfgVersion = $xmlcfg.SelectNodes("/Configuration/Version")

    $logPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/LogPath").Path
	$logPath = Join-Path -Path $logPath -ChildPath (Get-Date -Format yyyyMMddHHmm).ToString()
	if (!(Test-Path -Path $logPath)){
		$t = New-Item -Path $logPath -ItemType Directory -Force
	}
    $backupPath = ("{0}\BeforeUninstall" -F $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/BackupPath").Path)

    $MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL")
    $databaseInstance = $cfgVersion.MSSQL.Server
    #$SQLVersionNo = $cfgVersion.MSSQL.VersionNo
    $databaseSSISInstance = $cfgVersion.MSSQL.SSIS
    $databaseUserId = $MSSQLSecurity.Administrator
    $databasePassword = $MSSQLSecurity.AdministratorPassword
	if ($databasePassword.Length -gt 0){
		$databasePassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $databasePassword

	}
    $useSQLUser = $true
    if ($databaseUserId.length -eq 0){
            $useSQLUser = $false
            $databaseUserId = 'unknown'
			 $databasePassword = '404'
        }

    $LocalConfiguration = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration")
    $dbServiceUSer = $LocalConfiguration.Service.USerName

    $ropeName = $cfgVersion.RoPE.Name
    $ropeServiceName = $cfgVersion.RoPE.RoPEServiceName
    $ropeProductDatabase = $cfgVersion.RoPE.RoPEProductDatabase
    $opsName = $cfgVersion.OPS.Name
    $opsServiceName = $cfgVersion.OPS.ServiceName
    $opsProductDatabase = $cfgVersion.OPS.DBName
    $timerServiceName = $cfgVersion.ES.TimerServiceName
    $odwProductDatabase = $cfgVersion.ODW.ODWProductDatabase
    $odwProductDatabaseMaster = $cfgVersion.ODW.ODWPRoductDatabaseMaster
    $odwProductDatabaseStaging = $cfgVersion.ODW.ODWPRoductDatabaseStaging
    $odwName = $cfgVersion.ODW.Name
    $esName = $cfgVersion.ES.Name
    $esProductDatabase = $cfgVersion.ES.DBName
    $esProductDatabaseAudit = $cfgVersion.ES.AuditDBName
    $esProductSourceSystemDB = $cfgVersion.ES.SourceSystemDBName
    $esIISAppPoolName = $cfgVersion.ES.IISAppPool
    $esIISWebSite = $cfgVersion.ES.IISWebSite
	$esDropFolder = $cfgVersion.ES.DropFolder

    $uninstallODW = [System.Convert]::ToBoolean($cfgVersion.ODW.Enabled)
    $uninstallRoPE = [System.Convert]::ToBoolean($cfgVersion.RoPE.Enabled)
    $uninstallOPS = [System.Convert]::ToBoolean($cfgVersion.OPS.Enabled)
    $uninstallES = [System.Convert]::ToBoolean($cfgVersion.ES.Enabled)

    $demoEnabled = [System.Convert]::ToBoolean($xmlcfg.SelectNodes("/Configuration/Demo").Enabled)

	$ropeFolder = $cfgVersion.RoPE.InstallationPath
	$opsFolder = $cfgVersion.OPS.InstallationPath
	$odwFolder = $cfgVersion.ODW.InstallationPath
	$esFolder = $cfgVersion.ES.InstallationPath

    $administratorUser = $localConfiguration.Administrator.UserName
    $administratorUserPassword = $localConfiguration.Administrator.Password
	try{
	$administratorUserPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $administratorUserPassword
	}catch{
		Show-Info -IsCI $IsCI -Message "Administrator password not found in the config file, skipping" -ForegroundColor Yellow
	}
    $secstr = New-Object -TypeName System.Security.SecureString
    $administratorUserPassword.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $credDB = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
    <#if (($cfgVersion.MSSQL.RsOnAppServer).Length -gt 0){
			$rsOnAppServer = [System.Convert]::ToBoolean($cfgVersion.MSSQL.RsOnAppServer)
		}
		else{
			$rsOnAppServer = $false
		}
    #>
    #check SQLServer ps module
        # check ps version
        $psVersion = $PSVersionTable.PSVersion
        $correctPSVersion = $true
        if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)){
            $correctPSVersion = $false
        }
        Show-Info -IsCI $IsCI -Message ("Detected following PowerShell version: {0}.{1}" -f $psVersion.Major, $psVersion.Minor) -ForegroundColor Yellow
        if (!$correctPSVersion){
            Show-Info -IsCI $IsCI -Message "Powershell is not in a correct version, aborting" -ForegroundColor Red
            Throw
        }
        #check if sql server module can be installed
        $importedSQLModule = $false
        try{
            $installedModule = Get-InstalledModule SQLServer -ErrorAction SilentlyContinue
            if ($null -ne $installedModule){
                Import-Module SQLServer -ErrorAction Continue
                $importedSQLModule = $true
                Show-Info -IsCI $IsCI -Message "SQLServer PS module imported" -ForegroundColor Yellow
            }else{
                Show-Info -IsCI $IsCI -Message "SQLServer module not installed, installing..." -ForegroundColor Yellow
            }
        }catch{
            Show-Info -IsCI $IsCI -Message "Unable to import SQLServer PS module, installing..." -ForegroundColor Yellow
        }
        if (!$importedSQLModule){
            try{
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                Install-Module sqlserver -Force -AllowClobber
                Show-Info -IsCI $IsCI -Message "SQLServer module installed, importing..." -ForegroundColor Yellow
                Import-Module SQLServer
                Show-Info -IsCI $IsCI -Message "Module imported" -ForegroundColor Yellow
            }catch{
                Show-Info -IsCI $IsCI -Message "Unable to import SQLServer PS module" -ForegroundColor Red
                Show-Info -IsCI $IsCI -Message $_.Exception.Message
                Throw
            }
        }

		#check sql user
		if ($useSQLUser){
			try
			{
				$sqlConnection = New-Object System.Data.SqlClient.SqlConnection ("Data Source={2};database=master;User ID={0};Password={1};" -f $databaseUserId, $databasePassword, $databaseInstance)
				$sqlConnection.Open()
				$sqlConnection.Close()
			}catch{
				Show-Info -IsCI $IsCI -Message ("User {0} could not connect to SQL server" -f $databaseUserId) -ForegroundColor Red
				break
			}
		}
		#check local user
		$serviceUser = $localConfiguration.Service.UserName
		$User = Get-ADUser -Filter {sAMAccountName -eq $serviceUser}
		If ($null -eq $User){
			Show-Info -IsCI $IsCI -Message ("User {0} doesn't exist in AD, skipping password validation" -f $serviceUser) -ForegroundColor Yellow
		}else{
			$serviceUserPassword = $localConfiguration.Service.Password
			$serviceUserPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $serviceUserPassword
			Add-Type -AssemblyName System.DirectoryServices.AccountManagement
			$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('domain')
			$validUser = $DS.ValidateCredentials($serviceUser, $serviceUserPassword)
			if (!$validUser){
				Show-Info -IsCI $IsCI -Message ("User {0} could not be logged in" -f $serviceUser) -ForegroundColor Red
				break
			}
		}

	$cfgVersionType=$cfgVersion.Type
	if ($cfgVersionType -eq "Newest" -or $cfgVersionType -eq "Specific"){
		$credMaster = Get-Credential -Message "Please provide user and password to download installation packages" -ErrorAction Stop
		Show-Info -IsCI $IsCI -Message "Checking necessary permissions, please wait..." -ForegroundColor Yellow
		try{
			$t = ("Net use * /delete /y 2>&1> 'omada.log'" -f $esDropFolder)
			try{
				Invoke-Expression "& $t" -ErrorAction SilentlyContinue | Out-Null
			}
			catch{
				Show-Info -IsCI $IsCI -Message "Log files not removed, skipping" -ForegroundColor Yellow
			}
			New-PSDrive -Name S -PSProvider FileSystem -Root $esDropFolder -Credential $credMaster -ErrorAction Stop | Out-Null
		}
		catch{
			    Show-Info -IsCI $IsCI -Message $_.Exception.Message -ForegroundColor Red
				Show-Info -IsCI $IsCI -Message $_.Exception.ItemName -ForegroundColor Red
		}
		finally{
			Remove-PSDrive -Name S -ErrorAction SilentlyContinue
		}
	}
	else{
		$credMaster = $null
	}
    if (($Action -eq "Uninstall") -or ($Action -eq "Upgrade")){
        Show-Info -IsCI $IsCI -Message "Starting uninstall..." -ForegroundColor Yellow
        Show-Info -IsCI $IsCI -Message "Stopping services..." -ForegroundColor yellow
        #bool if there is no need to wait
        $noOISwait = $true

        $t = Get-CimInstance -Class Win32_Service -Filter "Name='$timerServiceName'"
        if ($null -ne $t -and $uninstallES -eq $true){
            $noOISwait = $false
            Restart-Service -ServiceName ("*{0}*" -f $timerServiceName) -Action "Stop"
        }
        elseif ($uninstallES -eq $false){
            Show-Info -IsCI $IsCI -Message "ES uninstall disabled, skipping" -ForegroundColor Yellow
        }
        else{
            Show-Info -IsCI $IsCI -Message ("Service {0} doesn't exist, skipping" -F $timerServiceName) -ForegroundColor Yellow
        }
        $t = Get-CimInstance -Class Win32_Service -Filter "Name='$ropeServiceName'"
        if ($null -ne $t -and $uninstallRoPE -eq $true){
            $noOISwait = $false
            Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Stop"
        }
        elseif ($uninstallRoPE -eq $false){
            Show-Info -IsCI $IsCI -Message "RoPE uninstall disabled, skipping" -ForegroundColor Yellow
        }
        else{
            Show-Info -IsCI $IsCI -Message ("Service {0} doesn't exist, skipping" -F $ropeServiceName) -ForegroundColor Yellow
        }
        $t = Get-CimInstance -Class Win32_Service -Filter "Name='$opsServiceName'"
        if ($null -ne $t -and $uninstallOPS -eq $true){
            try{
                $noOISwait = $false
                Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Stop"
            }
            catch{
                $ServicePID = (Get-CimInstance win32_service | Where-Object { $_.name -eq $opsServiceName}).processID
                Stop-Process $ServicePID -Force
            }
        }
        elseif ($uninstallOPS -eq $false){
            Show-Info -IsCI $IsCI -Message "OPS uninstall disabled, skipping" -ForegroundColor Yellow
        }
        else{
            Show-Info -IsCI $IsCI -Message ("Service {0} doesn't exist, skipping" -F $opsServiceName) -ForegroundColor Yellow
        }

        if (!$noOISwait){
            #wait couple of seconds so evething will stop...
            Show-Info -IsCI $IsCI -Message "Waiting for all systems to be stopped..." -ForegroundColor Yellow
            Start-Sleep -s 15
            Show-Info -IsCI $IsCI -Message "Resuming" -ForegroundColor Green
        }

        ###Backup of databases
        Try{
            Show-Info -IsCI $IsCI -Message "Backup of selected DBs" -ForegroundColor DarkGreen
            Backup-Databases -Xml $xmlcfg -BackupPath $BackupPath -IsCI $IsCI
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
             Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
             Show-Info -IsCI $IsCI -Message ("Error message: {0}, {1}" -F $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor Red
             break
        }

        $uninstallEverything = $true
         ### uninstall ROPE
        if ($uninstallRoPE -eq $true){
            Uninstall-Software -ProductName $ropeName -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $ropeProductDatabase -useSQLUser $useSQLUser -IsCI $IsCI
			if (Test-Path -Path $ropeFolder){
				#Show-Info -IsCI $IsCI -Message ("Removing RoPE folder - {0}" -f $ropeFolder) -ForegroundColor Yellow
				Remove-Item -Recurse -Force $ropeFolder
			}
        }
        else{
            $uninstallEverything = $false
            Show-Info -IsCI $IsCI -Message "Uninstall of RoPE disabled, skipping" -ForegroundColor Yellow
        }

        ### uninstall OPS
        if ($uninstallOPS -eq $true){
            Uninstall-Software -ProductName $opsName -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance  $databaseInstance -DBName $opsProductDatabase -useSQLUser $useSQLUser  -IsCI $IsCI
			if (Test-Path -Path $opsFolder){
				#Show-Info -IsCI $IsCI -Message ("Removing RoPE folder - {0}" -f $opsFolder) -ForegroundColor Yellow
				Remove-Item -Recurse -Force $opsFolder
			}
        }
        else{
            $uninstallEverything = $false
            Show-Info -IsCI $IsCI -Message "Uninstall of OPS disabled, skipping" -ForegroundColor Yellow
        }

        ###uninstall ODW
        if ($uninstallODW -eq $true){
            if ($databaseInstance -eq "localhost" -or $databaseInstance.startswith($env:ComputerName)){
                Uninstall-Software -ProductName $odwName -IsCI $IsCI
            }
            else{
                Uninstall-Software -ProductName $odwName -Cred $credDB -ComputerName $databaseSSISInstance -IsCI $IsCI
                #try{
                #    if ($databaseSSISInstance -ne $databaseInstance){
                #        Uninstall-Software -ProductName $odwName -Cred $credDB -ComputerName $databaseInstance -IsCI $IsCI
                #    }
                #}
                #catch{}
            }



            #Uninstall-Software -ProductName $odwName -Cred $credDB -ComputerName $databaseInstance -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $odwProductDatabase -useSQLUser $useSQLUser -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $odwProductDatabaseMaster -useSQLUser $useSQLUser -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $odwProductDatabaseStaging -useSQLUser $useSQLUser -IsCI $IsCI
			if (Test-Path -Path $odwFolder){
				#Show-Info -IsCI $IsCI -Message ("Removing ODW folder - {0}" -f $odwFolder) -ForegroundColor Yellow
				Remove-Item -Recurse -Force $odwFolder
			}
        }
        else{
            $uninstallEverything = $false
            Show-Info -IsCI $IsCI -Message "Uninstall of ODW disabled, skipping" -ForegroundColor Yellow
        }

        ###uninstall ES
        if ($uninstallES -eq $true){
            Remove-FullWebSite -IISAppPoolName $esIISAppPoolName -IISWebSite $esIISWebSite -Full $true -IsCI $IsCI
            Uninstall-Software -ProductName $esName -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $esProductDatabase -useSQLUser $useSQLUser -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $esProductDatabaseAudit -useSQLUser $useSQLUser -IsCI $IsCI
            Remove-Database -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -DBName $esProductSourceSystemDB -useSQLUser $useSQLUser -IsCI $IsCI
			if (Test-Path -Path $esFolder){
				Start-Sleep -s 15
				Remove-Item -Recurse -Force $esFolder -ErrorAction SilentlyContinue
			}
        }
        else{
            $uninstallEverything = $false
            Show-Info -IsCI $IsCI -Message "Uninstall of RoPE disabled, skipping" -ForegroundColor Yellow
        }



        #remove DB logni
        if ($uninstallEverything -eq $true){
            if ($demoEnabled){
                Show-Info -IsCI $IsCI -Message "This is demo environment, no need to remove db user" -ForegroundColor Yellow
            }else{
                Remove-DBUser -Domain $env:userdomain -UserToRemove $dbServiceUSer -User $databaseUserId -Password $databasePassword -Instance $databaseInstance -useSQLUser $useSQLUser -IsCI $IsCI
            }
        }
        else{
            Show-Info -IsCI $IsCI -Message "Not all components were uninstalled - database user will not be removed" -ForegroundColor Yellow
        }
        Set-Location '..\..\..\..\..\..'

        #if ((Test-Path -Path "C:\Program Files\Omada Identity Suite\") -eq $true){
        #    Remove-Item -Path "C:\Program Files\Omada Identity Suite\*" -Recurse -Force
        #}


        $reboot = $false
        $state = (Get-CimInstance -Class Win32_Service -Filter "Name='$ropeServiceName'").StartMode
        if ($state -eq "Disabled"){
            $reboot = $true
        }
        $state = (Get-CimInstance -Class Win32_Service -Filter "Name='$opsServiceName'").StartMode
        if ($state -eq "Disabled"){
            $reboot = $true
        }
        $state = (Get-CimInstance -Class Win32_Service -Filter "Name='$timerServiceName'").StartMode
        if ($state -eq "Disabled"){
            $reboot = $true
        }
        Show-Info -IsCI $IsCI -Message "Uninstall finished" -ForegroundColor green
        if ($reboot -eq $true){
            Show-Info -IsCI $IsCI -Message "A reboot of the machine is required. " -ForegroundColor Green
        }

    }
    if ($Action -eq "Upgrade" -or $Action -eq "Install"){

       #as this has to be done from skratch Call Invoke-OmadaInstallv12
       if ($reboot -eq $true){
            Show-Info -IsCI $IsCI -Message "Please reboot this machine before installation. " -ForegroundColor Green
            break
       }
       Show-Info -IsCI $IsCI -Message "Calling installation script" -ForegroundColor Cyan

       Invoke-OmadaInstall -XMLPath $XMLPath -credMaster $credMaster -IsCI $IsCI -startIE $startIE -LogPath $logPath
    }#install

	if ($Action -eq "Update"){
		Show-Info -IsCI $IsCI -Message "Calling update script" -ForegroundColor Cyan

		Invoke-OmadaUpdate  -XMLPath $XMLPath -credMaster $credMaster -IsCI $IsCI -startIE $startIE -LogPath $logPath
	}







}
