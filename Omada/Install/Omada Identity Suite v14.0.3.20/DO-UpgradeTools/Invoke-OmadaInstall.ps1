
Function Invoke-OmadaInstall {

    <#
    .SYNOPSIS
        Script performs installation of Omada Identity Suite in version 12
    .DESCRIPTION
        Script performs installation of Omada Identity Suite in version 12 on a clean machine with Windows 2012R2 and MS SQL. All confirutation is taken from xml file - ToDo creation of this file based on user input
    .PARAMETER XMLPath
        Path to xml file with configuration
	.PARAMETER credMaster
		Credential passed to script - if it is passed, no prompt is shown
    .PARAMETER IsCI
        If this a manual install or CI triggered
	.PARAMETER startIE
        If IE strould be started after installation is finished

    .EXAMPLE
        Invoke-OmadaInstall -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\install.config"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$XMLPath,

	[System.Management.Automation.PSCredential]$credMaster,

    $ErrorActionPreference = "stop",

    [Boolean]$IsCI = $false,

	[Boolean]$startIE = $true,

	[string]$LogPath
    )
    $tstart = Get-Date

	$moduleVersion = ("{0}.{1}.{2}.{3}" -f (Get-Module -Name "DO-UpgradeTools").Version.Major,(Get-Module -Name "DO-UpgradeTools").Version.Minor, (Get-Module -Name "DO-UpgradeTools").Version.Build, (Get-Module -Name "DO-UpgradeTools").Version.Revision)
	Show-Info -IsCI $IsCI -Message ("OISIT version: {0}" -f $moduleVersion) -ForegroundColor Green
	$moduleVersion = ("{0}.{1}" -f (Get-Module -Name "DO-UpgradeTools").Version.Major,(Get-Module -Name "DO-UpgradeTools").Version.Minor)

	if (Test-Path $XMLPath){
        [xml]$xmlcfg = Get-Content $XMLPath -Encoding UTF8
    }
    else{
        Show-Info -IsCI $IsCI -Message "Configuration file is missing" -ForegroundColor Red
        break
    }



    $tempPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/TemporaryFolder").Path
    $backupPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/BackupPath").Path
	if ($logPath.Length -eq 0){
		$logPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/LogPath").Path
		$logPath = Join-Path -Path $logPath -ChildPath (Get-Date -Format yyyyMMddHHmm).ToString()
	}
	#create folder for logs, new folder for each intallation run
	if(!(Test-Path -Path $logPath)){
		$t = New-Item -Path $logPath -ItemType Directory
	}

    Show-Info -IsCI $IsCI -Message "1. Preparation of installation" -ForegroundColor DarkGreen

    Show-Info -IsCI $IsCI -Message "1.1. Preparation of installation files" -ForegroundColor DarkGreen
    try{

        $cfgVersion = $xmlcfg.SelectNodes("/Configuration/Version")
        $localConfig = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration")
        $demoType = $xmlcfg.SelectNodes("/Configuration/Demo").Type
        $demoEnabled = [System.Convert]::ToBoolean($xmlcfg.SelectNodes("/Configuration/Demo").Enabled)
        $demoTA = [System.Convert]::ToBoolean($xmlcfg.SelectNodes("/Configuration/Demo").TA)
        $SQLVersion = $cfgVersion.MSSQL.Version
        $SQLVersionNo = $cfgVersion.MSSQL.VersionNo
        $SQLInstance = $cfgVersion.MSSQL.Server
        $SSISInstance = $cfgVersion.MSSQL.SSIS
        $SSRSPath = $cfgVersion.MSSQL.SSRSPath
        $esExe = $cfgVersion.ES.Exe
        $esDBName = $cfgVersion.ES.DBName
        $esAuditDBName = $cfgVersion.ES.AuditDBName
        $esSourceSystemDBName = $cfgVersion.ES.SourceSystemDBName
        $esDBUser = $cfgVersion.ES.DBUser
        $esDBPassword = $cfgVersion.ES.DBPassword
        $esDBPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $esDBPassword

        $esTimerService = $cfgVersion.ES.TimerServiceName
        $esip = (Get-NetIPAddress).IPv4Address | Select-Object -First 1
        $ODWexe = $cfgVersion.ODW.Exe
        $odwName = $cfgVersion.ODW.Name
        $RoPEexe = $cfgVersion.RoPE.Exe
        $ropeName = $cfgVersion.RoPE.Name
        $OPSexe = $cfgVersion.OPS.Exe
		$opsName = $cfgVersion.OPS.Name
		$esName = $cfgVersion.ES.Name

		$esAppPool = $cfgVersion.ES.IISAppPool
        $esWebSite = $cfgVersion.ES.IISWebSite
        $esBinding = $cfgVersion.ES.IISBinding
		$esThumbprint = $cfgVersion.ES.CertThumbprint

        $odwDBPassword = $cfgVersion.ODW.DBPass
        $odwDBPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $odwDBPassword
        $owdDBUser = $cfgVersion.ODW.DBUser

        $ropeDBUser = $cfgVersion.RoPE.DBUser
        $ropeDBPass = $cfgVersion.RoPE.DBUserPassword
        $ropeDBPass = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $ropeDBPass

        $installES = [System.Convert]::ToBoolean($cfgVersion.ES.Enabled)
        $installSQLSysClrTypes2012 = [System.Convert]::ToBoolean($cfgVersion.ES.InstallSQLSysClrTypes2012)
        $installReportViewer2012 = [System.Convert]::ToBoolean($cfgVersion.ES.InstallReportViewer2012)
        $installODW = [System.Convert]::ToBoolean($cfgVersion.ODW.Enabled)
        $installRoPE = [System.Convert]::ToBoolean($cfgVersion.RoPE.Enabled)
        $installOPS = [System.Convert]::ToBoolean($cfgVersion.OPS.Enabled)
        $installChangesets = [System.Convert]::ToBoolean($cfgVersion.ES.Changesets.Enabled)

        $changesetsSkipErrors = [System.Convert]::ToBoolean($cfgVersion.ES.Changesets.SkipErrors)
		if (($cfgVersion.ES.Changesets.Merge).Length -gt 0){
			$noChangesetsMerge = (![System.Convert]::ToBoolean($cfgVersion.ES.Changesets.Merge))
		}
		else{
			$noChangesetsMerge = $true
		}

        $copyChangesets = [System.Convert]::ToBoolean($cfgVersion.ES.Changesets.CopyToLocalPath)

        #check SQL server
		if (($cfgVersion.MSSQL.RsOnAppServer).Length -gt 0){
			$rsOnAppServer = [System.Convert]::ToBoolean($cfgVersion.MSSQL.RsOnAppServer)
		}
		else{
			$rsOnAppServer = $false
		}
        $t = (Get-SQLName -SQLInstance $SQLInstance -rsOnAppServer $rsOnAppServer)
        #$SQLName = $t.SQLName
        $SQLInstanceWithout = $t.SQLInstanceWithout
        $rsServer = $t.rsServer
        $remoteDB = $t.remoteDB
        $sqlInstanceName = $t.SQLInstanceName
		$encKey = $localConfig.EncryptionKey

        #reports
        $uploadReports = [System.Convert]::ToBoolean($cfgVersion.ODW.UploadReports.Enabled)
        $skipReportErrors = [System.Convert]::ToBoolean($cfgVersion.ODW.UploadReports.SkipErrors)
        $rsHttps = [System.Convert]::ToBoolean($cfgVersion.MSSQL.RsHttps)
		if ($rsOnAppServer -eq $true){
			$ssrsServiceName = "ReportServer"
			$ServiceStatus = Get-Service -name $ssrsServiceName -ErrorAction SilentlyContinue
			Show-Info -IsCI $IsCI -Message ("Looking for {0}..." -f $ssrsServiceName) -ForegroundColor yellow
			#as SSRS on SQL 2014 has different service name
			if ($null -eq $ServiceStatus){
				$ssrsServiceName = "SQLServerReportingServices"
				$ServiceStatus = Get-Service -name $ssrsServiceName -ErrorAction SilentlyContinue
				Show-Info -IsCI $IsCI -Message ("Looking for {0}..." -f $ssrsServiceName) -ForegroundColor yellow
			}
			#check ssrs in names instances (if needed)
			if ($null -ne $sqlInstanceName -and $null -eq $ServiceStatus){
				$ssrsServiceName = ('ReportServer${0}' -f $sqlInstanceName)
				$ServiceStatus = Get-Service -name $ssrsServiceName -ErrorAction SilentlyContinue
				Show-Info -IsCI $IsCI -Message ('Looking for {0}...' -f $ssrsServiceName) -ForegroundColor yellow
				#as SSRS on SQL 2014 has different service name
				if ($null -eq $ServiceStatus){
					$ssrsServiceName = ('SQLServerReportingServices${0}' -f $sqlInstanceName)
					$ServiceStatus = Get-Service -name $ssrsServiceName -ErrorAction SilentlyContinue
					Show-Info -IsCI $IsCI -Message ('Looking for {0}...' -f $ssrsServiceName) -ForegroundColor yellow
				}
			}
			if ($null -eq $ServiceStatus){
				Show-Info -IsCI $IsCI -Message "Reporting services were not found on this machine" -ForegroundColor Red
				throw
			}
			elseif($ServiceStatus.Status -ne "Running"){
				Show-Info -IsCI $IsCI -Message "Reporting services are not running on this machine" -ForegroundColor Red
				throw
			}
		}
        $disableForceSSL = [System.Convert]::ToBoolean($cfgVersion.ES.DisableReportServerForceSSL)
        $updateHostsFile = [System.Convert]::ToBoolean($cfgVersion.ES.UpdateHostsFile)
		$createImportTask = [System.Convert]::ToBoolean($cfgVersion.ES.AddDailyImportTask)
		$esFeaturesToInstall = $cfgVersion.ES.Features
		$esImportSurveys = [System.Convert]::ToBoolean($cfgVersion.ES.SurveyTemplates.Enabled)
        $enableCustomization = [System.Convert]::ToBoolean($localConfig.Customization)
        $demoDBs = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/DBS")
        $demoRoPEFiles = $xmlcfg.SelectNodes("/Configuration/Version/RoPE/ConfigFiles")
        $odwUploadReportsToolPath = $cfgVersion.ODW.UploadReports.InnerText

        $opsConfiguration = $xmlcfg.SelectNodes("/Configuration/Version/OPS")
        $opsProductDatabase = $opsConfiguration.DBName
        $opsDBUser = $opsConfiguration.DBUser
        $opsDBPass = $opsConfiguration.DBPassword
        $opsDBPass = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $opsDBPass
        $opsServiceName = $opsConfiguration.ServiceName
        $pushServiceUrl = $opsConfiguration.PushConfigurationWebService

        $ODWProductDB = $cfgVersion.ODW.ODWProductDatabase
        $ODWProductDBStaging = $cfgVersion.ODW.ODWProductDatabaseStaging
        $ODWProductDBMaster = $cfgVersion.ODW.ODWProductDatabaseMaster
        $RoPEProductDB = $cfgVersion.RoPE.RoPEProductDatabase
        $RoPEInstallationPath = $cfgVersion.RoPE.InstallationPath

        $esInstallationPath = $cfgVersion.ES.InstallationPath

		$ODWAdminsGroup = $cfgVersion.ODW.ADAdmins
		$ODWAuditorsGroup = $cfgVersion.ODW.ADAuditors
		$ODWUsersGroup = $cfgVersion.ODW.ADUsers

        $restoreESDB = $false
        $restoreSourceSystemDB = $false
        $restoreAuditDB = $false
        $restoreODWProductDB = $false
        $restoreODWProductDBStaging = $false
        $restoreODWProductDBMaster = $false
        $restoreRoPEDB = $false
        $restoreOPSDB = $false

        $esInstallerPath = (Join-Path -Path $TempPath -ChildPath "ES\install")
        $odwInstallerPath = (Join-Path -Path $TempPath -ChildPath ("ODW\install\SQL{0}" -F $SQLVersion))
        $ropeInstallerPath = (Join-Path -Path $TempPath -ChildPath "RoPE\install\RoPE")
        $opsInstallerPath = (Join-Path -Path $TempPath -ChildPath "OPS\install\Default Configuration\Release\DiskImages\DISK1")
		$changesetPath = $xmlcfg.SelectNodes("/Configuration/Version/ES").ChangesetsPath
        $odwInstallationPath = $cfgVersion.ODW.InstallationPath
		$opsInstallationPath = $cfgVersion.OPS.InstallationPath

		$allPackages = $false
		$demoEnabled = $xmlcfg.SelectNodes("/Configuration/Demo").Enabled

		$localConfiguration = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration")
        $serviceUser = $localConfiguration.Service.UserName
        $serviceUserPassword = $localConfiguration.Service.Password
        $serviceUserPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $serviceUserPassword
        $serviceUserDescription = $localConfiguration.Service.Description
        $serviceUserFullDomain = $localConfiguration.Service.Domain + "." + $localConfiguration.Service.DomainExt
        $serviceUserDomain = $localConfiguration.Service.Domain
        $administratorUser = $localConfiguration.Administrator.UserName
        $administratorUserPassword = $localConfiguration.Administrator.Password
        $administratorUserPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $administratorUserPassword
        $administratorDomain = $localConfiguration.Administrator.Domain

        $majorVersion = $xmlcfg.SelectNodes("/Configuration/Version/OIS").Version
        $MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL")
        $SQLServer = $MSSQLSecurity.Server
        $useSQLUser = $true
        $SQLAdmUser = $MSSQLSecurity.Administrator
		$SQLAdmPass = $MSSQLSecurity.AdministratorPassword
        if ($SQLAdmPass.length -gt 0){
			$SQLAdmPass = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $SQLAdmPass
		}
        if ($SQLAdmUser.length -eq 0){
            $useSQLUser = $false
            $SQLAdmUser = 'unknown'
			$SQLAdmPass = '404'
        }
        $MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL/IntegratedSecurity")
        $ConnectionString = ("Data Source={0};Initial Catalog={1};" -F $SQLServer, $ESDBName)

		$secstr = New-Object -TypeName System.Security.SecureString
        $administratorUserPassword.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $credDB = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
		$dtexecDir = Get-DtexecPath -SQLVersion $SQLVersion -Server $SSISInstance -Credential $credDB -SQLVersionNo $SQLVersionNo -IsCI $IsCI

        $demoEnabled = [System.Convert]::ToBoolean($xmlcfg.SelectNodes("/Configuration/Demo").Enabled)
        #$osVersion = (Get-WmiObject win32_OperatingSystem).Version.Split(".")[0]
		$osVersion = (Get-CimInstance Win32_OperatingSystem).version.Split(".")[0]
        $stopRopeService = [System.Convert]::ToBoolean($cfgVersion.RoPE.StopServiceDuringInstallation)
		$ropeServiceName = $cfgVersion.RoPE.RoPEServiceName

		$languageVersion = $cfgVersion.ES.LanguageVersion

        #end of variables

        #check SQLServer ps module
        # check ps version
        $psVersion = $PSVersionTable.PSVersion
        $correctPSVersion = $true
        if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)){
            $correctPSVersion = $false
        }
        Show-Info -IsCI $IsCI -Message ("Detected following PowerShell version: {0}.{1}" -f $psVersion.Major, $psVersion.Minor) -ForegroundColor Yellow
        if (!$correctPSVersion){
            Show-Info -IsCI $IsCI -Message "Powershell is not in a correct version (5.1 or newer), aborting" -ForegroundColor Red
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

        #verify if ssrs path exists
        if ($rsOnAppServer){
            if (!(Test-Path -Path $SSRSPath)){
                Show-Info -IsCI $IsCI -Message ("Provided Reporting Services path does not exist {0}, aborting..." -f $SSRSPath) -ForegroundColor Red
				break
            }
        }else{
            If (!(Invoke-Command -ComputerName $SQLInstanceWithout -ScriptBlock {Test-Path -Path $args[0]} -ArgumentList $SSRSPath)){
                Show-Info -IsCI $IsCI -Message ("Provided Reporting Services path does not exist {0}, aborting..." -f $SSRSPath) -ForegroundColor Red
				break
            }
        }

		$netVersion = (Get-ItemProperty ‘HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full’  -Name Release).Release
		$net = ''
		$netok = 'no'
		if ($netVersion -eq '378389'){
			$net = '4.5'
		}elseif ($netVersion -eq '378675' -or $netVersion -eq '378758'){
			$net = '4.5.1'
		}elseif ($netVersion -eq '379893'){
			$net = '4.5.2'
		}elseif ($netVersion -eq '393295' -or $netVersion -eq '393297'){
			$net = '4.6'
		}elseif ($netVersion -eq '394254' -or $netVersion -eq '394271' -or $netVersion -eq '394294'){
			$net = '4.6.1'
			$netok = 'yes'
		}elseif ($netVersion -eq '394802' -or $netVersion -eq '394806'){
			$net = '4.6.2'
			$netok = 'yes'
		}elseif ($netVersion -eq '460798' -or $netVersion -eq '460805'){
			$net = '4.7.0'
			$netok = 'yes'
        }elseif ($netVersion -eq '461308' -or $netVersion -eq '461310'){
			$net = '4.7.1'
			$netok = 'yes'
        }elseif ($netVersion -eq '461814' -or $netVersion -eq '461808'){
			$net = '4.7.2'
			$netok = 'yes'
        }elseif ($netVersion -gt '461814'){
			$net = 'unknown'
			$netok = 'unknown'
		}

		if ($netok -eq 'no'){
			Show-Info -IsCI $IsCI -Message ("Microsoft .Net is not in correct version: {0}" -f $net) -ForegroundColor Red
			break
		}elseif ($netok -eq 'yes'){
			Show-Info -IsCI $IsCI -Message ("Microsoft .Net version: {0}" -f $net) -ForegroundColor Green
		}else{
			Show-Info -IsCI $IsCI -Message ("Unknown Microsoft .Net version: {0}, this is not critical issue" -f $net) -ForegroundColor Red
		}




        if ($installES -eq $true -and $installODW -eq $true -and $installRoPE -eq $true -and $installOPS -eq $true){
            $isFullInstall = $true
            Show-Info -IsCI $IsCI -Message "This is a full Omada Identity Suite installation" -ForegroundColor Green
        }
        else{
            $isFullInstall = $false
            Show-Info -IsCI $IsCI -Message "This is a component oriented Omada Identity Suite installation" -ForegroundColor DarkGreen
        }

        Show-Info -IsCI $IsCI -Message "Checking if any DB will be restored" -ForegroundColor Yellow
        $dbs = $demoDBs.DB | Where-Object { $_.Restore -eq "true"}
        if ($dbs.Name -contains $esDBName){
           $restoreESDB = $true
           Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $esDBName) -ForegroundColor Green
        }
        if ($dbs.Name -contains $esSourceSystemDBName){
            $restoreSourceSystemDB = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $esSourceSystemDBName) -ForegroundColor Green
        }
        if ($dbs.Name -contains $esAuditDBName){
            $restoreAuditDB = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $esAuditDBName) -ForegroundColor Green
        }
        if ($dbs.Name -contains $ODWProductDB){
            $restoreODWProductDB = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $ODWProductDB) -ForegroundColor Green
        }
        if ($dbs.Name -contains $ODWProductDBStaging){
            $restoreODWProductDBStaging = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $ODWProductDBStaging) -ForegroundColor Green
        }
        if ($dbs.Name -contains $ODWProductDBMaster){
            $restoreODWProductDBMaster = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $ODWProductDBMaster) -ForegroundColor Green
        }
        if ($dbs.Name -contains $RoPEProductDB){
            $restoreRoPEDB = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $RoPEProductDB) -ForegroundColor Green
        }
        if ($dbs.Name -contains $opsProductDatabase){
            $restoreOPSDB = $true
            Show-Info -IsCI $IsCI -Message ("DB '{0}' will be restored" -F $opsProductDatabase) -ForegroundColor Green
        }
        $errorValue = $false
        if ($dbs.ChildNodes.Count -gt 0){
            $backupPath = Join-Path -Path $tempPath -ChildPath "Backup"
            foreach($node in $dbs){
                $dbName = $node.Name
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($dbName + ".bak")
                $t = Test-Path -Path $dbBackupPath
                if ($t -eq $true){
                   Show-Info -IsCI $IsCI -Message ("Backup file of {0} found" -F $dbName) -ForegroundColor Green
                }
                else{
                   Show-Info -IsCI $IsCI -Message ("Backup file of {0} not found" -F $dbName) -ForegroundColor Red
                   $errorValue = $true
                }
            }
        }
        if ($errorValue -eq $true){
            Show-Info -IsCI $IsCI -Message "Not all DB backup files were found" -ForegroundColor Red
            throw
        }
        if ($installES -eq $false){
            Show-Info -IsCI $IsCI -Message "Enterprise Server will not be installed" -ForegroundColor Green
        }
        if ($installODW -eq $false){
            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse will not be installed" -ForegroundColor Green
        }
        if ($installRoPE -eq $false){
            Show-Info -IsCI $IsCI -Message "Role and Policy Engine will not be installed" -ForegroundColor Green
        }
        if ($installOPS -eq $false){
            Show-Info -IsCI $IsCI -Message "Omada Provisioning Server will not be installed" -ForegroundColor Green
        }

        $cfgVersionType=$cfgVersion.Type
    }
    catch{

		Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }

    try{
        if ($cfgVersionType -eq "Newest"){
            Show-Info -IsCI $IsCI -Message "Newest versions of OIS will be installed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "Credentials for network share are required" -ForegroundColor Yellow
				if ($null -eq $credMaster){
					$credential = Get-Credential -Message "Please provide user and password to download installation packages" -ErrorAction Stop
				}
				else{
					$credential = $credMaster
				}
            Show-Info -IsCI $IsCI -Message "Credentials provided" -ForegroundColor Yellow
            if ($installES -eq $true){
                $ESVersion = Get-LatestSoftwareVersion -DropFolder $cfgVersion.ES.DropFolder -Credential $credential -Version $majorVersion.Split('.')[0]
            }
            if ($installODW -eq $true){
                $ODWVersion = Get-LatestSoftwareVersion -DropFolder $cfgVersion.ODW.DropFolder -Credential $credential -Version $majorVersion.Split('.')[0]
            }
            if ($installRoPE -eq $true){
                $RoPEVersion = Get-LatestSoftwareVersion -DropFolder $cfgVersion.RoPE.DropFolder -Credential $credential -Version $majorVersion.Split('.')[0]
            }
            if ($installOPS -eq $true){
                $OPSVersion = Get-LatestSoftwareVersion -DropFolder $cfgVersion.OPS.DropFolder -Credential $credential -Version $majorVersion.Split('.')[0]
            }

            Show-Info -IsCI $IsCI -Message "Downloading installation files from drop folders" -ForegroundColor Yellow
            #Use copy function
            $r = Copy-UpgradeFiles -Credential $credential -TempPath $tempPath -ESVersion $ESVersion -OPSVersion $OPSVersion -ODWVersion $ODWVersion -RoPEVersion $RoPEVersion -ESDropFolder $cfgVersion.ES.DropFolder `
                -OPSDropFolder $cfgVersion.OPS.DropFolder -ODWDropFolder $cfgVersion.ODW.DropFolder -RoPEDropFolder $cfgVersion.RoPE.DropFolder -CopyES $installES `
                -CopyRoPE $installRoPE -CopyODW $installODW -CopyOPS $installOPS -IsCI $IsCI -esExe $esExe -odwExe $ODWexe -ropeExe $RoPEexe -opsExe $OPSexe
            if ($r){
                Show-Info -IsCI $IsCI -Message "Files copied" -ForegroundColor Green
            }
            else{
                Show-Info -IsCI $IsCI -Message "Some problem occured with connection to network share" -ForegroundColor Red
                break
            }


        }
        elseif ($cfgVersionType -eq "Specific"){
            Show-Info -IsCI $IsCI -Message "Specific versions of OIS will be installed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "Credentials for network share are required" -ForegroundColor Yellow
				if ($null -eq $credMaster){
					$credential = Get-Credential -Message "Please provide user and password to download installation packages" -ErrorAction Stop
				}
				else{
					$credential = $credMaster
				}
            Show-Info -IsCI $IsCI -Message "Credentials provided" -ForegroundColor Yellow
            $r = Copy-UpgradeFiles -Credential $credential -TempPath $tempPath -ESVersion $cfgVersion.ES.Version -OPSVersion $cfgVersion.OPS.Version  `
                -ODWVersion $cfgVersion.ODW.Version -RoPEVersion $cfgVersion.RoPE.Version `
                -ESDropFolder $cfgVersion.ES.DropFolder -OPSDropFolder $cfgVersion.OPS.DropFolder -ODWDropFolder $cfgVersion.ODW.DropFolder  `
                -RoPEDropFolder $cfgVersion.RoPE.DropFolder -CopyES $installES `
                -CopyRoPE $installRoPE -CopyODW $installODW -CopyOPS $installOPS  -IsCI $IsCI `
                -esExe $esExe -odwExe $odwExe -opsExe $opsExe -ropeExe $RoPEexe
            if ($r){
                Show-Info -IsCI $IsCI -Message "Files copied" -ForegroundColor Green
            }
            else{
                Show-Info -IsCI $IsCI -Message "Some problem occured with connection to network share" -ForegroundColor Red
                break
            }

        }
        elseif ($cfgVersionType -eq "LocalCopy"){
            Show-Info -IsCI $IsCI -Message "Installation files from local path will be installed" -ForegroundColor Green
        }
        else{
            Show-Info -IsCI $IsCI -Message "Unknown software version in configuration file" -ForegroundColor Red
            break
        }

        #check if installation files are provided
        if ($installES -eq $true){
            $t = Get-ChildItem -Path $tempPath -recurse -filter $esExe -File
            if ($null -eq $t){
                Show-Info -IsCI $IsCI -Message "Installer for Enterprise Server not found" -ForegroundColor Red
                break
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Installer for Enterprise Server found: {0}" -f $t.FullName) -ForegroundColor Yellow
            }
            $esinstallerPath = $t.Directory.FullName
            $installerPath = (Join-Path -path $esInstallerPath -ChildPath $esExe)
            $installerVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[0] + '.' + [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[1]
			if ($installerVersion -eq $majorVersion -and $installerVersion -eq $moduleVersion){
				Show-Info -IsCI $IsCI -Message "OISIT version, configuration file version and ES installer version are the same" -ForegroundColor Green
			}
			else{
				Show-Info -IsCI $IsCI -Message ("OISIT version ({0}), configuration file version ({1}) and ES installer version ({2}) are not the same - error" -f $moduleVersion, $majorVersion, $installerVersion) -ForegroundColor Red
				break
			}
         }
         if ($installODW -eq $true){
            $t = Get-ChildItem -Path $tempPath -recurse -filter $odwExe -File
            if ($null -eq $t){
                Show-Info -IsCI $IsCI -Message "Installer for Omada Data Warehouse not found" -ForegroundColor Red
                break
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Installer for Omada Data Warehouse found: {0}" -f $t.FullName) -ForegroundColor Yellow
            }
            $odwinstallerPath = $t.Directory.FullName
            $installerPath = (Join-Path -path $odwInstallerPath -ChildPath $ODWexe)
            $installerVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[0] + '.' + [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[1]
			if ($installerVersion -eq $majorVersion -and $installerVersion -eq $moduleVersion){
				Show-Info -IsCI $IsCI -Message "OISIT version, configuration file version and ODW installer version are the same" -ForegroundColor Green
			}
			else{
				Show-Info -IsCI $IsCI -Message ("OISIT version ({0}), configuration file version ({1}) and ODW installer version ({2}) are not the same - error" -f $moduleVersion, $majorVersion, $installerVersion) -ForegroundColor Red
				break
			}
         }
         if ($installRoPE -eq $true){
            $t = Get-ChildItem -Path $tempPath -recurse -filter $ropeExe -File
            if ($null -eq $t){
                Show-Info -IsCI $IsCI -Message "Installer for Role and Policy Engine not found" -ForegroundColor Red
                break
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Installer for Role and Policy Engine found: {0}" -f $t.FullName) -ForegroundColor Yellow
            }
            $ropeinstallerPath = $t.Directory.FullName
            $installerPath = (Join-Path -path $ropeInstallerPath -ChildPath $RoPEexe)
            $installerVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[0] + '.' + [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[1]
            if ($installerVersion -eq $majorVersion -and $installerVersion -eq $moduleVersion){
				Show-Info -IsCI $IsCI -Message "OISIT version, configuration file version and RoPE installer version are the same" -ForegroundColor Green
			}
			else{
				Show-Info -IsCI $IsCI -Message ("OISIT version ({0}), configuration file version ({1}) and RoPE installer version ({2}) are not the same - error" -f $moduleVersion, $majorVersion, $installerVersion) -ForegroundColor Red
				break
			}
         }
         if ($installOPS -eq $true){
            $t = Get-ChildItem -Path $tempPath -recurse -filter $opsExe -File
            if ($null -eq $t){
                Show-Info -IsCI $IsCI -Message "Installer for Omada Provisioning Service not found" -ForegroundColor Red
                break
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Installer for Omada Provisioning Service found: {0}" -f $t.FullName) -ForegroundColor Yellow
            }
            $opsinstallerPath = $t.Directory.FullName
            $installerPath = (Join-Path -path $opsInstallerPath -ChildPath $OPSexe)
            $installerVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[0] + '.' + [System.Diagnostics.FileVersionInfo]::GetVersionInfo($installerPath).FileVersion.Split(".")[1]
            if ($installerVersion -eq $majorVersion -and $installerVersion -eq $moduleVersion){
				Show-Info -IsCI $IsCI -Message "OISIT version, configuration file version and OPS installer version are the same" -ForegroundColor Green
			}
			else{
				Show-Info -IsCI $IsCI -Message ("OISIT version ({0}), configuration file version ({1}) and OPS installer version ({2}) are not the same - error" -f $moduleVersion, $majorVersion, $installerVersion) -ForegroundColor Red
				break
			}
        }
        if ((Test-Path -Path $logPath) -eq $false){
            Show-Info -IsCI $IsCI -Message "Folder for logs is missing, creating" -ForegroundColor Yellow
			$t =New-Item -ItemType Directory -Path $logPath
        }


        Show-Info -IsCI $IsCI -Message "Installation files prepared" -ForegroundColor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }

    Show-Info -IsCI $IsCI -Message "1.2. Preparation of connection string" -ForegroundColor DarkGreen
    try{

        if ($MSSQLSecurity.Enabled -eq $true){
            Show-Info -IsCI $IsCI -Message "Integrated security will be used" -ForegroundColor Yellow
            $ConnectionString += "Integrated Security=SSPI;"
        }
        else{
            Show-Info -IsCI $IsCI -Message "Integrated security will NOT be used" -ForegroundColor Yellow
            $ConnectionString += ("User ID={0};Password={1};" -F $MSSQLSecurity.User, $MSSQLSecurity.Password)
        }

        $t = Push-ConnStringToRegistry -Action "Write" -MajorVersion $majorVersion -ConnectionString $ConnectionString -IsCI $IsCI

        Show-Info -IsCI $IsCI -Message "Connection string prepared" -ForegroundColor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "12" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }

    Show-Info -IsCI $IsCI -Message "1.3. Checking Enterprise Server prerequisites" -ForegroundColor DarkGreen
    if ($installES -or $isFullInstall){
	    if ($updateHostsFile){
		    try{
			    $ScriptBlock = {
				    $esBinding = $args[0]
				    $esip = $args[1]
				    $hostsfilename = "C:\Windows\System32\drivers\etc\hosts"
				    $c = Get-Content -Encoding UTF8 $hostsfilename
				    $t = ($c -match $esBinding)
				    if ($t.Length -eq 0){
					    Show-Info -IsCI $IsCI -Message "Binding in hosts file is missing, adding" -ForegroundColor Yellow
					    $l = ("
					    {1}          {0}" -F $esBinding, $esip)
					    Add-Content $hostsfilename $l
				    }
			    }

			    Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $esBinding, $esip
			    if ($SSISInstance -ne "localhost" -and !$SSISInstance.startswith($env:ComputerName)){
				    Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $esBinding, $esip
			    }
		    }
		    catch{
			    Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "13" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
			    break
		    }
	    }
	    Show-Info -IsCI $IsCI -Message "Adding required groups to AD" -ForegroundColor Yellow
	    try{


		    try{
			    $t = Get-ADGroup -Identity $ODWAdminsGroup
		    }
		    catch{
			    try{
				    $t = New-ADGroup -Name $ODWAdminsGroup -GroupScope "Global"
			    }
			    catch{
				    Show-Info -IsCI $IsCI -Message ("AD group {0} was not created, this is not a critical error - reports may not work correctly, continuing installation..." -F $ODWAdminsGroup) -ForegroundColor Red
			    }
		    }
		    try{
			    $t = Get-ADGroup -Identity $ODWAuditorsGroup
		    }
		    catch{
			    try{
				    $t = New-ADGroup -Name $ODWAuditorsGroup -GroupScope "Global"
			    }
			    catch{
				    Show-Info -IsCI $IsCI -Message ("AD group {0} was not created, this is not a critical error - reports may not work correctly, continuing installation..." -F $ODWAuditorsGroup) -ForegroundColor Red
			    }
		    }
		    try{
			    $t = Get-ADGroup -Identity $ODWUsersGroup
		    }
		    catch{
			    try{
				    $t = New-ADGroup -Name $ODWUsersGroup -GroupScope "Global"
			    }
			    catch{
				    Show-Info -IsCI $IsCI -Message ("AD group {0} was not created, this is not a critical error - reports may not work correctly, continuing installation..." -F $ODWUsersGroup) -ForegroundColor Red
			    }
		    }

		    try{

				#getting domain users group
			    $users = (Get-ADGroup -Filter '*' | Where-Object {$_.SID -like "S-1-5-21-*-513"}).sid.value
				$t2 = Get-ADObject -Filter "objectSid -eq '$users'"
			    $ODWGroup = Get-ADGroup -Identity $ODWUsersGroup
				Add-ADGroupMember -Identity $ODWGroup -Members $t2
				Show-Info -IsCI $IsCI -Message ("Adding 'Domain Users' as a member of '{0}'" -F $ODWUsersGroup) -ForegroundColor Yellow
				<#
				$ADmembers = Get-ADGroupMember -Identity $ODWUsersGroup -Recursive | Select -ExpandProperty Name
			    If ($ADmembers -contains $t) {
				    Show-Info -IsCI $IsCI -Message ("{0} is already a member of {1}" -F $t,$ADmembers) -ForegroundColor Green
			    }
			    Else {
				    Show-Info -IsCI $IsCI -Message ("{0} is not a member of {1}, adding..." -F $t,$ADmembers) -ForegroundColor Yellow
				    Add-ADGroupMember -Identity $ODWUsersGroup -Member $t
			    }#>
		    }
		    catch{
				Show-Info -IsCI $IsCI -Message "Adding failed, skipping" -ForegroundColor Yellow
			}


            if ($SSISInstance -ne 'localhost' -and !$SSISInstance.startswith($env:ComputerName)){
                $ScriptBlock = {
                    $SSISInstance = $args[0]
                    $domain = $args[1]
                    $user = $args[2]
                    try{
                        $c = ("WinNT://{0}/administrators,group" -F $SSISInstance)
                        $group = [ADSI]$c
                        $c = ("WinNT://{0}/{1},user" -F $domain, $user)
                        $group.Add($c)
                    }
                    catch{
						Write-Host ("Adding on {0} failed, skipping" -f $SSISInstance) -ForegroundColor Yellow
					}
                }
                Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $SSISInstance, $serviceUserDomain, $serviceUser
            }

        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "1.3" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        Show-Info -IsCI $IsCI -Message "Checking registry if SSRS is installed" -ForegroundColor Yellow
        try{
            $changeimport = Get-Process ReportServer -ErrorAction SilentlyContinue
            if ($changeimport) {
                Show-Info -IsCI $IsCI -Message "Reporting Server is installed on this machine, no updates in registry needed." -ForegroundColor Yellow
            }
            else{
            #if SSRS is not installed on local machines, some fake registry values have to be provided in order to properly install ODW
                Show-Info -IsCI $IsCI -Message "Adding registry values in order to create proper ODW configuration" -ForegroundColor Yellow
                $p = ("{0}\SSRS.reg" -F $tempPath)
                if ((Test-Path -Path $p) -eq $true){
			        Remove-Item $p -Force -ErrorAction SilentlyContinue
                    $t = New-Item -ItemType file -Path $p -ErrorAction SilentlyContinue
		        }

                $c = 'Windows Registry Editor Version 5.00

                [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReportServer]
    "ImagePath"=hex(2):22,00,43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,\
      6d,00,20,00,46,00,69,00,6c,00,65,00,73,00,5c,00,4d,00,69,00,63,00,72,00,6f,\
      00,73,00,6f,00,66,00,74,00,20,00,53,00,51,00,4c,00,20,00,53,00,65,00,72,00,\
      76,00,65,00,72,00,5c,00,4d,00,53,00,52,00,53,00,31,00,31,00,2e,00,4d,00,53,\
      00,53,00,51,00,4c,00,53,00,45,00,52,00,56,00,45,00,52,00,5c,00,52,00,65,00,\
      70,00,6f,00,72,00,74,00,69,00,6e,00,67,00,20,00,53,00,65,00,72,00,76,00,69,\
      00,63,00,65,00,73,00,5c,00,52,00,65,00,70,00,6f,00,72,00,74,00,53,00,65,00,\
      72,00,76,00,65,00,72,00,5c,00,62,00,69,00,6e,00,5c,00,52,00,65,00,70,00,6f,\
      00,72,00,74,00,69,00,6e,00,67,00,53,00,65,00,72,00,76,00,69,00,63,00,65,00,\
      73,00,53,00,65,00,72,00,76,00,69,00,63,00,65,00,2e,00,65,00,78,00,65,00,22,\
      00,00,00'

                if ((Test-Path -Path $p) -eq $false){
                    $t = New-Item -ItemType file -Path $p
                }
                $t = Set-Content -Path $p -Value $c
                $t = regedit /s $p

                if ((Test-Path -Path $p) -eq $true){
			        Remove-Item $p -Force  -ErrorAction SilentlyContinue
                    $t = New-Item -ItemType file -Path $p -ErrorAction SilentlyContinue
		        }

                $c = ('Windows Registry Editor Version 5.00

    [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsDtsServer{0}0]
    "ImagePath"=hex(2):22,00,43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,\
      6d,00,20,00,46,00,69,00,6c,00,65,00,73,00,5c,00,4d,00,69,00,63,00,72,00,6f,\
      00,73,00,6f,00,66,00,74,00,20,00,53,00,51,00,4c,00,20,00,53,00,65,00,72,00,\
      76,00,65,00,72,00,5c,00,31,00,33,00,30,00,5c,00,44,00,54,00,53,00,5c,00,42,\
      00,69,00,6e,00,6e,00,5c,00,4d,00,73,00,44,00,74,00,73,00,53,00,72,00,76,00,\
      72,00,2e,00,65,00,78,00,65,00,22,00,00,00' -F $SQLVersionNo)
                $t = Set-Content -Path $p -Value $c
                $t = regedit /s $p
            }

		    if ((Test-Path -Path $p) -eq $true){
			    Remove-Item $p -Force -ErrorAction SilentlyContinue
		    }
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "13" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
    }

	Show-Info -IsCI $IsCI -Message "Installing windows features - if needed" -ForegroundColor Yellow
    try{
		if ($osVersion -eq "10"){
			Show-Info -IsCI $IsCI -Message "Windows Server 2016 or later detected" -ForegroundColor Green
			$t= Add-WindowsFeature -Name NET-Framework-Features
			$t= Add-WindowsFeature -Name Web-Static-Content
		}
		else{
			Show-Info -IsCI $IsCI -Message "Windows Server 2012R2 or ealier detected" -ForegroundColor Green
			$t= Add-WindowsFeature -Name AS-NET-Framework
			$t= Add-WindowsFeature -Name AS-Web-Support
        }
		$t= Add-WindowsFeature -Name NET-Framework-45-ASPNET
		$t= Add-WindowsFeature -Name Web-Net-Ext45
		$t= Add-WindowsFeature -Name Web-Mgmt-Tools
		$t= Add-WindowsFeature -Name Web-Asp-Net45
		$t= Add-WindowsFeature -Name Web-Basic-Auth
		$t= Add-WindowsFeature -Name Web-Windows-Auth

		Show-Info -IsCI $IsCI -Message "Windows features installed" -ForegroundColor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

		Show-Info -IsCI $IsCI -Message "Updating registry for correct web site authentication" -ForegroundColor Yellow
		$t = New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
		if ((Test-Path "HKCR:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\BackConnectionHostNames") -eq $true){
            Show-Info -IsCI $IsCI -Message "No need to update registry, skipping" -ForegroundColor Green
        }
		else{
			try{
				$t = @(
				$esBinding,
				$env:computername
				)
				$x = New-ItemProperty -Path "HKCR:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -PropertyType MultiString -Name "BackConnectionHostNames" -Value $t
				Restart-Service -ServiceName "IISADMIN" -Action "Restart"
				Show-Info -IsCI $IsCI -Message "Added value to registry" -ForegroundColor Green
			}
			catch{
				Show-Info -IsCI $IsCI -Message "No need to update registry, skipping" -ForegroundColor Green
			}
		}
		$t = Remove-PSDrive -Name HKCR
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "13" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }
    Show-Info -IsCI $IsCI -Message "1.4. Removal of old log files" -ForegroundColor DarkGreen
    try{
         Show-Info -IsCI $IsCI -Message "As this is a installation from a local copy, then there may be some leftovers from previous installations..." -ForegroundColor Yellow
         Get-ChildItem $logPath -include *.log -recurse | ForEach-Object ($_) {remove-item $_.fullname}

         if ($SSISInstance -ne "localhost" -and !$SSISInstance.startswith($env:ComputerName)){
            Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock{
                If ((Test-Path -Path $args[0]) -eq $true){
                    Get-ChildItem $args[0] -include *.log -recurse | ForEach-Object ($_) {remove-item $_.fullname}
                }else{
                    New-Item -Path $args[0] -ItemType Directory | Out-Null
                }

            } -ArgumentList $logPath
         }

         Show-Info -IsCI $IsCI -Message "Old log files removed" -ForegroundColor Green
         Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "14" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI

    }

    Show-Info -IsCI $IsCI -Message "1.5. Configuration of separate DB\SSIS server, if required" -ForegroundColor DarkGreen
    try{
        if ($remoteDB -eq $false){
            Show-Info -IsCI $IsCI -Message "DB server is the same as APP server, skipping" -ForegroundColor Green
        }
		elseif ($isFullInstall -eq $false){
		    Show-Info -IsCI $IsCI -Message "This is a component oriented installation, skipping" -ForegroundColor Green
		}
        else{
        #as ODW has to be installed on SSIS server, not on DB server
            Show-Info -IsCI $IsCI -Message "Copying installation files to DB\SSIS server(s)" -ForegroundColor Yellow
            Copy-FilesToRemoteServers  -SSISInstance $SSISInstance -SQLInstanceWithout $SQLInstanceWithout -credDB $credDB -tempPath $tempPath -logPath $LogPath -scriptsPath $PSScriptRoot

            Show-Info -IsCI $IsCI -Message "Files copied" -ForegroundColor Green
        }
         Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "15" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break;
    }

    try{
        if ($SSISInstance -eq $SQLInstanceWithout){
            Show-Info -IsCI $IsCI -Message "SSIS is the same as DB server, no additional configuration required, skipping" -ForegroundColor Green
        }
        else{
            $ScriptBlock = {
                $version = $args[0]
                $sqlServer = $args[1]
                if ($args[2].IndexOf('Binn') -gt 0){
					$dtexecDir = ("{0}" -F $args[2])
				}
				else{
					$dtexecDir = ("{0}\Binn" -F $args[2])
				}
				$restart = $false

                #$path = ('C:\Program Files\Microsoft SQL Server\{0}0\DTS\Binn' -F $version)
                $XmlFile = (Join-Path -Path $dtexecDir -ChildPath 'MsDtsSrvr.ini.xml')

                [xml]$ini = Get-Content -Encoding UTF8 $XmlFile
                $ini.SelectNodes("/DtsServiceConfiguration/TopLevelFolders/Folder") | Where-Object {$_.ServerName} | ForEach-Object {
                    if ($_.ServerName -ne $sqlServer){
                        $_.ServerName = $sqlServer
                        #$restart = $true
                    }
                } #/ServerName
                if ($restart){
                    $ini.Save($XmlFile)
                    Restart-Service -Name ("MsDtsServer{0}0" -f $version) -Force
                }
                else{
                    Write-Host "No need to restart Integration service" -ForegroundColor Yellow
                }


                Write-Host "SSIS server configuration changed" -ForegroundColor Green
            }
            Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $SQLVersionNo, $SQLInstance, $dtexecDir

        }
        Show-Info -IsCI $IsCI -Message "SSIS server updated" -ForegroundColor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "15" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }

    if ($isFullInstall){
        Show-Info -IsCI $IsCI -Message "1.6. Preparation of service user" -ForegroundColor DarkGreen
        try{

            #ADD different users for fidderent products
            New-LocalUser -UserName $serviceUser -Password $serviceUserPassword -Description $serviceUserDescription -Type "Service" -OverridePolicy $true -FullDomain $serviceUserFullDomain -logPath $logPath -tempPath $tempPath -SQLInstance $SSISInstance -CredDB $credDB -domain $serviceUserDomain -SSISInstance $SQLInstanceWithout -IsCI $IsCI
            Show-Info -IsCI $IsCI -Message "Service user created" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
		$_.InvocationInfo
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "16" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
    }

    #Show-Info -IsCI $IsCI -Message "2. Enterprise Server installation" -ForegroundColor DarkGreen


    if ($installES -eq $true){
        try{
            Show-Info -IsCI $IsCI -Message "2.1 Enterprise Server installation" -ForegroundColor DarkGreen
            $args = ("/l*v \""{0}\installlog_es.log\""" -F $logPath)
            $args +=  " SERVICETYPE=\""2\"""
            $args +=  " SERVICEDOMAIN=\""$serviceUserDomain\"""
            $args +=  " SERVICEUSER=\""$serviceUser\"""
            $args +=  " SERVICEPASSWORD=\""$serviceUserPassword\"""
            $args +=  " INSTALLDIR=\""$esInstallationPath\"""
            $args +=  " ADDLOCAL=\""$esFeaturesToInstall\"""

            $t = Start-Process -Wait -WorkingDirectory $esInstallerPath -FilePath $esExe -ArgumentList " /V""$args /qn"" " -PassThru -WindowStyle Hidden

			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_es.log" -f $esName, $logPath) -ForegroundColor Red
				break
			}



            Show-Info -IsCI $IsCI -Message "Copying changesets to import..." -ForegroundColor Yellow
            if ($copyChangesets -eq $true){
				if (!(Test-Path -Path $changesetPath)){
					$t = New-Item -ItemType directory -Path $changesetPath

				}
                $changesets = $xmlcfg.SelectNodes("/Configuration/Version/ES/Changesets")
                $changesetPath = $xmlcfg.SelectNodes("/Configuration/Version/ES").ChangesetsPath
                $changesetsCustomer = $cfgVersion.ES.ChangesetsCustomer

                #copying suggestedpackages
				if ($installChangesets -eq $true){

					$i = 0
					$changesetsAll = $changesets.ChangeSet
					if ($changesetsAll.ChildNodes.Count -gt 0){
						foreach ($node in $changesetsAll) {

							Show-Info -IsCI $IsCI -Message ("Copying {1} to {0}" -F $esInstallationPath, $node.Name) -ForegroundColor Yellow
							Copy-Item -Path (Join-Path -Path $changesetPath -ChildPath ($node.Name)) -Destination ($esInstallationPath + "\" + $node.Name) -Force
							$i++
						}
					}
					else{
						Show-Info -IsCI $IsCI -Message "No changesets to copy" -ForegroundColor Yellow
					}
				}
				else{
					Show-Info -IsCI $IsCI -Message "Changesets are disabled, copy is not required" -ForegroundColor Yellow
				}
            }
            else{
                Show-Info -IsCI $IsCI -Message "Changesets do not require to be copied to local path." -ForegroundColor Green
            }

            Show-Info -IsCI $IsCI -Message "Enterprise Server installed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "21" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        Show-Info -IsCI $IsCI -Message "2.2 Adding additional tools for Enterprise Server" -ForegroundColor DarkGreen
        try{
            if ($installSQLSysClrTypes2012 -eq $true){
                Show-Info -IsCI $IsCI -Message "Installing SQLSysClrTypes2012..." -foregroundcolor yellow
                if ((Test-Path(Join-Path -Path $esInstallationPath -ChildPath "support files\SQLSysClrTypes2012.msi")) -eq $true){
                    $args = "/i SQLSysClrTypes2012.msi /q";
                    $t = Start-Process -Wait -WorkingDirectory (Join-Path -Path $esInstallationPath -ChildPath "support files") -FilePath "msiexec" -ArgumentList "$args" -PassThru
                    Show-Info -IsCI $IsCI -Message "SQLSysClrTypes2012 installed" -foregroundcolor Green
                }
                else{
                    Show-Info -IsCI $IsCI -Message "File SQLSysClrTypes2012.msi is missing, skipping" -ForegroundColor Magenta
                }
            }
            else{
                Show-Info -IsCI $IsCI -Message "Skipping installation of SQLSysClrTypes2012" -ForegroundColor Yellow
            }

            if ($installReportViewer2012 -eq $true){
                Show-Info -IsCI $IsCI -Message "Installing ReportViewer2012..." -foregroundcolor yellow
                if ((Test-Path(Join-Path -Path $esInstallationPath -ChildPath "support files\ReportViewer2012.msi")) -eq $true){
                    $args = "/i ReportViewer2012.msi /q";
                    $t = Start-Process -Wait -WorkingDirectory (Join-Path -Path $esInstallationPath -ChildPath "support files") -FilePath "msiexec" -ArgumentList "$args" -PassThru
                    Show-Info -IsCI $IsCI -Message "ReportViewer2012 installed" -foregroundcolor Green
                }
                else{
                    Show-Info -IsCI $IsCI -Message "File ReportViewer2012.msi is missing, skipping" -ForegroundColor Magenta
                }
            }
            else{
                Show-Info -IsCI $IsCI -Message "Skipping installation of ReportViewer2012" -ForegroundColor Yellow
            }

            Show-Info -IsCI $IsCI -Message "Finished installing additional tools" -foregroundcolor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "22" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        Show-Info -IsCI $IsCI -Message "2.3 Enterprise Server initial configuration" -ForegroundColor DarkGreen

        try{
            Show-Info -IsCI $IsCI -Message ("Creating DB {0}..." -F $esDBName) -ForegroundColor Yellow
            #Show-Info -IsCI $IsCI -Message ("main script: Use SQL user: {0} {1}" -F $useSQLUser, $SQLAdmUser)
            Create-Database -User $SQLAdmUser -Password $SQLAdmPass -Instance $SQLInstance -DBName $esDBName -SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

            Show-Info -IsCI $IsCI -Message "Creating Source System Data DB..." -ForegroundColor Yellow
            Create-Database -User $SQLAdmUser -Password $SQLAdmPass -Instance $SQLInstance -DBName $esSourceSystemDBName -SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

            Show-Info -IsCI $IsCI -Message "Creating Audit DB..." -ForegroundColor Yellow
            Create-Database -User $SQLAdmUser -Password $SQLAdmPass -Instance $SQLInstance -DBName $esAuditDBName -SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

            Show-Info -IsCI $IsCI -Message "Running initial SQL scripts..." -ForegroundColor Yellow
            $initialScripts = $xmlcfg.SelectNodes("/Configuration/Version/ES/DBInitialScripts")
            $i = 0
            if ($enableCustomization -eq $true){
                Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
                $nodes = $initialScripts.ChildNodes | Where-Object { $_.Step -eq "2.2.1" -or $_.Step -eq "2.2.2"}
            }
            else{
                $nodes = $initialScripts.ChildNodes | Where-Object { $_.Step -eq "2.2.1"}
            }

            foreach($node in $nodes){
                $sqlFile = $node.ScriptPath
                $sqlDB = $node.DBName
                if ($sqlFile.Length -gt 0){
                    Show-Info -IsCI $IsCI -Message ("Running {0} of {1} script(s) in {3}: {2}" -F ($i + 1),$nodes.Count, $sqlFile, $sqlDB) -ForegroundColor Yellow
                    if ((Test-Path $sqlFile) -eq $true){
						$c = Get-Content -Encoding UTF8 -path $sqlFile -Raw
						$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
                        if ($useSQLUser){
                            Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $sqlDB -QueryTimeout 300 -query $c #-inputfile $sqlFile
                        }
                        else{
                            Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $sqlDB -QueryTimeout 300 -query $c #-inputfile $sqlFile
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
                $i++
            }


            Show-Info -IsCI $IsCI -Message "Addtional updates in DB" -ForegroundColor Yellow
			$t = ''
			if ($esThumbprint.Length -gt 0){
			$t = 's'
			}
			$c = ("UPDATE tblCustomerSetting SET ValueStr='942e8812-bf35-45b2-8a19-2bd27ab801a3' WHERE [Key]='RoPEAccessGrps';
					UPDATE tblCustomerSetting set ValueStr='http{1}://{0}/' where [Key]='WebSiteUrl';
					INSERT INTO [dbo].[tblCustomerSetting] ([Key],[Name],[Description],[ValueStr],[ValueInt],[ValueDateTime],[ValueBool],[Type],[Category])
                    VALUES('ColSearchLeftWldCrd','UseLeftWildcardInColumnSearch','UseLeftWildcardInColumnSearch',null,null,null,1,2,'User Interface');
			" -f $esBinding, $t)
            if ($useSQLUser){
                Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
            }
            else{
                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
            }

            #task 65032 - ES service needs to be started to create additional columns in tblCustomer
            Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Start"
            Show-Info -IsCI $IsCI -Message "Generating additional columns in tblCustomer..." -ForegroundColor Yellow
            Start-Sleep -s 10

            $c = "Update dbo.tblCustomerAuth SET AuthenticationType = 'Integrated' WHERE CustomerID = 1000;"
            if ($useSQLUser){
                Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
            }
            else{
                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
            }
            Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Stop"
            #end task 65032

            if ($restoreESDB -eq $true){
               Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $esDBName) -ForegroundColor Yellow
               $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($esDBName + ".bak")
               Restore-OmadaDatabaseTask -DBName $esDBName -BackupPath $dbBackupPath -IsCI $IsCI
               Add-UserToDatabase -DBLogin $esDBUser -Instance $SQLInstance -DBName $esDBName -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -IsCI $IsCI
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $esDBName) -ForegroundColor Yellow
            }
            if ($restoreSourceSystemDB -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $esSourceSystemDBName) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($esSourceSystemDBName + ".bak")
                Restore-OmadaDatabaseTask -DBName $esSourceSystemDBName -BackupPath $dbBackupPath -IsCI $IsCI
                Add-UserToDatabase -DBLogin $esDBUser -Instance $SQLInstance -DBName $esSourceSystemDBName -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $esSourceSystemDBName) -ForegroundColor Yellow
            }
            if ($restoreAuditDB -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $esAuditDBName) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($esAuditDBName + ".bak")
                Restore-OmadaDatabaseTask -DBName $esAuditDBName -BackupPath $dbBackupPath -IsCI $IsCI
                Add-UserToDatabase -DBLogin $esDBUser -Instance $SQLInstance -DBName $esAuditDBName -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
            }
            else{
                 Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $esAuditDBName) -ForegroundColor Yellow
            }

            Show-Info -IsCI $IsCI -Message "Adding licence..." -ForegroundColor Yellow
            Add-Licence -DBInstance $SQLInstance -DBName $esDBName -LicenseKey $cfgVersion.OIS.LicenseKey -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI

            Show-Info -IsCI $IsCI -Message "Enterprise Server configured" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "23" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
        Show-Info -IsCI $IsCI -Message "2.4 Creating a web site for Enterprise Server" -ForegroundColor DarkGreen
        try{

			#Override to change default administrator user

			#$c = ("Update tblUser set UserName=UPPER('{0}') where UserName='ADMINISTRATOR'" -F $administratorUser)
			$c = ("Update tblUser set UserName=UPPER('{0}') where UserName='ADMINISTRATOR'" -F $env:USERNAME)
			if ($useSQLUser){
                invoke-sqlcmd -ServerInstance $SQLInstance -User $SQLAdmUser -Password $SQLAdmPass -query $c -database $esDBName
            }
            else
            {
                invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database $esDBName
            }

            $esWebSitePath = (Join-Path -Path $esInstallationPath -ChildPath "website")
            $u = ("{0}\{1}" -F $serviceUserDomain, $serviceUser)
            $t = New-OISWebSite -IISAppPoolName $esAppPool -IISWebSite $esWebSite -AppPool $true -WebSitePath $esWebSitePath -WebSiteBinding $esBinding -Firewall $true -AppPoolUser $u -AppPoolUserPassword $serviceUserPassword -CertThumbprint $esThumbprint -IsCI $IsCI -isDemo $demoEnabled -isTA $demoTA

            Show-Info -IsCI $IsCI -Message "Starting a web site..." -ForegroundColor Yellow

            Try{
                $t = Invoke-WebRequest -URI "http://$esBinding" -TimeoutSec 180 -UseDefaultCredentials
            }
            Catch {
                Show-Info -IsCI $IsCI -Message "Calling web site failed. This is not critical error, installation is not aborted." -ForegroundColor Red
            }

                $ScriptBlock = {

                    $esBinding = $args[0]
                    $esIp = $args[1]
					$report = $args[2]

					if ($updateHostsFile){
						$hostsfilename = "C:\Windows\System32\drivers\etc\hosts"
						$c = Get-Content -Encoding UTF8 $hostsfilename
						$t = ($c -match $esBinding)
						if ($t.Length -eq 0){
							if($report){
								Show-Info -IsCI $IsCI -Message "Binding in hosts file is missing, adding" -ForegroundColor Yellow
							}
						    $l = ("
						       {1}          {0}" -F $esBinding, $esIp)
						    Add-Content $hostsfilename $l
						}
					}
					if($report){
						 Show-Info -IsCI $IsCI -Message ("Adding {0} as a home page" -F $esBinding) -ForegroundColor Yellow
						}
                     $path = 'HKCU:\Software\Microsoft\Internet Explorer\Main\'
					 if(Test-Path -path $path){
						 $name = 'Start Page'
						 if ($esThumbprint.Length -gt 0){
							$value = ('https://{0}/' -F $esBinding)
						 }else{
							$value = ('http://{0}/' -F $esBinding)
						 }
						 Set-Itemproperty -Path $path -Name $name -Value $value
						 $name = 'Default_Page_URL'
						 if ($esThumbprint.Length -gt 0){
							$value = ('https://{0}/' -F $esBinding)
						 }else{
							$value = ('http://{0}/' -F $esBinding)
						 }
						 Set-Itemproperty -Path $path -Name $name -Value $value
						 if($report){
							Show-Info -IsCI $IsCI -Message "Home page updated" -ForegroundColor Green
						}
					}
					else{
						if($report){
							 Show-Info -IsCI $IsCI -Message "Home page not updated - registry key was not found" -ForegroundColor Yellow
						}
					}
					 if ($osVersion -ne "10"){#Disabling IE enhanced security with this registry changes doesn't work in Windows Server 2016
						if($report){
							Show-Info -IsCI $IsCI -Message "Disabling IE enhanced security" -ForegroundColor Yellow
						}
                    }
					$AdminKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}”
                    $UserKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}”
                    Set-ItemProperty -Path $AdminKey -Name “IsInstalled” -Value 0
                    Set-ItemProperty -Path $UserKey -Name “IsInstalled” -Value 0

					$t = Get-Process iExplore -ErrorAction SilentlyContinue
					if ($null -ne $t) {
						Stop-Process -Name iExplore -ErrorAction SilentlyContinue -Force
					}


					if($report){
    					Show-Info -IsCI $IsCI -Message "IE enhanced security disabled" -ForegroundColor Green
					}
                }

                Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $esBinding, $esip, $true
                if ($SSISInstance -ne 'localhost' -and !$SSISInstance.startswith($env:ComputerName)){
                    Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $SSISInstance -Credential $credDB -ArgumentList $esBinding, $ip, $false
                }



            Show-Info -IsCI $IsCI -Message "Finished creating a web site" -foregroundcolor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "24" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
        }
        Show-Info -IsCI $IsCI -Message "2.5 Creating proxy account in MS SQL" -ForegroundColor DarkGreen
        try{
            #create SQL credentials

            $c = "if not exists (select * from sys.credentials where name = N'$($serviceUserDomain)\$($serviceUser)')
            BEGIN
            CREATE CREDENTIAL [$($serviceUserDomain)\$($serviceUser)] WITH IDENTITY = N'$($serviceUserDomain)\$($serviceUser)', SECRET = N'$($serviceUserPassword)'
            END"

            if ($useSQLUser){
                invoke-sqlcmd -ServerInstance $SQLInstance -User $SQLAdmUser -Password $SQLAdmPass -query $c -database "master"
            }
            else
            {
                invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database "master"
            }


            #create SQL proxy user

            $c = "if not exists (SELECT name FROM sysproxies where name='$($serviceUserDomain)\$($serviceUser)')
                BEGIN
                EXEC msdb.dbo.sp_add_proxy @proxy_name=N'$($serviceUserDomain)\$($serviceUser)',@credential_name=N'$($serviceUserDomain)\$($serviceUser)', @enabled=1;
                EXEC msdb.dbo.sp_grant_proxy_to_subsystem @proxy_name=N'$($serviceUserDomain)\$($serviceUser)', @subsystem_id=3;
                EXEC msdb.dbo.sp_grant_proxy_to_subsystem @proxy_name=N'$($serviceUserDomain)\$($serviceUser)', @subsystem_id=9;
                EXEC msdb.dbo.sp_grant_proxy_to_subsystem @proxy_name=N'$($serviceUserDomain)\$($serviceUser)', @subsystem_id=10;
                EXEC msdb.dbo.sp_grant_proxy_to_subsystem @proxy_name=N'$($serviceUserDomain)\$($serviceUser)', @subsystem_id=11;
                EXEC msdb.dbo.sp_grant_proxy_to_subsystem @proxy_name=N'$($serviceUserDomain)\$($serviceUser)', @subsystem_id=12;
                EXEC msdb.dbo.sp_grant_login_to_proxy @proxy_name=N'$($serviceUserDomain)\$($serviceUser)', @login_name=N'$($serviceUserDomain)\$($serviceUser)';
                END;
                EXEC sp_addrolemember N'db_ssisadmin', [$($serviceUserDomain)\$($serviceUser)];
                "
            if ($useSQLUser){
                invoke-sqlcmd -ServerInstance $SQLInstance -U $SQLAdmUser -Password $SQLAdmPass -query $c -database "msdb"
            }
            else{
                invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database "msdb"
            }


            Show-Info -IsCI $IsCI -Message "Proxy account created" -foregroundcolor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "25" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
        Show-Info -IsCI $IsCI -Message "2.6 Applying changesets" -ForegroundColor DarkGreen
        try{
            if ($installChangesets -eq $true){

                Invoke-ChangeSet -Step "2.6" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
                Show-Info -IsCI $IsCI -Message "Finished applying changesets" -foregroundcolor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            else{
                Show-Info -IsCI $IsCI -Message "Changesets disabled, skipping" -ForegroundColor Yellow
            }
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "26" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
        #Bug 56358, required by OIS 14, windows integration security requires this setting
        #if ($demoEnabled -or $null -ne $demoType){
		#	Show-Info -IsCI $IsCI -Message "2.7 Demo installation, allowing http access to ES portal" -ForegroundColor DarkGreen
			try{
				#when using windows authentication
				$c = "Update tblMasterSetting Set ValueBool=0 where [Key]='SecureSessionCookie' or [Key]='OISXBasicAuth'"
				 if ($useSQLUser){
					Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
				}
				else{
					Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
				}
				#when using basic authentication
				#not used right now, some additional changes in OISIT required
				#$c = "Update tblMasterSetting Set ValueBool=0 where [Key]='SecureSessionCookie';Update tblMasterSetting Set ValueBool=1 where [Key]='OISXBasicAuth'"
				# if ($useSQLUser){
				#	Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
				#}
				#else{
				#	Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
				#}
				Show-Info -IsCI $IsCI -Message "Http access updated" -foregroundcolor Green
			}
			catch{
				Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "26" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
				break
			}
		#}

    }
    else{
        Show-Info -IsCI $IsCI -Message "2. Skipping Enterprise Server installation" -ForegroundColor DarkGreen
    }
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
                    $t = Invoke-Command -ScriptBlock {Restart-Service -ServiceName "MSDTC"}
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
            Show-Info -IsCI $IsCI -Message "3.2 Omada Data Warehouse installation" -ForegroundColor DarkGreen

            $a = ("/qn /l*v \""{0}\installlog_odw.log\""" -F $logPath)

            $a +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            if ($useSQLUser){
                $a +=  " IS_SQLSERVER_AUTHENTICATION=\""1\"""
            }
            else{
                $a +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            }
            $a +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""
            $a +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""

            $a +=  (" SSISSERVER=\""{0}\""" -F $SQLInstance) #$SSISInstance
            #installation on SSIS and the SSRS is not on that server - force installer to install reports
            if ($remoteDB -and ($SSISInstance -ne $SQLInstance)){
                $a += (" SSRSPath=\""{0}\""" -F (Join-Path -Path $PSScriptRoot -ChildPath 'Private\ODW\Omada.exe'))
            }
            $a += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $ODWProductDB)
            $a += (" ODWSTAGINGDB=\""{0}\""" -F $ODWProductDBStaging)
            $a += (" ODWMASTER=\""{0}\""" -F $ODWProductDBMaster)
            $a +=  " INSTALLDIR=\""$odwInstallationPath\"""
            #$a += " OISXCONN=\""$ConnectionString\"""#removed from installer from version rel 12.0.4
	        #$a += (" LICENSEKEY=\""{0}\""" -F $cfgVersion.OIS.LicenseKey) bug 46176,  workaround due to command line parameter length limitations - license is added after the installation

            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse installation starting..." -ForegroundColor Yellow
            $ScriptBlock = {

                $f = Join-Path -Path $args[0] -ChildPath $args[1]
                #(" /V""{0} /qn"" " -F $args[2])
                Start-Process -Wait -FilePath $f -ArgumentList (" /V""{0} /qn"" " -F $args[2]) -PassThru  | Out-Null #-WorkingDirectory $args[0]
				if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $args[3]} ) -or !(Test-Path -Path $args[5])){
					Write-Host -Message ("{0} was not installed. Please check installation on {2} log for details - {1}\installlog_odw.log" -f $args[3], $logPath, $args[4]) -ForegroundColor Red
					break
				}
            }

            if (!$remoteDB){
				Show-Info -IsCI $IsCI -Message "Installation on local machine" -ForegroundColor Yellow
                $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, "local machine", $odwInstallationPath
            }
            else{
                #ODW install on SSIS - in order to IS of OIS to work
				Show-Info -IsCI $IsCI -Message ("Installation on {0}" -F $SSISInstance) -ForegroundColor Yellow
                Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, $SSISInstance, $odwInstallationPath
            }
			#Add license key to ODW DB
            $q = ("Update tblApplicationSetting set ValueStr='{0}' where [Key]='licenseString'" -f $cfgVersion.OIS.LicenseKey)
            if ($useSQLUser){
                Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $ODWProductDB -Query $q -QueryTimeout 300
            }
            else{
                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $ODWProductDB -Query $q -QueryTimeout 300
            }
            if ($remoteDB -and $rsOnAppServer){
                Show-Info -IsCI $IsCI -Message ("Copying reports to {0}" -F $env:ComputerName) -ForegroundColor Yellow
                Copy-ReportDefinition -SSISInstance $SSISInstance -SQLInstance $SQLInstance -targetServer $env:ComputerName -odwInstallationPath $odwInstallationPath -credDB $credDB -scriptPath $PSScriptRoot -SSRSPath $ssrsPath -IsCI $IsCI
            }
            elseif ($remoteDB -and ($SSISInstance -ne $SQLInstance)){
                Show-Info -IsCI $IsCI -Message ("Copying reports to {0}" -F $SQLInstanceWithout) -ForegroundColor Yellow
                Copy-ReportDefinition -SSISInstance $SSISInstance -SQLInstance $SQLInstance -targetServer $SQLInstanceWithout -odwInstallationPath $odwInstallationPath -credDB $credDB -scriptPath $PSScriptRoot -SSRSPath $ssrsPath -IsCI $IsCI
            }

            if ($restoreODWProductDB -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $ODWProductDB) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($ODWProductDB + ".bak")
                Restore-OmadaDatabaseTask -DBName $ODWProductDB -BackupPath $dbBackupPath -IsCI $IsCI
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $ODWProductDB) -ForegroundColor Yellow
            }
            if ($restoreODWProductDBStaging -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $ODWProductDBStaging) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($ODWProductDBStaging + ".bak")
                Restore-OmadaDatabaseTask -DBName $ODWProductDBStaging -BackupPath $dbBackupPath -IsCI $IsCI
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $ODWProductDBStaging) -ForegroundColor Yellow
            }
            if ($restoreODWProductDBMaster -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $ODWProductDBMaster) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($ODWProductDBMaster + ".bak")
                Restore-OmadaDatabaseTask -DBName $ODWProductDBMaster -BackupPath $dbBackupPath -IsCI $IsCI
            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $ODWProductDBMaster) -ForegroundColor Yellow
            }


            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse installed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
                }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "32" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
        Show-Info -IsCI $IsCI -Message "3.3 Adding Omada Data Warehouse users" -ForegroundColor DarkGreen
        try{
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName $cfgVersion.ODW.ODWProductDatabase -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName $cfgVersion.ODW.ODWProductDatabaseStaging -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName $cfgVersion.ODW.ODWPRoductDatabaseMaster -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
			Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName "msdb" -Role "db_ssisadmin" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
			$q = ("sp_addrolemember 'db_datareader', '{0}\{1}' " -f $serviceUserDomain, $serviceUser)
			if ($useSQLUser){
                Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database "msdb" -Query $q -QueryTimeout 300 #-inputfile $sqlFile
            }
            else{
                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database "msdb" -Query $q -QueryTimeout 300 #-inputfile $sqlFile
            }
            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse users added" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "33" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
        try{
            Show-Info -IsCI $IsCI -Message "3.4 Changing dtsConfig configuration files" -ForegroundColor DarkGreen

            $dtsUpdates = $xmlcfg.SelectNodes("/Configuration/Version/ODW/DtsConfigUpdates")
            $nodes = $dtsUpdates.ChildNodes
            foreach($node in $nodes){
                        Show-Info -IsCI $IsCI -Message ("Updating attribute {0}" -F $node.ParentElementValue) -ForegroundColor Yellow
                        Update-XMLNode -XMLFile (Join-Path -Path $odwInstallationPath -ChildPath $node.File) -XMLParentNode $node.ParentNode -ParentElementValue $node.ParentElementValue `
                        -ParentElementKey $node.ParentElementKey -KeyAttribute $node.KeyAttribute -KeyValue $node.KeyValue -ComputerName $SSISInstance -Cred $credDB -IsCI $IsCI
                    }

            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse dtsConfig updated" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "34" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        Show-Info -IsCI $IsCI -Message "3.5 Omada Data Warehouse configuration" -ForegroundColor DarkGreen
        try{
            Show-Info -IsCI $IsCI -Message "Running configuration packages" -ForegroundColor Yellow
            $odwConfigurationPackages = $cfgVersion.ODW.ConfigurationPackages
            Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock {
				 $SQLVersionNo = $args[0]
				 $dtexecDir = $args[1]
				$t = ('sc.exe config MsDtsServer{0}0 binPath= "{1}MsDtsSrvr.exe"' -F $SQLVersionNo,$dtexecDir)
				Invoke-Expression "& $t" | Out-Null
				Restart-Service ("MsDtsServer{0}0" -f $SQLVersionNo)
			} -ArgumentList $SQLVersionNo,$dtexecDir

            $nodes = $odwConfigurationPackages.ChildNodes | Where-Object {($_.Step -eq "3.5")}
            $i = 1

                foreach($node in $nodes){
                    Show-Info -IsCI $IsCI -Message ("Running package {0}" -F $node.PackageName) -ForegroundColor Yellow
                    if ($node.Arguments.Length -gt 0){
                        $arg = ('/SET "{0}"' -F $node.Arguments)
                    }
                    else{
                        $arg = ''
                    }
                    $tt = $node.PackageName
                    $as = ("/DTS ""\""$tt"""" /SERVER \""$SSISInstance\"" /DECRYPT $encKey /CHECKPOINTING OFF  /REPORTING V " + $arg) # E shows error, V shows verbose log

                    $l = ("{0}\Package_step_{1}_{2}.log" -F $logPath, "3.5", $i)
                    if ($SSISInstance -eq 'localhost' -or $SSISInstance.startswith($env:ComputerName)){
                        Show-Info -IsCI $IsCI -Message ("Logs saved to: {0}" -F $l) -ForegroundColor Yellow
                    }else{
                        Show-Info -IsCI $IsCI -Message ("Logs saved to: {0} on {1}" -F $l, $SSISInstance) -ForegroundColor Yellow
                    }
                    Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock {
                        if ((Test-Path -Path (Join-Path -Path $args[0] -ChildPath dtexec.exe)) -eq $false){
                            $dtexecDir = Join-Path -Path $args[0] -ChildPath "Binn"
                        }
                        else{
                            $dtexecDir = $args[0]
                        }
                        if ((Test-Path -Path $args[2]) -eq $true){
                            Remove-Item -Path $args[2] -Force
                        }
                        $x = Start-Process -Wait -WorkingDirectory $dtexecDir -FilePath dtexec.exe -ArgumentList $args[1] -PassThru -RedirectStandardOutput $args[2]

                        $x = Get-Content -Encoding UTF8 $args[2] | Select-Object -last 4 | Select-Object -First 1

                        $wordToFind = 'DTSER_SUCCESS'
						$containsWord = $false
						$x | ForEach-Object{
							if ($_ -match $wordToFind){
								$containsWord = $true
								Write-Host ("Found" -f $containsWord) -ForegroundColor Yellow
							}
						}
						If (!$containsWord){
                            Write-Host "Package execution failed" -ForegroundColor Red
                            Write-Host $x -ForegroundColor Red

                            throw
                        }
                        else{
                            Write-Host "Package execution succeeded" -ForegroundColor Green
                        }
                    } -ArgumentList $dtexecDir, $as, $l
                    $i++
                }


            Show-Info -IsCI $IsCI -Message "Configuration packages applied" -ForegroundColor Green

            Show-Info -IsCI $IsCI -Message "Adding user for reports..." -ForegroundColor Yellow

			$c = (Get-Content -Encoding UTF8 -Path (Join-Path -Path (Split-Path -parent $PSCommandPath) -ChildPath "Private\ODW\setupReports.sql") -Raw).Replace("[Omada Data Warehouse]",("[{0}]" -f $ODWProductDB))
            $c = $c.Replace("megamart\ODWAdmins",("{0}\{1}" -f $serviceUserDomain, $ODWAdminsGroup)).Replace("megamart\ODWAuditors",("{0}\{1}" -f $serviceUserDomain, $ODWAuditorsGroup)).Replace("megamart\ODWUsers",("{0}\{1}" -f $serviceUserDomain, $ODWUsersGroup)) #$c.Replace("DOMAIN",$serviceUserDomain).Replace("megamart\",("{0}\" -F $serviceUserDomain))
			if ($useSQLUser){
                Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database "master" -Query $c -QueryTimeout 300 #-inputfile $sqlFile
            }
            else{
                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database "master" -Query $c -QueryTimeout 300 #-inputfile $sqlFile
            }
            #Run-SqlFromFile $SQLAdmUser $SQLAdmPass $SQLInstance "master" (Join-Path -Path (Split-Path -parent $PSCommandPath) -ChildPath "Private\ODW\setupReports.sql") -IsCI $IsCI

            Show-Info -IsCI $IsCI -Message "User added" -ForegroundColor Green

            Show-Info -IsCI $IsCI -Message "Running initial SQL scripts..." -ForegroundColor Yellow
            $initialODWScripts = $xmlcfg.SelectNodes("/Configuration/Version/ODW/DBScripts")
            $i = 0
            if ($enableCustomization -eq $true){
                Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
                $nodes = $initialODWScripts.ChildNodes | Where-Object { $_.Step -eq "3.5.1" -or $_.Step -eq "3.5.2"}
            }
            else{
                $nodes = $initialODWScripts.ChildNodes | Where-Object { $_.Step -eq "3.5.1"}
            }

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


            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse configured" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "35" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        Show-Info -IsCI $IsCI -Message "3.6 Omada Data Warehouse reports upload" -ForegroundColor DarkGreen
        if ($uploadReports -eq $true){
            try{
                Publish-Reports -rsHttps $rsHttps -remoteDB $remoteDB -rsOnAppServer $rsOnAppServer -rsServer $rsServer -odwUploadReportsToolPath $odwUploadReportsToolPath -odwInstallationPath $odwInstallationPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName $SQLInstance -SQLInstanceWithout $SQLInstanceWithout -SSRSPath $SSRSPath -credDB $credDB -SkipErrors $skipReportErrors
                Show-Info -IsCI $IsCI -Message "Omada Data Warehouse reports configured" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            catch{
                Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "36" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
                break
            }
        }
        else{
               Show-Info -IsCI $IsCI -Message "Omada Data Warehouse reports upload skipped" -ForegroundColor Green
               Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }


    }
    else{
        Show-Info -IsCI $IsCI -Message "3. Skipping Omada Data Warehouse installation" -ForegroundColor DarkGreen
    }
    if ($installRoPE -eq $true){

        Show-Info -IsCI $IsCI -Message "4.1 Role and Policy Engine installation" -ForegroundColor DarkGreen
        try{
            #Workaround - RoPE installer from command line uses (if such key exists) username from version 11.1 - NOT the one provided in argument
            $t = New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
            if ((Test-Path -Path "HKCR:\Software\Omada\Role and policy Engine\11.1\InstallerSettings") -eq $true){
                    Set-ItemProperty -Path "HKCR:\Software\Omada\Role and policy Engine\11.1\InstallerSettings" -Name "ServiceUser" -Value $serviceUser -ErrorAction SilentlyContinue
            }
            $t = Remove-PSDrive -Name HKCR
            #end of workaround

            #$localConfiguration = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration")
            #$serviceUser = $localConfiguration.Service.UserName
            #$serviceUserPassword = $localConfiguration.Service.Password
			#$serviceUserPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $serviceUserPassword
            #$ropeServiceName = $cfgVersion.RoPE.RoPEServiceName

            $args = (" /l*v \""{0}\installlog_rope.log\""" -F $logPath)

            $args +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            if ($useSQLUser){
                $args +=  " IS_SQLSERVER_AUTHENTICATION=\""2\"""
            }
            else{
                $args +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            }
            $args +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""
            $args +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""
            $args += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $cfgVersion.RoPE.RoPEProductDatabase)
            $args += " SERVICETYPE=\""2\"""#1=user account, 2=Service account
            $args += " SERVICEDOMAIN=\""$serviceUserDomain\"""
            $args += " SERVICEUSER=\""$serviceUser\"""
            $args += " SERVICEPASSWORD=\""$serviceUserPassword\"""
            $args +=  " INSTALLDIR=\""$ropeInstallationPath\"""
            $args += " CONNSTROISX=\""$ConnectionString\"""

            Show-Info -IsCI $IsCI -Message "Role and Policy Engine installation starting..." -ForegroundColor Yellow
            $t = Start-Process -Wait -WorkingDirectory $ropeInstallerPath -FilePath "$RoPEexe" -ArgumentList " /V""$args /qn"" " -PassThru
			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $ropeName} ) ){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_rope.log" -f $ropeName, $logPath) -ForegroundColor Red
				break
			}

            if ($restoreRoPEDB -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $RoPEProductDB) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($RoPEProductDB + ".bak")
                Restore-OmadaDatabaseTask -DBName $RoPEProductDB -BackupPath $dbBackupPath -IsCI $IsCI

            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $RoPEProductDB) -ForegroundColor Yellow
            }


			netsh http add urlacl url=http://+:8733/RoPERemoteApi/ user=$serviceUserDomain\$serviceUser >$null

            Show-Info -IsCI $IsCI -Message "Role and Policy Engine installed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "41" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
        Show-Info -IsCI $IsCI -Message "4.2 Adding Role and Policy Engine user to DB" -ForegroundColor DarkGreen
        try{
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $ropeDBUser) -Instance $SQLInstance -DBName $RoPEProductDB -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

            if ($stopRopeService -eq $false){
                Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Start"
            }

            Show-Info -IsCI $IsCI -Message "User added to Role and Policy Engine" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
           Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "42" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

    }
    else{
        Show-Info -IsCI $IsCI -Message "4. Skipping Role and Policy Engine installation" -ForegroundColor DarkGreen
    }
    if ($installOPS -eq $true){
        Show-Info -IsCI $IsCI -Message "5. Omada Provisioning Service installation" -ForegroundColor DarkGreen
        try{


            Show-Info -IsCI $IsCI -Message "Omada Provisioning Service installation starting..." -foregroundcolor yellow

            $args = ("/l*v \""{0}\installlog_ops.log\""" -F $logPath)
            $args += " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            $args += " IS_SQLSERVER_DATABASE=\""$opsProductDatabase\"""
            $args += " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""
            $args += " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""
            if ($useSQLUser){
                $args += " IS_SQLSERVER_AUTHENTICATION=\""1\"""
            }
            else
            {
                $args += " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            }
            $args += " SERVICETYPE=\""2\"""
            $args += " SERVICEDOMAIN=\""$serviceUserDomain\"""
            $args += " SERVICEUSER=\""$serviceUser\"""
            $args += " SERVICEPASSWORD=\""$serviceUserPassword\"""
            $args +=  " INSTALLDIR=\""$opsInstallationPath\"""
            $args += " OISXCONN=\""$ConnectionString\"""

            #$args

            $t = Start-Process -Wait -WorkingDirectory $opsInstallerPath -FilePath $OPSexe -ArgumentList "/S /V""$args /qr"" " -PassThru
			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $opsName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_ops.log" -f $opsName, $logPath) -ForegroundColor Red
				break
			}
			#in case DB is not created (when installation is unattended, some bug in installer)
			#check if db exists
            $dbExists = $false
			$conn = New-Object system.Data.SqlClient.SqlConnection
                    if ($useSQLUser){
                        $conn.connectionstring = [string]::format("Server={0};Database={1};User Id={2};Password={3}",$SQLInstance,$opsProductDatabase, $SQLAdmUser, $SQLAdmPass)
                    }
                    else{
                        $conn.connectionstring = [string]::format("Server={0};Database={1};Integrated Security=SSPI;",$SQLInstance,$opsProductDatabase)
                    }
                    try{
                        $conn.open()
                        $dbExists = $true
                    }catch{
                        $dbExists = $false
                    }
                    Show-Info -IsCI $IsCI -Message ("DB exists {0}" -F $dbExists) -ForegroundColor Green

            if ($restoreOPSDB -eq $true){
                Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $opsProductDatabase) -ForegroundColor Yellow
                $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($opsProductDatabase + ".bak")
                Restore-OmadaDatabaseTask -DBName $opsProductDatabase -BackupPath $dbBackupPath -IsCI $IsCI

            }
            else{
                Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $opsProductDatabase) -ForegroundColor Yellow
            }
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $opsDBUser) -Instance $SQLInstance -DBName $opsProductDatabase -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

			try{
            $u = (Get-CimInstance -ComputerName (Get-ADComputer -Filter 'OperatingSystem -like "Windows Server*"' | Select-Object -ExpandProperty Name) -Query "SELECT Name, StartName FROM Win32_Service WHERE Name = '$opsServiceName'").StartName
            if ($u -eq 'LocalSystem'){
                $t = ('& sc.exe config "{0}" obj="{1}\{2}" password="{3}"' -F $opsServiceName, $serviceUserDomain, $serviceUser, $serviceUserPassword)
                 Invoke-Expression ($t)
            }
			}
			catch{
				Show-Info -IsCI $IsCI -Message ("Unable to check if {0} is run in the context of {1}, minor issue - installation will be continued" -f $opsServiceName, $serviceUser) -ForegroundColor Yellow
			}

			netsh http add urlacl url=http://+:8000/ProvisioningService/service/ user=$serviceUserDomain\$serviceUser >$null
            Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Start"

            Show-Info -IsCI $IsCI -Message "Omada Provisioning Service installed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "50" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
		if ($esThumbprint.Length -gt 0){
			Show-Info -IsCI $IsCI -Message "5.1. Change configuration of Omada Provisioning Service to use SSL" -ForegroundColor DarkGreen
			try{
				Show-Info -IsCI $IsCI -Message "Updating OPS instances" -ForegroundColor Yellow
				$c = ('Declare @t nvarchar(4000)
					Set @t = ''<Properties>
					<Property Id="919">Default</Property>
					<Property Id="1000131">{0}</Property>
					<Property Id="1000132" Modified="true">8001</Property>
					<Property Id="1000133">false</Property>
					<Property Id="1000224" Modified="true">true</Property>
					</Properties>''

					Declare @xml XML
					SET @xml = CAST(@t AS XML);

					Update [{1}].[dbo].[tblDataObjectVersion] set PropertyXML=@xml
					where ID=(Select ID from [{1}].[dbo].[tblDataObjectVersion] where CurrentVer=1 and
					DataObjectID=(Select ID from [{1}].[dbo].[tblDataObject] where
					ParentID=(Select ID from [{1}].[dbo].[tblDataObject] where DisplayName=''ops instances'')))' -F $esbinding,$esDBName)
					if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }

					Show-Info -IsCI $IsCI -Message "Updating OPS service configuration file" -ForegroundColor Yellow

					$xmlConfigPath = Join-Path -Path $opsInstallationPath -ChildPath 'Omada.OPS.Service.exe.config'
					$xml = [xml](Get-Content -Encoding UTF8 $XMLConfigPath)

					$t = $xml.'configuration'.'system.serviceModel'.services."#comment"
					$t = $t.Replace("Standard service settings for letting OPS running regualr HTTP","").Replace(" For running HTTPS/SSL use this setting rather than the above. Update 'Port' and 'Use SSL' properties on OPS Instance in the enterprise server ","").Replace("<!--","").Replace("-->","").Replace("https://demo:",("https://{0}:" -F $esbinding))
					$xml.configuration."system.serviceModel".services.InnerXml = $t

					$t = $xml.'configuration'.'system.serviceModel'.client."#comment"
					$t = (($t -split '\n')[3]).Replace("enterpriseserver",$esbinding)
					$xml.configuration."system.serviceModel".client.InnerXml = $t

					$xml.Save($xmlConfigPath)

					Show-Info -IsCI $IsCI -Message "Adding certificate to connection" -ForegroundColor Yellow
					netsh http add sslcert ipport=0.0.0.0:8001 certhash=$esThumbprint appid='{86521b84-b247-4a15-b698-9d0bcc61e520}' >$null
					netsh http add sslcert ipport=127.0.0.1:8001 certhash=$esThumbprint appid='{86521b84-b247-4a15-b698-9d0bcc61e520}' >$null
					netsh http delete urlacl url=http://+:8001/ProvisioningService/Service/ >$null
					netsh http add urlacl url=https://+:8001/ProvisioningService/service/ user=$serviceUserDomain\$serviceUser >$null

					Restart-Service $opsServiceName

					Show-Info -IsCI $IsCI -Message "Configuration of Omada Provisioning Service changed" -ForegroundColor Green
					Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
			}
			catch{
				Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "51" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
				break
			}
		}
    }
    else{
        Show-Info -IsCI $IsCI -Message "5. Skipping Omada Provisioning Service installation" -ForegroundColor DarkGreen
    }
    #Show-Info -IsCI $IsCI -Message "Missing shemas..."
    #Copy-Item -Path 'C:\temp\Install\Schemas\*.*' -Destination 'C:\Program Files\Omada Identity Suite\Enterprise Server 12\website\Schema' -Force

    Show-Info -IsCI $IsCI -Message "6. Additional configuration" -ForegroundColor DarkGreen
    try{
            if (($installChangesets -eq $true) -and ($installES -eq $true)){
                Show-Info -IsCI $IsCI -Message "Changesets enabled and Enterprise Server was installed" -ForegroundColor Yellow
                #if demo enabled - if yes, then suggested packages. If not, then only core packages
				if ($demoEnabled -and $demoType -ne "Empty"){
					Show-Info -IsCI $IsCI -Message "Starting the import of suggested packages..." -ForegroundColor Yellow
					$allPackages = $true
					$l = ("{0}\changeset_suggestedpackage.log" -f $logPath)
					#input file based on paramater which needs to be passed to the utility
                    Import-ChangeSet -Customer omada -inputFile "P" -logFile $l -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI
                }
                elseif ($demoEnabled -and $demoType -eq "Empty"){
                    Show-Info -IsCI $IsCI -Message "Starting the import of suggested packages (but systems will not be imported)..." -ForegroundColor Yellow
					$allPackages = $true
					$l = ("{0}\changeset_suggestedpackage.log" -f $logPath)
                    Import-ChangeSet -Customer omada -inputFile "P" -logFile $l -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI
                }
				else{
					$l = ("{0}\changeset_corepackage.log" -f $logPath)
					Show-Info -IsCI $IsCI -Message "Starting the import of core packages..." -ForegroundColor Yellow
					Import-ChangeSet -Customer omada -inputFile "K" -logFile $l -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI
				}
				Get-Errors -IsCI $IsCI -l $l -SkipErrors $changesetsSkipErrors

				Invoke-ChangeSet -Step "6.1.1" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
                if ($enableCustomization -eq $true){
                    Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
                    Invoke-ChangeSet -Step "6.1.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
                }
            }

            if ($SQLInstance -ne 'localhost' -and $installES){
                if ($SQLInstanceName.Length -gt 0 -and !($rsOnAppServer)){
                    $rsUrl = ("http{0}://{1}/ReportServer_{2}" -F $s,$SQLInstanceWithout, $SQLInstanceName)
                }else{
					if ($rsOnAppServer){
						$rsServer = 'localhost'
					}else{
						$rsServer = $SQLInstanceWithout
					}
                    $rsUrl = ("http{0}://{1}/ReportServer" -F $s,$rsServer)
                }
                $c = ("
                         Declare @id int
                        Declare @temp as varchar(4000)
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ESARC</Property><Property Id=""932"" Modified=""true"">Initial Catalog={0};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        Declare @xml XML
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ESARC'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={0};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">RoPE</Property><Property Id=""932"" Modified=""true"">Initial Catalog={2};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='RoPE'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={2};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
						Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OISRoPE</Property><Property Id=""932"" Modified=""true"">Initial Catalog={2};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OISRoPE'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={2};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODW</Property><Property Id=""932"" Modified=""true"">Initial Catalog={3};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODW'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={3};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODWMD</Property><Property Id=""932"" Modified=""true"">Initial Catalog={4};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODWMD'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={4};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OPS</Property><Property Id=""932"" Modified=""true"">Initial Catalog={5};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OPS'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={5};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">Source System Data DB</Property><Property Id=""932"" Modified=""true"">Initial Catalog={6};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='Source System Data DB'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={6};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODWS</Property><Property Id=""932"" Modified=""true"">Initial Catalog={7};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODWS'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={7};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OISAudit</Property><Property Id=""932"" Modified=""true"">Initial Catalog={8};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OISAudit'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={8};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODWSSIS</Property><Property Id=""932"" Modified=""true"">Data Source={10};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODWSSIS'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Data Source={10};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OISES</Property><Property Id=""932"" Modified=""true"">Initial Catalog={9};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OISES'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={9};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id

                        Update tblCustomerSetting set ValueStr='{11}' where [Key]='SSRSUrl' --and Category='Website'
						Update tblCustomerSetting set ValueStr='{12}' where [Key]='SSISServer' and Category='Microsoft SQL Server Integration Services'

                    " -F $esAuditDBName, $SQLInstance, $RoPEProductDB, $ODWProductDB, $ODWProductDBMaster, $opsProductDatabase, $esSourceSystemDBName, $restoreODWProductDBStaging, $esAuditDBName, $esDBName, $SSISInstance, $rsUrl,$env:COMPUTERNAME, $esDBName)

                    if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }

					#kerberos double hop caused an issue and following setting was (or will be introduced - in this case, no change is done)
					if ($SQLInstance -ne $SSISInstance){
						 $c = ("UPDATE [dbo].[tblCustomerSetting] SET valuebool=1 where [key]='SSISUseKerberos';UPDATE [dbo].[tblCustomerSetting] SET valuestr='{0}' where [key]='SSISServer'" -f $SSISInstance)
						 if ($useSQLUser){
							Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName  -query $c
						}
						else{
							Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName  -query $c
						}
					}
             }

        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "61" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }

        Show-Info -IsCI $IsCI -Message "6.2 Additional configuration of Audit DB" -ForegroundColor DarkGreen
        if (($installChangesets -eq $true) -and ($installES -eq $true) -and ($installODW -eq $true)){
            try{
                Show-Info -IsCI $IsCI -Message "IIS reset..." -ForegroundColor Yellow
                $t = invoke-command -scriptblock {iisreset}

                Show-Info -IsCI $IsCI -Message "Restarting a web site..." -ForegroundColor Yellow
                Try{
                    $t = Invoke-WebRequest -URI "http://$esBinding" -TimeoutSec 60 -UseDefaultCredentials
                }
                Catch {
                    Show-Info -IsCI $IsCI -Message "Calling web site failed. This is not critical error, installation is not aborted." -ForegroundColor Red
                }

                Show-Info -IsCI $IsCI -Message "Restarting Timer service..." -ForegroundColor Yellow
                Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Restart"

                Show-Info -IsCI $IsCI -Message "Generating audit tables..." -ForegroundColor Yellow
                Start-Sleep -s 20

                Show-Info -IsCI $IsCI -Message "Running archiving scripts..." -ForegroundColor Yellow
                $sqlFile = Join-Path -Path $odwInstallationPath -ChildPath $cfgVersion.ES.AuditDBInitialScript

                $ScriptBlock = {
                    $sqlFile = $args[0]
                    $esAuditDBName = $args[1]
                    $SQLAdmUser = $args[2]
                    $SQLAdmPass = $args[3]
                    $SQLInstance = $args[4]
					$useSQLUser = $args[5]

                    #as sqlFile here is copied with ODW
                    #Set-ItemProperty $sqlFile -name IsReadOnly -value $false
                    #(Get-Content -Encoding UTF8 $sqlFile).replace('$(dbName)', $esAuditDBName) | Set-Content $sqlFile
                    $env:dbName = $esAuditDBName
					Write-Host  ("AuditDB: {0}" -f $env:dbName) -ForegroundColor Yellow
                    if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esAuditDBName -inputfile $sqlFile -QueryTimeout 300
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esAuditDBName -inputfile $sqlFile -QueryTimeout 300
                    }
                }
                if ($ComputerName -eq 'localhost' -or $ComputerName -eq $env:ComputerName){
                    Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $sqlFile, $esAuditDBName, $SQLAdmUser, $SQLAdmPass, $SQLInstance, $useSQLUser
                }
                else{
                    Invoke-Command -ScriptBlock $ScriptBlock -Credential $credDB -ComputerName $SSISInstance -ArgumentList $sqlFile, $esAuditDBName, $SQLAdmUser, $SQLAdmPass, $SQLInstance, $useSQLUser
                }

                Show-Info -IsCI $IsCI -Message "Audit DB configured" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            catch{
                Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "62" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
                break
            }
        }
        else{
            Show-Info -IsCI $IsCI -Message "As this is a partial installation - audit will not be configured" -ForegroundColor Yellow
        }


    try{
        $msSqlService = "MSSQLSERVER";
        Show-Info -IsCI $IsCI -Message ("6.3 Changing startup type of installed services and adding dependency on {0}" -f $msSqlService) -ForegroundColor DarkGreen

        if ($installRoPE -eq $true){
            Set-ServicesStartAndDependency -ServiceName $ropeServiceName -StartType "delayed-auto" -Dependencies $msSqlService
        }
        if ($installES -eq $true){
            Set-ServicesStartAndDependency -ServiceName $esTimerService -StartType "delayed-auto" -Dependencies $msSqlService
        }
        if ($installOPS -eq $true){
            Set-ServicesStartAndDependency -ServiceName $opsServiceName -StartType "delayed-auto" -Dependencies $msSqlService

			if ($esThumbprint.Length -gt 0){
				Show-Info -IsCI $IsCI -Message "Updating OPS instances entry in ES to use SSL" -ForegroundColor Yellow
				$c = ('Declare @t nvarchar(4000)
					Set @t = ''<Properties>
					<Property Id="919">Default</Property>
					<Property Id="1000131">{0}</Property>
					<Property Id="1000132" Modified="true">8001</Property>
					<Property Id="1000133">false</Property>
					<Property Id="1000224" Modified="true">true</Property>
					</Properties>''

					Declare @xml XML
					SET @xml = CAST(@t AS XML);

					Update [{1}].[dbo].[tblDataObjectVersion] set PropertyXML=@xml
					where ID=(Select ID from [{1}].[dbo].[tblDataObjectVersion] where CurrentVer=1 and
					DataObjectID=(Select ID from [{1}].[dbo].[tblDataObject] where
					ParentID=(Select ID from [{1}].[dbo].[tblDataObject] where DisplayName=''ops instances'')))' -F $esbinding,$esDBName)
					if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }
					Restart-Service -ServiceName ("*{0}*" -f $esTimerService)
			}

			Invoke-Expression -Command 'sc.exe \\localhost config "$opsServiceName" start=delayed-auto' | Out-Null
            $secstr = New-Object -TypeName System.Security.SecureString
            $administratorUserPassword.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
            if ($installChangesets -eq $true){
                if($installES){
					if ($allPackages -and $demoType -ne "Empty"){
						$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
						$ws = New-WebServiceProxy -uri $pushServiceUrl -UseDefaultCredential #-Credential $cred
						$t = $ws.PushConfiguration()
                    }
                    elseif ($allPackages -and $demoType -eq "Empty"){
                        Show-Info -IsCI $IsCI -Message "Suggested packages were installed, OPS configuration wasn't pushed to ES" -ForegroundColor Yellow
                    }
                    else{
    					Show-Info -IsCI $IsCI -Message "Only core packages were installed, OPS configuration wasn't pushed to ES" -ForegroundColor Yellow
					}
                }
                else{
                    Show-Info -IsCI $IsCI -Message "As Enterprise Server installation was disabled, OPS configuration wasn't pushed to ES" -ForegroundColor Yellow
                }
            }
            Show-Info -IsCI $IsCI -Message "Startup type changed" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

        }

        #Sometimes - don't figured yet why - SSIS service path is pointing to weird path. Fix
        $t = ('sc.exe config MsDtsServer{0}0 binPath= "{1}MsDtsSrvr.exe"' -F $SQLVersionNo,$dtexecDir)
        $tt = Invoke-Expression "& $t"
		try{
			Restart-Service ("MsDtsServer{0}0" -f $SQLVersionNo)
		}
		catch{
			Show-Info -IsCI $IsCI -Message ("Restart of MsDtsServer{0}0 failed, skipping "-f $SQLVersionNo) -ForegroundColor Yellow
		}
		Show-Info -IsCI $IsCI -Message $t -ForegroundColor Yellow
		Show-Info -IsCI $IsCI -Message ("Updating Integration Services windows service to v{0}" -F $SQLVersionNo) -ForegroundColor Yellow

            if ($useSQLUser){
                Invoke-Sqlcmd -query "EXEC sp_addrolemember N'SQLAgentOperatorRole', [$($serviceUserDomain)\$($serviceUser)]" -database "msdb"  -ServerInstance $SQLInstance -Username $SQLAdmUser -Password $SQLAdmPass
            }
            else{
                Invoke-Sqlcmd -query "EXEC sp_addrolemember N'SQLAgentOperatorRole', [$($serviceUserDomain)\$($serviceUser)]" -database "msdb"  -ServerInstance $SQLInstance
            }
        }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "63" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }

    if ($installODW){
         Show-Info -IsCI $IsCI -Message "6.4 Change configuration of Reporting Server" -ForegroundColor DarkGreen
         try{
            if ($disableForceSSL -eq $true){

                $ScriptBlock ={
                    $SSRSPath = $args[0]
					$server = $args[1]
                    $XMLFile = ("{0}\ReportServer\rsreportserver.config" -F $SSRSPath)
					if ((Test-Path -Path $XMLFile)){
						[xml]$xmlTemp = Get-Content -Encoding UTF8 $XMLFile
						$nodes = $xmlTemp.SelectNodes("/Configuration/Add")
						$nodes | Where-Object {$_.Key -eq "SecureConnectionLevel"} | ForEach-Object {$_.Value = "0"}
						$xmlTemp.Save($XMLFile)
						Write-Host  "Configuration changed" -ForegroundColor Green
					}
					else{
						Write-Host "Reporting Server not found, skipping" -ForegroundColor Green
						Write-Host ("({0}) Missing path: {1}" -F $server, $XMLFile)
					}

                }
                if ($SQLInstance -eq 'localhost' -or $SQLInstance.startswith($env:ComputerName)){
                    Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $SSRSPath, $SQLInstance
                }
                else{
                    Invoke-Command -ScriptBlock $ScriptBlock -Credential $CredDB -ComputerName $SQLInstanceWithout -ArgumentList $SSRSPath, $SQLInstanceWithout
                }
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            else{
                Show-Info -IsCI $IsCI -Message "Change in configuration of Reporting Server disabled, skipping..." -ForegroundColor Yellow
            }

         }
         catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "64" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
    }

    if ($enableCustomization -eq $true){
        if ($installRoPE){
            Show-Info -IsCI $IsCI -Message "6.5 Additional changes in RoPE configuration files" -ForegroundColor DarkGreen
            if ($enableCustomization -eq $true){
				try{
						if ($null -ne $demoRoPEFiles){
						   foreach($node in $demoRoPEFiles.ChildNodes){
								$t = $xmlcfg.SelectNodes("/Configuration/Version/RoPE/InstallationPath")
								$tp = (Join-Path -Path $t.InnerText -ChildPath ($Node.Target + "\" + $Node.Name))
								Show-Info -IsCI $IsCI -Message ("Copying {0} to {1}" -F $node.Name,$tp) -ForegroundColor Yellow
								$t = $xmlcfg.SelectNodes("/Configuration/Version/RoPE/ConfigFilesSourcePath")
								$sp = Join-Path -Path $t.InnerText -ChildPath $node.Name
								Copy-Item -Path $sp -Destination $tp -Force
						}
						Show-Info -IsCI $IsCI -Message "Additional RoPE configuration files copied" -ForegroundColor Green
					}
					else{
						Show-Info -IsCI $IsCI -Message "No RoPE configuration files to copy, skipping" -ForegroundColor Yellow
					}
				}
				catch{
					Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "65" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
					break
				}
			}
			else{
				Show-Info -IsCI $IsCI -Message "Customization is disabled, skipping" -ForegroundColor Yellow
			}
			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
		}

        Show-Info -IsCI $IsCI -Message "6.6. Additional changesets import" -ForegroundColor DarkGreen
        try{
            if (($installChangesets -eq $true) -and ($installES -eq $true)){
                Show-Info -IsCI $IsCI -Message "Changesets enabled and Enterprise Server was installed" -ForegroundColor Yellow
                Invoke-ChangeSet -Step "6.6.1" -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					if ($enableCustomization -eq $true){
						Show-Info -IsCI $IsCI -Message "Customization is enabled, running also additional scripts" -ForegroundColor Yellow
						Invoke-ChangeSet -Step "6.6.2" -SkipErrors $changesetsSkipErrors -xml $xmlcfg -Customer $changesetsCustomer -LogFilePath $logPath -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI -noMerge $noChangesetsMerge
					}
				}
            Show-Info -IsCI $IsCI -Message "Additional changesets imported" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "66" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
    }

	    try{

            Show-Info -IsCI $IsCI -Message "6.7 Import survey(s)" -ForegroundColor DarkGreen
            if ($esImportSurveys){
				Show-Info -IsCI $IsCI -Message "Survey(s) import enabled" -ForegroundColor Green
				$esImportSurveysTool = $cfgVersion.ES.SurveyTemplates.ToolPath
				$esImportSurveysPath = $cfgVersion.ES.SurveyTemplates.SurveyTemplatesPath
				$surveys = (Get-ChildItem -Path $esImportSurveysPath).Name
				$i = 1
				foreach($file in $surveys){
					Show-Info -IsCI $IsCI -Message ("Importing: {0} ({1} of {2})" -F $file.Replace(".xml",""), $i, $surveys.Count) -ForegroundColor Yellow
					$l = Join-Path -Path $logPath -ChildPath ("surveyImport_{0}.log" -f $file.Replace(".xml",""))
					$f = Join-Path -Path $esImportSurveysPath -ChildPath $file
					$t = ('"{0}" -c 1000 -f "{1}" -l "{2}"' -F $esImportSurveysTool, $f, $l)
					Invoke-Expression "& $t"
					$i++
				}
				Show-Info -IsCI $IsCI -Message "Survey(s) were imported" -ForegroundColor Green
			}else{
				Show-Info -IsCI $IsCI -Message "Survey(s) import disabled, skipping" -ForegroundColor Green
			}
			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "67" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }


    try{

            Show-Info -IsCI $IsCI -Message "6.8 Additional DBs restore" -ForegroundColor DarkGreen
            $additionalDBs = $demoDBs.DB.Name | Where-Object{-not (($_ -eq "$esDBName") -or ($_ -eq "$esSourceSystemDBName") -or ($_ -eq "$esAuditDBName") -or `
            ($_ -eq "$ODWProductDB") -or ($_ -eq "$ODWProductDBStaging") -or ($_ -eq "$ODWProductDBMaster") -or ($_ -eq "$RoPEProductDB") -or ($_ -eq "$opsProductDatabase"))}
            foreach($adb in $additionalDBs){
                $restore = [System.Convert]::ToBoolean(($demoDBs.DB | Where-Object{$_.Name -eq "$adb"}).Restore)
                if ($restore -eq $true){
                    Show-Info -IsCI $IsCI -Message ("Restoring {0}" -F $adb) -ForegroundColor Yellow
                    $dbBackupPath = Join-Path -Path $backupPath -ChildPath ($adb + ".bak")
                    Restore-OmadaDatabaseTask -DBName $adb -BackupPath $dbBackupPath -IsCI $IsCI
                    Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -Instance $SQLInstance -DBName $adb -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
                }
                else{
                    Show-Info -IsCI $IsCI -Message ("Restore of {0} is disabled, skipping" -F $adb) -ForegroundColor Yellow
                }
            }

            Show-Info -IsCI $IsCI -Message "Additional Dbs Restored" -ForegroundColor Green
            Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "68" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
# add different users in different databases - if needed


    if ($isFullInstall){
        try{
            Show-Info -IsCI $IsCI -Message "6.9 Creation of task for daily import\export" -ForegroundColor DarkGreen
            if ($createImportTask -eq $true){
			    $taskFileTemplate = Join-Path -Path $changesetPath.Replace("Changesets","ES") -ChildPath "NightlyImportTemplate.xml"
			    if (Test-Path -Path $taskFileTemplate){
				    $taskUser = ("{0}\{1}" -F $administratorDomain, $administratorUser)
				    $c = Get-Content -Encoding UTF8 -path $taskFileTemplate -Raw
				    $c = $c.Replace("TASKAUTHOR",$taskUser).Replace("TASKSERVER",$SSISInstance).Replace("TASKENCRYPTION",$encKey).Replace("TASKSQL",$SQLVersionNo)
				    $ScriptBlock = {
					    $c = $args[0]
					    $taskUser = $args[1]
					    $administratorUserPassword = $args[2]
					    Register-ScheduledTask -Xml $c -TaskName "Omada - nightly import" -User $taskUser -Password $administratorUserPassword –Force | Out-Null
				    }
				    if ($SSISInstance -eq 'localhost' -or $SSISInstance.startswith($env:ComputerName)){
                    Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $c, $taskUser, $administratorUserPassword
                }
                else{
                    Invoke-Command -ScriptBlock $ScriptBlock -Credential $CredDB -ComputerName $SSISInstance -ArgumentList $c, $taskUser, $administratorUserPassword
                }

			    }
			    else{
				    Show-Info -IsCI $IsCI -Message "File used to create import\export task is missing, skipping" -ForegroundColor Yellow
			    }

                Show-Info -IsCI $IsCI -Message "Task created" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            else{
                Show-Info -IsCI $IsCI -Message "Creation of task is disabled, skipping" -ForegroundColor Green
            }

        }
        catch{
            Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "69" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
    }

	if ($null -ne $languageVersion){
		Try{
			Show-Info -IsCI $IsCI -Message "6.10 Installation of language pack" -ForegroundColor DarkGreen
			$packPath = Join-Path -Path $esInstallationPath -ChildPath (Join-Path -Path 'support files\Language Packs' -ChildPath $languageVersion)
            $l = ("{0}\changeset_{1}.log" -f $logPath, $languageVersion.Replace(".xml",""))
			if (Test-Path -Path $packPath){
				Import-ChangeSet -Customer omada -inputFile $packPath -logFile $l -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI
				Show-Info -IsCI $IsCI -Message "Updating default language" -ForegroundColor Yellow
				$languages = @{"danish_language_pack.xml"= 1001;
					"german_language_pack.xml" = 1002;
					"spanish_language_pack.xml" = 1003;
					"swedish_language_pack.xml" = 1004;
					"dutch_language_pack.xml" = 1005;
					"finnish_language_pack.xml" = 1006;
					"french_language_pack.xml" = 1007;
					"italian_language_pack.xml" = 1008;
					"norwegian_language_pack.xml" = 1009;
					"japanese_language_pack.xml" = 1010;
					"chinese_language_pack.xml" = 1011;
					"greek_language_pack.xml" = 1012;
					"polish_language_pack.xml" = 1013;
					"russian_language_pack.xml" = 1014;}
					$languageID = $languages.get_Item($languageVersion)
					if ($null -eq $languageID){
						$languageID = 1000
					}
				$c = ("Update [{0}].[dbo].[tblUser] set LanguageID={1} where UserName='{2}';
						Update [{0}].[dbo].[tblCustomerSetting] set ValueInt={1} where [Key]='DefaultLanguage';" -F $esDBName, $languageID, $env:USERNAME)
			if ($useSQLUser){
                invoke-sqlcmd -ServerInstance $SQLInstance -User $SQLAdmUser -Password $SQLAdmPass -query $c -database $esDBName
            }
            else
            {
                invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database $esDBName
            }


			}
			else{
				Show-Info -IsCI $IsCI -Message ("File {0} with language pack is missing, skipping..." -f $packPath) -ForegroundColor Yellow
			}
			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
		}
		catch{
			Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "69" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI #as we run out of number - so we stay with 69
			break
		}
	}

    try{
        Show-Info -IsCI $IsCI -Message "6.11 Services restart..." -ForegroundColor DarkGreen

        if ($installES -eq $true){
            Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Restart"
        }
        if ($installRoPE -eq $true -and $stopRopeService -eq $false){
            Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Restart"
        }
        if ($installOPS -eq $true){
            Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Restart"
        }
        Show-Info -IsCI $IsCI -Message "Waiting systems to fully start..." -ForegroundColor Yellow
        Start-Sleep -s 10

        Show-Info -IsCI $IsCI -Message "Additional configuration performed" -ForegroundColor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "69" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }

    #DataBases backup
    Try{
        Show-Info -IsCI $IsCI -Message "6.12 Backup of newly configured DBs" -ForegroundColor DarkGreen
        $t = Join-Path -Path $backupPath -ChildPath "cleanSystemBackup"
        Backup-Databases -Xml $xmlcfg -BackupPath $t -BackupAll $false -IsCI $IsCI
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
         Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "69" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI #as we run out of number - so we stay with 69
         break
    }

    #call common import script
    if ($isFullInstall){
        Switch-OmadaToDemo -XMLPath $XMLPath -IsCI $IsCI -LogPath $logPath
    }

    if ($demoEnabled){
        Show-Info -IsCI $IsCI -Message "Final systems restart" -ForegroundColor Yellow
        if ($installES -eq $true){
             Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Restart"
        }
        if ($installRoPE -eq $true){
            Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Restart"
        }
        if ($installOPS -eq $true){
            Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Restart"
        }
    }
    else{
        if ($installRoPE -eq $true -and $stopRopeService -eq $true){#first start of rope service
            Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Start"
        }
    }
    Restart-Service -ServiceName MSDTC -Action "Restart"

	if ($remoteDB -and !$SSISInstance.startswith($env:ComputerName)){
		Try{
			Show-Info -IsCI $IsCI -Message "6.12 Removal of network shares created during installation" -ForegroundColor DarkGreen
			$c = {
				Get-SmbShare -Name "OmadaInstall" | Remove-SmbShare -Confirm:$false
				Get-SmbShare -Name "OmadaLogs" | Remove-SmbShare -Confirm:$false
				Get-SmbShare -Name "OmadaScript" | Remove-SmbShare -Confirm:$false
			}
			Invoke-Command -ComputerName $SQLInstanceWithout -Credential $credDB -ScriptBlock $c
			if ($SQLInstanceWithout -ne $SSISInstance){
				Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $c
			}

			Show-Info -IsCI $IsCI -Message "Shares removed" -ForegroundColor Green
			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
		}
		catch{
			 Show-Info -IsCI $IsCI -Message "No shares were removed, this is not a critical error" -ForegroundColor Red
		}
	}


    Show-Info -IsCI $IsCI -Message "IIS restart" -ForegroundColor Yellow
    $t = invoke-command -scriptblock {iisreset}
    if ($installES){
        try{
            Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Restart"
            Start-Sleep -s 10
        }
        catch{
			Show-Info -IsCI $IsCI -Message "Service restart failed, skipping" -ForegroundColor Yellow
		}
		if ($enableCustomization -eq $true){
				Show-Info -IsCI $IsCI -Message "Customization is enabled, enabling changeset logging" -ForegroundColor Yellow
				$c = "UPDATE tblCustomerSetting SET ValueBool='1' WHERE [Key]='AllowMassUpdate';
					UPDATE tblCustomerSetting SET ValueBool='1' WHERE [Key]='ConfigurationMode';
					UPDATE tblCustomerSetting SET ValueBool='1' WHERE [Key]='EnabConfigChngLogng';
					"#UPDATE tblCustomerSetting SET ValueBool='1' WHERE [Key]='ColSearchLeftWldCrd';
				if ($useSQLUser){
					Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
				}
				else{
					Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
				}
           }
    }

    #Check Omada services states
    $services = @($esTimerService, $opsServiceName, $ropeServiceName)

    foreach($service in $services){
        $service = Get-Service -Name *$service* -ErrorAction SilentlyContinue

        if($null -eq $Service){
            Write-Host "$service is not installed"
        } else {
            if ($Service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Write-Host ('Trying to start a service {0} ' -f $service.DisplayName)
                Start-Service $service.Name
                $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, (New-TimeSpan -Minutes 1))
            }

            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                Write-Error ('{0} is not running (current state: {1})' -f $service.DisplayName, $service.Status)
            } else {
                Write-Host ('{0} is running' -f $service.DisplayName)
            }
        }
    }

    $tend = Get-Date

    c:

    Write-Host "Installation complete. " -ForegroundColor Green
	if ($SSISInstance -ne 'localhost' -and !$SSISInstance.startswith($env:ComputerName) -and $remoteDB){
		$ScriptBlock = {
            Write-Host  ("Installed on {0}:" -F $args[0]) -ForegroundColor DarkGreen
            Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like '*Omada*'} |  Select-Object DisplayName, DisplayVersion  | Format-Table –AutoSize
		}
		Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $SSISInstance -Credential $credDB -ArgumentList $SSISInstance
		Show-Info -IsCI $IsCI -Message "Installed locally:" -ForegroundColor DarkGreen
	}
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like '*Omada*'} |  Select-Object DisplayName, DisplayVersion  | Format-Table –AutoSize
    if ($demoType -eq "Full" -or $demoType -eq "Empty"){
		Show-Info -IsCI $IsCI -Message ("Table (c) by Lars")

	}

	#workaround for DevTestLabs as there is not that easy to get error message
	$p = (Join-Path -Path $logPath -ChildPath "done.txt")
        if (!(Test-Path -Path $p)){
		New-Item -Path $p -ItemType File | Out-Null
		Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like '*Omada*'} |  Select-Object DisplayName, DisplayVersion  | Out-String | Set-Content -Path $p
	}
	if ($IsCI){
		Show-Info -IsCI $IsCI -Message ("{0} | Work is done, machine is ready. " -F $tend.DateTime) -ForegroundColor DarkGreen
	}else {
		Show-Info -IsCI $IsCI -Message ("Start time: {0}, finish time: {1}" -F $tstart.DateTime, $tend.DateTime) -ForegroundColor DarkGreen
	}
    if ($installES -and $startIE){
        $url = ("http://{0}/" -f $esBinding)
        $ie = New-Object -com internetexplorer.application;
        $ie.visible = $true;
        $ie.navigate($url);
    }
}