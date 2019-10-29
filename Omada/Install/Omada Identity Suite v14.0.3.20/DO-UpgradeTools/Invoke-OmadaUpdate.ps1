
Function Invoke-OmadaUpdate {
    <#
    .SYNOPSIS
        Script updates Omada components
    .DESCRIPTION
        Script updates Omada components based on configuration file
    .PARAMETER XMLPath
        Path to xml file with configuration
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Invoke-OmadaUpdate -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\install.config"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$XMLPath,

	[System.Management.Automation.PSCredential]$credMaster,

	[Boolean]$startIE = $true,

    [Boolean]$IsCI = $false,

	[string]$LogPath
    )
    $tstart = Get-Date
    if (Test-Path $XMLPath){
        [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
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
    $cfgVersion = $xmlcfg.SelectNodes("/Configuration/Version")

	$majorVersion = $xmlcfg.SelectNodes("/Configuration/Version/OIS").Version
    $MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL")

	$SQLVersion = $cfgVersion.MSSQL.Version
    $SQLVersionNo = $cfgVersion.MSSQL.VersionNo
	$SQLAdmUser = $MSSQLSecurity.Administrator
	$SQLAdmPass = $MSSQLSecurity.AdministratorPassword
	if ($SQLAdmPass.Length -gt 0){
		$SQLAdmPass = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $SQLAdmPass
	}
	else{
        $useSQLUser = $false
        $SQLAdmUser = 'unknown'
		$SQLAdmPass = '404'
    }
	$SQLInstance = $cfgVersion.MSSQL.Server
	$SQLServer = $MSSQLSecurity.Server

	$majorVersion = $xmlcfg.SelectNodes("/Configuration/Version/OIS").Version
	$moduleVersion = ("{0}.{1}" -f (Get-Module -Name "DO-UpgradeTools").Version.Major,(Get-Module -Name "DO-UpgradeTools").Version.Minor)

	$installES = [System.Convert]::ToBoolean($cfgVersion.ES.Enabled)
    $installODW = [System.Convert]::ToBoolean($cfgVersion.ODW.Enabled)
    $installRoPE = [System.Convert]::ToBoolean($cfgVersion.RoPE.Enabled)
    $installOPS = [System.Convert]::ToBoolean($cfgVersion.OPS.Enabled)

	$esInstallerPath = (Join-Path -Path $TempPath -ChildPath "ES\install")
    $odwInstallerPath = (Join-Path -Path $TempPath -ChildPath ("ODW\install\SQL{0}" -F $SQLVersion))
    $ropeInstallerPath = (Join-Path -Path $TempPath -ChildPath "RoPE\install\RoPE")
    $opsInstallerPath = (Join-Path -Path $TempPath -ChildPath "OPS\install\Default Configuration\Release\DiskImages\DISK1")

	$esExe = $cfgVersion.ES.Exe
	$ODWexe = $cfgVersion.ODW.Exe
	$RoPEexe = $cfgVersion.RoPE.Exe
	$OPSexe = $cfgVersion.OPS.Exe

	$odwName = $cfgVersion.ODW.Name
	$ropeName = $cfgVersion.RoPE.Name
	$opsName = $cfgVersion.OPS.Name
	$esName = $cfgVersion.ES.Name

	$esDBName = $cfgVersion.ES.DBName

	$ODWProductDB = $cfgVersion.ODW.ODWProductDatabase
    $ODWProductDBStaging = $cfgVersion.ODW.ODWProductDatabaseStaging
    $ODWProductDBMaster = $cfgVersion.ODW.ODWProductDatabaseMaster

	$SSISInstance = $cfgVersion.MSSQL.SSIS
	$credDB = new-object -typename System.Management.Automation.PSCredential -argumentlist $administratorUser, $secstr
	$dtexecDir = Get-DtexecPath -SQLVersion $SQLVersion -Server $SSISInstance -Credential $credDB -SQLVersionNo $SQLVersionNo -IsCI $IsCI
	if ($null -eq $dtexecDir){
		Show-Info -IsCI $IsCI -Message ("No SSIS path found on {0}, please check configuration" -f $SSISInstance) -ForegroundColor Red
        break
	}
    else{
		Show-Info -IsCI $IsCI -Message ("Path to SSIS on {0}: {1}" -f $SSISInstance, $dtexecDir) -ForegroundColor Green
	}

	$esTimerService = $cfgVersion.ES.TimerServiceName
	$opsServiceName = $cfgVersion.OPS.ServiceName
	$ropeServiceName = $cfgVersion.RoPE.RoPEServiceName

	$esBinding = $cfgVersion.ES.IISBinding
	$esThumbprint = $cfgVersion.ES.CertThumbprint

	$localConfiguration = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration")
    $serviceUser = $localConfiguration.Service.UserName
    $serviceUserPassword = $localConfiguration.Service.Password
	$serviceUserPassword = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $serviceUserPassword
    $serviceUserDomain = $localConfiguration.Service.Domain

	$esFeaturesToInstall = $cfgVersion.ES.Features
	$esInstallationPath = $cfgVersion.ES.InstallationPath
	$ropeInstallationPath = $cfgVersion.RoPE.InstallationPath
	$opsInstallationPath = $cfgVersion.OPS.InstallationPath
	$odwInstallationPath = $cfgVersion.ODW.InstallationPath


	$enableCustomization = [System.Convert]::ToBoolean($localConfiguration.Customization)
	$demoRoPEFiles = $xmlcfg.SelectNodes("/Configuration/Version/RoPE/ConfigFiles")
	$RoPEProductDB = $cfgVersion.RoPE.RoPEProductDatabase

	$demoType = $xmlcfg.SelectNodes("/Configuration/Demo").Type
	$demoEnabled = [System.Convert]::ToBoolean($xmlcfg.SelectNodes("/Configuration/Demo").Enabled)

	$opsProductDatabase = $cfgVersion.OPS.DBName
    $opsDBPass = $cfgVersion.OPS.DBPassword
	if ($SQLAdmPass.Length -gt 0){
		$opsDBPass = Read-PasswordFromConfig -XMLPath $XMLPath -encryptedText $opsDBPass
	}

	$uploadReports = [System.Convert]::ToBoolean($cfgVersion.ODW.UploadReports.Enabled)
	$skipReportErrors = [System.Convert]::ToBoolean($cfgVersion.ODW.UploadReports.SkipErrors)
	$odwUploadReportsToolPath = $cfgVersion.ODW.UploadReports.InnerText
	$rsHttps = [System.Convert]::ToBoolean($cfgVersion.MSSQL.RsHttps)
	$SSRSPath = $cfgVersion.MSSQL.SSRSPath
	if (($cfgVersion.MSSQL.RsOnAppServer).Length -gt 0){
		$rsOnAppServer = [System.Convert]::ToBoolean($cfgVersion.MSSQL.RsOnAppServer)
            if ($rsOnAppServer -eq $true){
			$ServiceStatus = Get-Service -name "ReportServer" -ErrorAction SilentlyContinue
				if ($null -eq $ServiceStatus){
					Show-Info -IsCI $IsCI -Message "Reporting services were not found on this machine" -ForegroundColor Red
					throw
				}
				elseif($ServiceStatus.Status -ne "Running"){
					Show-Info -IsCI $IsCI -Message "Reporting services are not running on this machine" -ForegroundColor Red
					throw
				}
			}
	}
	else{
		$rsOnAppServer = $false
	}

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


	    $t = (Get-SQLName -SQLInstance $SQLInstance -rsOnAppServer $rsOnAppServer)
        #$SQLName = $t.SQLName
        $SQLInstanceWithout = $t.SQLInstanceWithout
        $rsServer = $t.rsServer
        $remoteDB = $t.remoteDB


	     Show-Info -IsCI $IsCI -Message "Starting OIS update script..." -ForegroundColor Green

	    if ($installES -eq $false){
            Show-Info -IsCI $IsCI -Message "Enterprise Server will not be updated" -ForegroundColor Green
        }
        if ($installODW -eq $false){
            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse will not be updated" -ForegroundColor Green
        }
        if ($installRoPE -eq $false){
            Show-Info -IsCI $IsCI -Message "Role and Policy Engine will not be updated" -ForegroundColor Green
        }
        if ($installOPS -eq $false){
            Show-Info -IsCI $IsCI -Message "Omada Provisioning Server will not be updated" -ForegroundColor Green
        }

        $cfgVersionType=$cfgVersion.Type

	try{
		Show-Info -IsCI $IsCI -Message "1.1. Preparation of installation files" -ForegroundColor Green

        if ($cfgVersionType -eq "Newest"){
            Show-Info -IsCI $IsCI -Message "Newest versions of OIS will be installed" -ForegroundColor Green
				if ($null -eq $credMaster){
					Show-Info -IsCI $IsCI -Message "Credentials for network share are required" -ForegroundColor Yellow
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
                -CopyRoPE $installRoPE -CopyODW $installODW -CopyOPS $installOPS -IsCI $IsCI
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
            $r = Copy-UpgradeFiles -Credential $credential -TempPath $tempPath -ESVersion $cfgVersion.ES.Version -OPSVersion $cfgVersion.OPS.Version -ODWVersion $cfgVersion.ODW.Version -RoPEVersion $cfgVersion.RoPE.Version `
                -ESDropFolder $cfgVersion.ES.DropFolder -OPSDropFolder $cfgVersion.OPS.DropFolder -ODWDropFolder $cfgVersion.ODW.DropFolder -RoPEDropFolder $cfgVersion.RoPE.DropFolder -CopyES $installES `
                -CopyRoPE $installRoPE -CopyODW $installODW -CopyOPS $installOPS  -IsCI $IsCI
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
        #there are three possible places where installer can be placed
        if ($installES -eq $true){
            $t = Join-Path -Path $esInstallerPath -ChildPath $esExe
            $t2 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "ES\Install") -ChildPath $esExe
            $t3 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "ES") -ChildPath $esExe
            $t4 = Join-Path -Path $TempPath -ChildPath $esExe
            if ((Test-Path -Path $t) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Enterprise Server found" -ForegroundColor Yellow
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t2) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Enterprise Server found" -ForegroundColor Yellow
                 $esInstallerPath = (Join-Path -Path $tempPath -ChildPath "ES\Install")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t2) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t3) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Enterprise Server found" -ForegroundColor Yellow
                 $esInstallerPath = (Join-Path -Path $tempPath -ChildPath "ES")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t3) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t4) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Enterprise Server found" -ForegroundColor Yellow
                 $esInstallerPath = $tempPath
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t4) -ForegroundColor Yellow
            }
            else{
                Show-Info -IsCI $IsCI -Message "Installation file for Enterprise Server not found" -ForegroundColor Red
                break
            }
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
            $t = Join-Path -Path $odwInstallerPath -ChildPath $odwExe
            $t2 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "ODW\install") -ChildPath $odwExe
            $t3 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "ODW") -ChildPath $odwExe
            $t4 = Join-Path -Path $TempPath -ChildPath $odwExe
            if ((Test-Path -Path $t) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Data Warehouse found" -ForegroundColor Yellow
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t2) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Data Warehouse found" -ForegroundColor Yellow
                 $odwInstallerPath = (Join-Path -Path $tempPath -ChildPath "ODW\Install")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t2) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t3) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Data Warehouse found" -ForegroundColor Yellow
                 $odwInstallerPath = (Join-Path -Path $tempPath -ChildPath "ODW")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t3) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t4) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Data Warehouse found" -ForegroundColor Yellow
                 $odwInstallerPath = $tempPath
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t4) -ForegroundColor Yellow
            }
            else{
                Show-Info -IsCI $IsCI -Message "1Installation file for Omada Data Warehouse not found" -ForegroundColor Red
                break
            }
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
            $t = Join-Path -Path $ropeInstallerPath -ChildPath $RoPEexe
            $t2 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "RoPE\install") -ChildPath $RoPEexe
            $t3 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "RoPE") -ChildPath $RoPEexe
            $t4 = Join-Path -Path $TempPath -ChildPath $RoPEexe
            if ((Test-Path -Path $t) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Role and Policy Engine found" -ForegroundColor Yellow
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t2) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Role and Policy Engine found" -ForegroundColor Yellow
                 $ropeInstallerPath = (Join-Path -Path $tempPath -ChildPath "RoPE\Install")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t2) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t3) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Role and Policy Engine found" -ForegroundColor Yellow
                 $ropeInstallerPath = (Join-Path -Path $tempPath -ChildPath "RoPE")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t3) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t4) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Role and Policy Engine found" -ForegroundColor Yellow
                 $ropeInstallerPath = $tempPath
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t4) -ForegroundColor Yellow
            }
            else{
                Show-Info -IsCI $IsCI -Message "Installation file for Role and Policy Engine not found" -ForegroundColor Red
                break
            }
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
            $t = Join-Path -Path $opsInstallerPath -ChildPath $opsExe
            $t2 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "OPS\install") -ChildPath $opsExe
            $t3 = Join-Path -Path (Join-Path -Path $tempPath -ChildPath "OPS") -ChildPath $opsExe
            $t4 = Join-Path -Path $TempPath -ChildPath $opsExe
            if ((Test-Path -Path $t) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Provisioning Server found" -ForegroundColor Yellow
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t2) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Provisioning Server found" -ForegroundColor Yellow
                 $opsInstallerPath = (Join-Path -Path $tempPath -ChildPath "OPS\Install")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t2) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t3) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Provisioning Server found" -ForegroundColor Yellow
                 $opsInstallerPath = (Join-Path -Path $tempPath -ChildPath "OPS")
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t3) -ForegroundColor Yellow
            }
            elseif ((Test-Path -Path $t4) -eq $true){
                 Show-Info -IsCI $IsCI -Message "Installation file for Omada Provisioning Server found" -ForegroundColor Yellow
                 $opsInstallerPath = $tempPath
                 Show-Info -IsCI $IsCI -Message ("Installer was found here: {0}" -F $t4) -ForegroundColor Yellow
            }
            else{
                Show-Info -IsCI $IsCI -Message "Installation file for Omada Provisioning Server not found" -ForegroundColor Red
                break
            }
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
		else{
			Show-Info -IsCI $IsCI -Message "Cleaning log folder" -ForegroundColor Yellow
			$t = Get-Item -Path ("{0}\*" -f $logPath) | Remove-Item -Force -ErrorAction SilentlyContinue
		}

        Show-Info -IsCI $IsCI -Message "Installation files prepared" -ForegroundColor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName $_.InvocationInfo.InvocationName -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break
    }


	Show-Info -IsCI $IsCI -Message " 1.2. Checking versions of installers" -ForegroundColor Green

	$t = (Join-Path -path $odwinstallerPath -ChildPath $odwExe)
	$odwInstVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($t).FileVersion
	$t = (Join-Path -path $opsinstallerPath -ChildPath $opsExe)
	$opsInstVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($t).FileVersion
	$t = (Join-Path -path $ropeinstallerPath -ChildPath $ropeExe)
	$ropeInstVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($t).FileVersion
	try{
		if ($installES){
			$t = (Join-Path -path $esinstallerPath -ChildPath $esExe)
			$esMajor = $xmlcfg.SelectNodes("/Configuration/Version/OIS").Version.Split(".")[0]
			$esMinor = $xmlcfg.SelectNodes("/Configuration/Version/OIS").Version.Split(".")[1]
			$esInstVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($t).FileVersion
			if ($null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName})){
				$esMajor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName}).VersionMajor
				$esMinor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName}).VersionMinor
				$esBuild = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName}).DisplayVersion.Split(".")[2]
			}else{
				Show-Info -IsCI $IsCI -Message "ES installer or ES installed version not found" -ForegroundColor Red
				break
			}
		}
	}catch{
		Show-Info -IsCI $IsCI -Message "ES installer or ES installed version not found" -ForegroundColor Red
		break
	}
	try{
		if ($installODW){
			if ($remoteDB){
				$ScriptBlock = {
					$t = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like '*Omada*'} |  Select-Object DisplayVersion, DisplayName
					return $t
				}
				$t = Invoke-Command -ScriptBlock $ScriptBlock -ComputerName $SSISInstance -Credential $credDB
				if ($null -ne $t -and $t.DisplayName -eq $odwName){
					$odwMajor = $t.DisplayVersion.Split(".")[0]
					$odwMinor = $t.DisplayVersion.Split(".")[1]
					$odwBuild = $t.DisplayVersion.Split(".")[2]
				}
				else{
					Show-Info -IsCI $IsCI -Message ("ODW is not installed on {0}" -f $SSISInstance) -ForegroundColor Red
					break
				}
			}
			else{
				if ($null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $odwName})){
					$odwMajor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $odwName}).VersionMajor
					$odwMinor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $odwName}).VersionMinor
					$odwBuild = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $odwName}).DisplayVersion.Split(".")[2]
				}
				else{
					Show-Info -IsCI $IsCI -Message "ODW installer or ODW installed version not found" -ForegroundColor Red
					break
				}
			}
		}
	}catch{
		Show-Info -IsCI $IsCI -Message "ODW installer or ODW installed version not found" -ForegroundColor Red
		break
	}
	try{
		if ($installOPS){
			if ($null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $opsName})){
				$opsMajor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $opsName}).VersionMajor
				$opsMinor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $opsName}).VersionMinor
				$opsBuild = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $opsName}).DisplayVersion.Split(".")[2]
			}
			else{
				Show-Info -IsCI $IsCI -Message "OPS installer or OPS installed version not found" -ForegroundColor Red
				break
			}
		}
	}catch{
		Show-Info -IsCI $IsCI -Message "OPS installer or OPS installed version not found" -ForegroundColor Red
		break
	}
	try{
		if ($installRoPE){
			if( $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $ropeName})){
				$ropeMajor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $ropeName}).VersionMajor
				$ropeMinor = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $ropeName}).VersionMinor
				$ropeBuild = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $ropeName}).DisplayVersion.Split(".")[2]
			}
			else{
				Show-Info -IsCI $IsCI -Message "RoPE installer or RoPE installed version not found" -ForegroundColor Red
				break
			}
		}
	}catch{
		Show-Info -IsCI $IsCI -Message "RoPE installer or RoPE installed version not found" -ForegroundColor Red
		break
	}
	$stopInst = $false
	if ($installES){
		Show-Info -IsCI $IsCI -Message ("ES installer: {0}, installed version: {1}" -f $esInstVersion, ([string]$esMajor + "." + [string]$esMinor + "." + [string]$esBuild)) -ForegroundColor Yellow
		if ($esInstVersion.Split(".")[0] -lt $esMajor -or ($esInstVersion.Split(".")[0] -eq $esMajor -and $esInstVersion.Split(".")[1] -lt $esMinor) -or ($esInstVersion.Split(".")[0] -eq $esMajor -and ($esInstVersion.Split(".")[1] -eq $esMinor -and [int]$esInstVersion.Split(".")[2] -le [int]$esBuild))){
			Show-Info -IsCI $IsCI -Message "Installer is in the same version or in older than already installed version..." -ForegroundColor Red
			$stopInst = $true
		}
	}

	if ($installODW){
		Show-Info -IsCI $IsCI -Message ("ODW installer: {0}, installed version: {1}" -f $odwInstVersion, ([string]$odwMajor + "." + [string]$odwMinor + "." + [string]$odwBuild)) -ForegroundColor Yellow
		if ($odwInstVersion.Split(".")[0] -lt $odwMajor -or ($odwInstVersion.Split(".")[0] -eq $odwMajor -and $odwInstVersion.Split(".")[1] -lt $odwMinor) -or ($odwInstVersion.Split(".")[0] -eq $odwMajor -and ($odwInstVersion.Split(".")[1] -eq $odwMinor -and [int]$odwInstVersion.Split(".")[2] -le [int]$odwBuild))){
			Show-Info -IsCI $IsCI -Message "Installer is in the same version in older version than already installed version..." -ForegroundColor Red
			$stopInst = $true
		}
	}

	if ($installOPS){
		Show-Info -IsCI $IsCI -Message ("OPS installer: {0}, installed version: {1}" -f $opsInstVersion, ([string]$opsMajor + "." + [string]$opsMinor + "." + [string]$opsbuild)) -ForegroundColor Yellow
		if ($opsInstVersion.Split(".")[0] -lt $opsMajor -or ($opsInstVersion.Split(".")[0] -eq $opsMajor -and $opsInstVersion.Split(".")[1] -lt $opsMinor) -or ($opsInstVersion.Split(".")[0] -eq $opsMajor -and ($opsInstVersion.Split(".")[1] -eq $opsMinor -and [int]$opsInstVersion.Split(".")[2] -le [int]$opsBuild))){
			Show-Info -IsCI $IsCI -Message "Installer is in the same version in older version than already installed version..." -ForegroundColor Red
			$stopInst = $true
		}
	}

	if ($installRoPE){
		Show-Info -IsCI $IsCI -Message ("RoPE installer: {0}, installed version: {1}" -f $ropeInstVersion, ([string]$ropeMajor + "." + [string]$ropeMinor + "." + [string]$ropeBuild)) -ForegroundColor Yellow
		if ($ropeInstVersion.Split(".")[0] -lt $ropeMajor -or ($ropeInstVersion.Split(".")[0] -eq $ropeMajor -and $ropeInstVersion.Split(".")[1] -lt $ropeMinor) -or ($ropeInstVersion.Split(".")[0] -eq $ropeMajor -and ($ropeInstVersion.Split(".")[1] -eq $ropeMinor -and [int]$ropeInstVersion.Split(".")[2] -le [int]$ropeBuild))){
			Show-Info -IsCI $IsCI -Message "Installer is in the same version in older version than already installed version..." -ForegroundColor Red
			$stopInst = $true
		}
	}

	if ($stopInst){
		#break
	}

	#stop all services
	if ($installES){
		Stop-Service -Name $esTimerService -Force -ErrorAction SilentlyContinue
	}
	if ($installOPS){
		Stop-Service -Name $opsServiceName -Force -ErrorAction SilentlyContinue
	}
	if ($installRoPE){
		Stop-Service -Name $ropeServiceName -Force -ErrorAction SilentlyContinue
	}
	#backup all databases
	#fake xml to reuse existing script
	$xmlstring = ('<?xml version="1.0" encoding="utf-8"?>
<Configuration>
  <Version Type="LocalCopy">
    <MSSQL>
      <Server>{0}</Server>
      <Administrator>{1}</Administrator>
      <AdministratorPassword>{2}</AdministratorPassword>
    </MSSQL>
  </Version>
  <LocalConfiguration>
    <DBS>' -f $SQLInstance, $SQLAdmUser, $SQLAdmPass)

	if ($installES){
		$xmlString += ('<DB>
            <Omada>true</Omada>
            <Name>{0}</Name>
        </DB>
		<DB>
            <Omada>true</Omada>
            <Name>{1}</Name>
        </DB>
		<DB>
            <Omada>true</Omada>
            <Name>{2}</Name>
        </DB>' -f $cfgVersion.ES.DBName, $cfgVersion.ES.AuditDBName, $cfgVersion.ES.SourceSystemDBName)
	}
	if ($installODW){
		$xmlString += ('<DB>
            <Omada>true</Omada>
            <Name>{0}</Name>
        </DB>
		<DB>
            <Omada>true</Omada>
            <Name>{1}</Name>
        </DB>
		<DB>
            <Omada>true</Omada>
            <Name>{2}</Name>
        </DB>' -f $cfgVersion.ODW.ODWProductDatabase, $cfgVersion.ODW.ODWProductDatabaseStaging,$cfgVersion.ODW.ODWPRoductDatabaseMaster)
	}
	if ($installOPS){
		$xmlString += ('<DB>
            <Omada>true</Omada>
            <Name>{0}</Name>
        </DB>' -f $cfgVersion.OPS.DBName)
	}
	if ($installRoPE){
		$xmlString += ('<DB>
            <Omada>true</Omada>
            <Name>{0}</Name>
        </DB>' -f $cfgVersion.RoPE.RoPEProductDatabase)
	}

	$xmlstring += '</DBS>
   </LocalConfiguration>
</Configuration>'

	Show-Info -IsCI $IsCI -Message "1.3 Backup of databases before any change is done" -ForegroundColor Green
	#create a folder for DBs backups
    $ScriptBlock = {
        $backupPath = $args[0]
        if (!(Test-Path -Path $backupPath)){
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        }
    }
    if ($remoteDB){
        Invoke-Command -ComputerName $SQLInstanceWithout -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $backupPath
    }else{
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $backupPath
    }
	[xml]$xmlstring = $xmlstring
	Backup-Databases -BackupPath $backupPath -xml $xmlstring -IsCI $IsCI

	Show-Info -IsCI $IsCI -Message "1.4 Configuration of separate DB\SSIS server, if required" -ForegroundColor DarkGreen
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
            Copy-FilesToRemoteServers  -SSISInstance $SSISInstance -SQLInstanceWithout $SQLInstanceWithout -credDB $credDB -tempPath $tempPath -logPath $LogPath -scriptsPath $PSScriptRoot # -administratorDomain 'megamart' -administratorUser 'administrator'

            Show-Info -IsCI $IsCI -Message "Files copied" -ForegroundColor Green
        }
         Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
    }
    catch{
        Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "15" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
        break;
    }


	Show-Info -IsCI $IsCI -Message "Update preparations are finished" -ForegroundColor Green
    Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

	$values = ,("11", "0")
	$values += ,("11", "1")
	$values += ,("12", "0")
	$values += ,("12", "1")
	$values += ,("12", "2")
	$values += ,("12", "3")
	$values += ,("12", "4")
	$values += ,("12", "5")

	if ($installES){
		Show-Info -IsCI $IsCI -Message "2 Enterprise Server update" -ForegroundColor Green
		Show-Info -IsCI $IsCI -Message "2.1 Enterprise Server uninstallation" -ForegroundColor Green
		Uninstall-Software -ProductName $esName -IsCI $IsCI
		if (Test-Path -Path $esInstallationPath){
			Start-Sleep -s 15
			Remove-Item -Recurse -Force $esInstallationPath -ErrorAction SilentlyContinue
		}
		Show-Info -IsCI $IsCI -Message "Enterprise Server uninstalled" -ForegroundColor Green

		Show-Info -IsCI $IsCI -Message "2.2 Adding connection string to registry" -ForegroundColor Green
		try{

			$MSSQLSecurity = $xmlcfg.SelectNodes("/Configuration/Version/MSSQL/IntegratedSecurity")
			$ConnectionString = ("Data Source={0};Initial Catalog={1};" -F $SQLServer, $ESDBName)
			if ($MSSQLSecurity.Enabled -eq $true){
				Show-Info -IsCI $IsCI -Message "Integrated security will be used" -ForegroundColor Yellow
				$ConnectionString += "Integrated Security=SSPI;"
			}
			else{
				Show-Info -IsCI $IsCI -Message "Integrated security will NOT be used" -ForegroundColor Yellow
				$ConnectionString += ("User ID={0};Password={1};" -F $MSSQLSecurity.User, $MSSQLSecurity.Password)
			}

			$t = Push-ConnStringToRegistry -Action "Write" -MajorVersion $majorVersion -ConnectionString $ConnectionString -IsCI $IsCI
			Show-Info -IsCI $IsCI -Message "Connection string added" -ForegroundColor Yellow
		}
		catch{
			Show-Info -IsCI $IsCI -Message "Adding connection string failed, skipping" -ForegroundColor Yellow
		}

		Show-Info -IsCI $IsCI -Message "2.3 Enterprise Server installation" -ForegroundColor Green
            $args = ("/l*v \""{0}\installlog_es.log\""" -F $logPath)
            $args +=  " SERVICETYPE=\""2\"""
            $args +=  " SERVICEDOMAIN=\""$serviceUserDomain\"""
            $args +=  " SERVICEUSER=\""$serviceUser\"""
			$args +=  " SERVICEPASSWORD=\""$serviceUserPassword\"""
			$args +=  " INSTALLDIR=\""$esInstallationPath\"""
            $args +=  " ADDLOCAL=\""$esFeaturesToInstall\"""

			Show-Info -IsCI $IsCI -Message "Running installer..." -ForegroundColor Yellow
            $t = Start-Process -Wait -WorkingDirectory $esInstallerPath -FilePath $esExe -ArgumentList " /V""$args /qn"" " -PassThru -WindowStyle Hidden

			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_es.log" -f $esName, $logPath) -ForegroundColor Red
				break
			}

		Show-Info -IsCI $IsCI -Message "Enterprise Server installed" -ForegroundColor Green

		Show-Info -IsCI $IsCI -Message "2.4 Enterprise Server database update" -ForegroundColor Green

			$sqlFile1 = Join-Path -Path $esInstallationPath -ChildPath ("Sql scripts\dbup_VerMajor_VerMinor.sql")
			$sqlFile2 = Join-Path -Path $esInstallationPath -ChildPath ("Sql scripts\dbup_oim_VerMajor_VerMinor.sql")
			$updateDB = $false
			foreach($version in $values){
				if ($esMajor -le $version[0] -and ($esMajor -le $version[0] -and $esMinor -lt $version[1])){#remove older versions
					if ($esInstVersion.Split(".")[0] -ge $version[0] -and ($esInstVersion.Split(".")[0] -ge $version[0] -and $esInstVersion.Split(".")[1] -ge $version[1])){
						Show-Info -IsCI $IsCI -Message ("Upgrading Enterprise Server DB to version {0}.{1}" -f $version[0],$version[1]) -ForegroundColor Yellow
						$updateDB = $true

						$c1 = Get-Content -Encoding UTF8 -path $sqlFile1.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1]) -Raw
						$c2 = Get-Content -Encoding UTF8 -path $sqlFile2.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])  -Raw
						if ((Test-Path $sqlFile1.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])) -eq $true){

							if ($useSQLUser){
								Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c1
							}
							else{
								Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c1 #-inputfile $sqlFile
							}
						}
						else{
							Show-Info -IsCI $IsCI -Message ("SQL script is missing ({0}), aborting..." -f $sqlFile1.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])) -ForegroundColor Red
							throw
						}
						if ((Test-Path $sqlFile2.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])) -eq $true){

							if ($useSQLUser){
								Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c2
							}
							else{
								Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c2 #-inputfile $sqlFile
							}
						}
						else{
							Show-Info -IsCI $IsCI -Message ("SQL script is missing ({0}), aborting..." -f $sqlFile2.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])) -ForegroundColor Red
							throw
						}
						Start-Sleep -s 20
						#$sqlFile1.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])
						#$sqlFile2.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])
					}
				}
			}
			if (!$updateDB){
				Show-Info -IsCI $IsCI -Message "No need to update DB schema" -ForegroundColor Yellow
			}


	}

	if ($installODW){
		Show-Info -IsCI $IsCI -Message "3. Omada Data Warehouse update" -ForegroundColor Green

		$a = ("/qn /l*v \""{0}\installlog_odw.log\""" -F $logPath)

            $a +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            if ($useSQLUser){
                $a +=  " IS_SQLSERVER_AUTHENTICATION=\""2\"""
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
	        $a += (" LICENSEKEY=\""{0}\""" -F $cfgVersion.OIS.LicenseKey)

            Show-Info -IsCI $IsCI -Message "Omada Data Warehouse installation starting..." -ForegroundColor Yellow

			$ScriptBlock = {

                $f = Join-Path -Path $args[0] -ChildPath $args[1]

                Start-Process -Wait -FilePath $f -ArgumentList (" /s /V""{0} /qn"" " -F $args[2]) -PassThru | Out-Null  #-WorkingDirectory $args[0]
				if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $args[3]} )){
					Write-Host -Message ("{0} was not installed. Please check installation on {2} log for details - {1}\installlog_odw.log" -f $args[3], $logPath, $args[4]) -ForegroundColor Red
					break
				}

            }

            <#if (!$remoteDB){
				#(" /V""{0} /qn"" " -F $a)
				Show-Info -IsCI $IsCI -Message "Installation on local machine" -ForegroundColor Yellow
                $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, "local machine"
            }
            else{
                #ODW install on SSIS - in order to IS of OIS to work
				Show-Info -IsCI $IsCI -Message ("Installation on {0}" -F $SSISInstance) -ForegroundColor Yellow
                Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, $SSISInstance
                #ODW install on DB - in order to reports to work
				if (($SSISInstance -ne $SQLInstance)){# -and $isFullInstall
                    Show-Info -IsCI $IsCI -Message ("Installation on {0}" -F $SQLInstanceWithout) -ForegroundColor Yellow
					Invoke-Command -ComputerName $SQLInstanceWithout -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, $SQLInstanceWithout
                }
				if ($remoteDB -and $rsOnAppServer){
					Copy-ReportDefinition -SSISInstance $SSISInstance -SQLInstance $SQLInstance -SQLInstanceWithout $SQLInstanceWithout -odwInstallationPath $odwInstallationPath -credDB $credDB -scriptPath $PSScriptRoot -SSRSPath $ssrsPath -IsCI $IsCI
				}
            }#>
			if (!$remoteDB){
				Show-Info -IsCI $IsCI -Message "Installation on local machine" -ForegroundColor Yellow
                $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, "local machine", $odwInstallationPath
            }
            else{
                #ODW install on SSIS - in order to IS of OIS to work
				Show-Info -IsCI $IsCI -Message ("Installation on {0}" -F $SSISInstance) -ForegroundColor Yellow
                Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, $SSISInstance, $odwInstallationPath
            }
            if ($remoteDB -and $rsOnAppServer){
                Show-Info -IsCI $IsCI -Message ("Copying reports to {0}" -F $env:ComputerName) -ForegroundColor Yellow
                Copy-ReportDefinition -SSISInstance $SSISInstance -SQLInstance $SQLInstance -targetServer $env:ComputerName -odwInstallationPath $odwInstallationPath -credDB $credDB -scriptPath $PSScriptRoot -SSRSPath $ssrsPath -IsCI $IsCI
            }
            elseif ($remoteDB -and ($SSISInstance -ne $SQLInstance)){
                Show-Info -IsCI $IsCI -Message ("Copying reports to {0}" -F $SQLInstanceWithout) -ForegroundColor Yellow
                Copy-ReportDefinition -SSISInstance $SSISInstance -SQLInstance $SQLInstance -targetServer $SQLInstanceWithout -odwInstallationPath $odwInstallationPath -credDB $credDB -scriptPath $PSScriptRoot -SSRSPath $ssrsPath -IsCI $IsCI
            }

		}

		if ($installRoPE){
			Show-Info -IsCI $IsCI -Message "4 Role and Policy Engine update" -ForegroundColor Green
			#backup configuration files
			Show-Info -IsCI $IsCI -Message "4.1 Role and Policy Engine configuration files backup" -ForegroundColor Green
			$ropeBackup = Join-Path -Path $backupPath -ChildPath 'RoPEConfigurationFiles'
			if (Test-Path -Path $ropeBackup){
				Show-Info -IsCI $IsCI -Message "Cleaning all backup files..." -ForegroundColor Yellow
				$t = Remove-Item ('{0}\*' -f $ropeBackup) -Force
			}
			else{
				Show-Info -IsCI $IsCI -Message "Creating folder for backup files" -ForegroundColor Yellow
				$t = New-Item -Path $ropeBackup -ItemType Directory
			}
			Show-Info -IsCI $IsCI -Message "Backing up configuration files..." -ForegroundColor Yellow
			$ropePath = Join-Path -Path $ropeInstallationPath -ChildPath "Service\ConfigFiles"
			if (Test-Path -Path $ropePath){
				Copy-Item -Path ('{0}\*' -f $ropePath) -Destination $ropeBackup -Force
			}
			#uninstall
			Show-Info -IsCI $IsCI -Message "4.2 Role and Policy Engine uninstallation" -ForegroundColor Green
			Uninstall-Software -ProductName $ropeName -IsCI $IsCI
			if (Test-Path -Path $ropeInstallationPath){
				Remove-Item -Recurse -Force $ropeInstallationPath
			}
			#install
			Show-Info -IsCI $IsCI -Message "4.3 Role and Policy Engine installation" -ForegroundColor Green

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
			$args +=  " INSTALLDIR=\""$RoPEInstallationPath\"""
            $args += " CONNSTROISX=\""$ConnectionString\"""

            Show-Info -IsCI $IsCI -Message "Role and Policy Engine installation starting..." -ForegroundColor Yellow
            $t = Start-Process -Wait -WorkingDirectory $ropeInstallerPath -FilePath "$RoPEexe" -ArgumentList " /V""$args /qn"" " -PassThru
			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $ropeName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_es.log" -f $ropeName, $logPath) -ForegroundColor Red
				break
			}
			#run update script - C:\Program Files\Omada Identity Suite\Role and Policy Engine\Service\Support Files
			Show-Info -IsCI $IsCI -Message "4.4 Role and Policy Engine update script" -ForegroundColor Green
			$sqlFile = Join-Path -Path $ropeInstallationPath -ChildPath ("Support Files\UpdateDB_VerMajor_VerMinor.sql")
			$updateDB = $false
			foreach($version in $values){
				if ($ropeMajor -le $version[0] -and ($ropeMajor -le $version[0] -and $ropeMinor -lt $version[1])){#remove older versions
					if ($ropeInstVersion.Split(".")[0] -ge $version[0] -and ($ropeInstVersion.Split(".")[0] -ge $version[0] -and $ropeInstVersion.Split(".")[1] -ge $version[1])){
						Show-Info -IsCI $IsCI -Message ("Upgrading RoPE DB to version {0}.{1}" -f $version[0],$version[1]) -ForegroundColor Yellow
						$updateDB = $true
						$tp = $sqlFile.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])
						if ((Test-Path $tp) -eq $true){
							$q = Get-Content -Encoding UTF8 -path $tp -Raw
							if ($useSQLUser){
								Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $RoPEProductDB -QueryTimeout 300 -query $q
							}
							else{
								Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $RoPEProductDB -QueryTimeout 300 -query $q
							}
						}
						else{
							Show-Info -IsCI $IsCI -Message "SQL script is missing ($tp), aborting..." -ForegroundColor Red
							break
						}
						Start-Sleep -s 20
						#$sqlFile.Replace("VerMajor",$version[0]).Replace("VerMinor",$version[1])
					}
				}
			}
			if (!$updateDB){
				Show-Info -IsCI $IsCI -Message "No need to update DB schema" -ForegroundColor Yellow
			}
			#restore custom settings
            if ($enableCustomization -eq $true -and $demoEnabled){
			Show-Info -IsCI $IsCI -Message "4.5 Additional changes in RoPE configuration files" -ForegroundColor Green
			try{
						if ($null -ne $demoRoPEFiles ){
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
						    $t = $node2.ChildNodes | Where-Object{$_.key -eq $i[0] -and $_.value -eq $i[1] }
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
					Show-Info -IsCI $IsCI -Message $_.Exception.Message -ForegroundColor Red
					break
				}
			}
			else{
				Show-Info -IsCI $IsCI -Message "Customization is disabled, skipping" -ForegroundColor Yellow
			}
			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
		}

		 if ($installOPS){
			Show-Info -IsCI $IsCI -Message "5 Omada Provisioning Service update" -ForegroundColor Green
			#backup configuration files
			Show-Info -IsCI $IsCI -Message "5.1 Omada Provisioning Service uninstallation" -ForegroundColor Green

			Uninstall-Software -ProductName $opsName -IsCI $IsCI
			if (Test-Path -Path $opsInstallationPath){
				Remove-Item -Recurse -Force $opsInstallationPath
			}
			#install
			Show-Info -IsCI $IsCI -Message "5.2 Omada Provisioning Service installation" -ForegroundColor Green

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


            $t = Start-Process -Wait -WorkingDirectory $opsInstallerPath -FilePath $OPSexe -ArgumentList "/S /V""$args /qr"" " -PassThru

			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $opsName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_es.log" -f $opsName, $logPath) -ForegroundColor Red
				break
			}
			try{
            $u = (Get-CimInstance -ComputerName (Get-ADComputer -Filter 'OperatingSystem -like "Windows Server*"' | Select-Object -ExpandProperty Name) -Query "SELECT Name, StartName FROM Win32_Service WHERE Name = '$opsServiceName'" -ErrorAction SilentlyContinue).StartName
				if ($null -ne $u -and $u -eq 'LocalSystem'){
					$t = ('& sc.exe config "{0}" obj="{1}\{2}" password="{3}"' -F $opsServiceName, $serviceUserDomain, $serviceUser, $serviceUserPassword)
					 Invoke-Expression ($t)
				}
			}
			catch{
				Show-Info -IsCI $IsCI -Message ("Unable to check if {0} is run in the context of {1}, minor issue - installation will be continued" -f $opsServiceName, $serviceUser) -ForegroundColor Red
			}

			netsh http add urlacl url=http://+:8000/ProvisioningService/service/ user=$serviceUserDomain\$serviceUser >$null
            Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Start" -ErrorAction Stop

			if ($esThumbprint.Length -gt 0){
				Show-Info -IsCI $IsCI -Message "5.3 Change configuration of Omada Provisioning Service to use SSL" -ForegroundColor DarkGreen
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
					Show-Info -IsCI $IsCI -Message $_.Exception.Message -ForegroundColor Red
					break
				}
			}
			#check assemblies in ES and ROpe


			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
		}

		Show-Info -IsCI $IsCI -Message "6. Additional configuration" -ForegroundColor DarkGreen
		Show-Info -IsCI $IsCI -Message "6.1 Omada Data Warehouse reports upload" -ForegroundColor Green
        if ($uploadReports -eq $true){
            try{
                Publish-Reports -rsHttps $rsHttps -remoteDB $remoteDB -rsOnAppServer $rsOnAppServer -rsServer $rsServer -odwUploadReportsToolPath $odwUploadReportsToolPath -odwInstallationPath $odwInstallationPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName $SQLInstance -SQLInstanceWithout $SQLInstanceWithout -SSRSPath $SSRSPath -credDB $credDB -SkipErrors $skipReportErrors
                Show-Info -IsCI $IsCI -Message "Omada Data Warehouse reports configured" -ForegroundColor Green
                Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
            }
            catch{
                Show-Info -IsCI $IsCI -Message $_.Exception.Message -ForegroundColor Red
                break
            }
		}


		try{
            Show-Info -IsCI $IsCI -Message "6.2 Import survey(s)" -ForegroundColor Green
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
            Show-Info -IsCI $IsCI -Message $_.Exception.Message -ForegroundColor Red
            break
        }

	if ($null -ne $languageVersion){
		Try{
			Show-Info -IsCI $IsCI -Message "6.3 Installation of language pack" -ForegroundColor DarkGreen
			$packPath = Join-Path -Path $esInstallationPath -ChildPath (Join-Path -Path 'support files\Language Packs' -ChildPath $languageVersion)
			$l = ("{0}\changeset_{1}.log" -f $logPath, $languageVersion.Replace(".xml",""))

			if (Test-Path -Path $packPath){
				Import-ChangeSet -Customer omada -inputFile $packPath -logFile $l -ESProductInstallPath $esInstallationPath -ESServiceName $esTimerService -IsCI $IsCI
			}
			else{
				Show-Info -IsCI $IsCI -Message ("File {0} with language pack is missing, this is not a critical error, skipping..." -f $packPath) -ForegroundColor Red
			}
			Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
		}
		catch{
			Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "69" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI #as we run out of number - so we stay with 69
			break
		}
	}

		Show-Info -IsCI $IsCI -Message "6.4 Change start type of OIS services" -ForegroundColor Green
		try{
			if ($installRoPE -eq $true){
				Invoke-Expression -Command 'sc.exe \\localhost config "$ropeServiceName" start=delayed-auto' | Out-Null
			}
			if ($installES -eq $true){
				Invoke-Expression -Command 'sc.exe \\localhost config "$esTimerService" start=delayed-auto' | Out-Null
			}
			if ($installOPS -eq $true){
				Invoke-Expression -Command 'sc.exe \\localhost config "$opsServiceName" start=delayed-auto' | Out-Null
			}
			Show-Info -IsCI $IsCI -Message "Changed" -ForegroundColor Green
		}
        catch{
            Show-Info -IsCI $IsCI -ErrorMessage $_.Exception.Message -ForegroundColor Red
            break
		}

		if ($remoteDB -and !$SSISInstance.startswith($env:ComputerName)){
			Try{
				Show-Info -IsCI $IsCI -Message "6.5 Removal of network shares created during installation" -ForegroundColor DarkGreen
				$ScriptBlock = {
					Get-SmbShare -Name "OmadaInstall" | Remove-SmbShare -Confirm:$false
					Get-SmbShare -Name "OmadaLogs" | Remove-SmbShare -Confirm:$false
					Get-SmbShare -Name "OmadaScript" | Remove-SmbShare -Confirm:$false
				}
				Invoke-Command -ComputerName $SQLInstanceWithout -Credential $credDB -ScriptBlock $ScriptBlock
				if ($SQLInstanceWithout -ne $SSISInstance){
					Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock
				}

				Show-Info -IsCI $IsCI -Message "Shares removed" -ForegroundColor Green
				Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green
			}
			catch{
				 Show-Info -IsCI $IsCI -Message "No shares were removed, this is not a critical error" -ForegroundColor Red
			}
		}


		Show-Info -IsCI $IsCI -Message "6.6 Final systems restart" -ForegroundColor Yellow
		try{
			if ($installES -eq $true){
				Restart-Service -ServiceName ("*{0}*" -f $esTimerService) -Action "Restart" -ErrorAction Stop
				Start-Sleep -s 10
			}
			if ($installRoPE -eq $true){
				Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Restart" -ErrorAction Stop
			}
			if ($installOPS -eq $true){
				Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Restart" -ErrorAction Stop
			}

			Show-Info -IsCI $IsCI -Message "IIS restart" -ForegroundColor Yellow
			$t = invoke-command -scriptblock {iisreset}
		}
        catch{
            Show-Info -IsCI $IsCI -ErrorMessage $_.Exception.Message -ForegroundColor Red
            break
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
		if ($demoType -eq "Full"){
			Show-Info -IsCI $IsCI -Message ("Table (c) by Lars")

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