#removal of DBs during uninstall process in not prepared, do we need that?
#creation of DBs during install process in not prepared, however "leftovers" from previous installation are updated
#check if ES initial setup is needed when DBs were not deleted
#check if esSetSSRSPath is needed when DBs are not deleted

Function Invoke-OmadaUpgrade11 {

    <#
    .SYNOPSIS
        Triggers upgrade of Omada software installed on current machine
    .DESCRIPTION
        Triggers upgrade of Omada software installed on current machine...
    .PARAMETER Action
        What script should do - actions: Update, Uninstall, Install
    .PARAMETER IncludeDBs
        Remove\Include DBs in Uninstall\Install
    .PARAMETER ConnectionString
        Connection string to DB
    .PARAMETER Version
        Switch if newest or specific version should be used
    .PARAMETER ESVersion
        Version of Enterprise Server
    .PARAMETER ESDropFolder
        Location of ES drop folder
    .PARAMETER OPSVersion
        Version of Omada Provisioning Service
    .PARAMETER OPSDropFolder
        Location of OPS drop folder
    .PARAMETER ODWVersion
        Version of Data Warehouse
    .PARAMETER ODWDropFolder
        Location of ODW drop folder
    .PARAMETER RoPEVersion
        Version of Provisioning Engine
    .PARAMETER RoPEDropFolder
        Location of RoPE drop folder
    .PARAMETER SQLVersion
        Version of MS SQL installed on demo machine
    .PARAMETER SQLScriptPath
        Path to sql scripts
    .PARAMETER TempPath
        Path for temporary files

    .EXAMPLE
        Invoke-OmadaUpgrade11 -Action Update -Version Newest
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [ValidateSet("Update", "Uninstall", "Install")]
    [string]$Action,

    [bool]$IncludeDBs = $false,

    [Parameter (Mandatory)]
    [ValidateSet("Newest","Manual", "LocalCopy")]
    [string]$Version,

    [string]$ESVersion = '11.1.253',
    [string]$ESDropFolder = '\\OVMS09\drop\OE\OE11.1\rel',
    [string]$OPSVersion = '11.1.76',
    [string]$OPSDropFolder = '\\ovms09\drop\OPS\Rel\11.1',
    [string]$ODWVersion = '11.1.129',
    [string]$ODWDropFolder = '\\OVMS09\drop\common\ODW\Rel\v11.1',
    [string]$RoPEVersion = '11.1.120',
    [string]$RoPEDropFolder = '\\ovms09\drop\PolicyEngine\Rel\V11.1',

    [ValidateSet("2012", "2014")]
    [string]$SQLVersion = "2012",

    [string]$ConnectionString,
    [string]$SQLScriptPath = "C:\Powershell\DO-UpgradeTools\Private",
    [string]$TempPath = "c:\InstallTempFiles"
    )

    #set all variables
    $softMajorVersion = "11.1"
    $domain = $env:userdomain
    $databaseInstance = "localhost"
    $databaseUserId = "sa"
    $databasePassword = "Omada12345"

    $omadaServiceAccount = "srvc_omada"
    $omadaServicePassword = "Omada12345"

    $esFeaturesToInstall = "Omada_Enterprise,Omada_Identity_Manager,Tools"

    $ropeName = 'Omada Identity Suite Role and Policy Engine'
    $ropeServiceName = 'RoPE1.1'
    $opsName = "Omada Provisioning Service"
    $opsServiceName = "Omada ProvisioningService"
    $timerServiceName = "OETSVC111"
    $odwName = "Omada Identity Suite Data Warehouse"
    $esName = "Omada Identity Suite Enterprise Server"

    $esUrl = "http://enterpriseserver/"
    $esUserName = "Administrator"
    $esUserPassword = "Omada12345"

    $ropeProductDatabase = "RoPE"

    $opsProductDatabase = "ProvisioningService"

    $odwProductNameOISConnstr="Integrated Security=SSPI;Initial Catalog=OIS;Data Source=.;" #"?"

    $databaseSSISInstance = "localhost"#"WIN-T2I2IVSPT3T"
    $odwProductDatabase = "Omada Data Warehouse"
    $odwProductDatabaseMaster = "Omada Data Warehouse Master"
    $odwProductDatabaseStaging = "Omada Data Warehouse Staging"
    $odwConnstrOISX = "Integrated Security=SSPI;Initial Catalog=OIS;Data Source=.;"
    $odwProductInstallPath = "C:\Program Files\Omada Identity Suite\Datawarehouse"
    $odwConfigCommonConfiguration = "$odwProductInstallPath\Common\Omada ODW Configuration.dtsConfig"
    $odwConfigCommonImport = "$odwProductInstallPath\Common\Omada ODW Import.dtsConfig"
    $odwConfigCommonExport = "$odwProductInstallPath\Common\Omada ODW Export.dtsConfig"
    $odwConfigOISXExport = "$odwProductInstallPath\Source Systems\OIS-X\Omada ODW OISX Export.dtsConfig"
    $odwConfigAD = "$odwProductInstallPath\Source Systems\AD\Omada ODW AD.dtsConfig"
    $odwConfigLegacy = "$odwProductInstallPath\Source Systems\SQL\Omada ODW GenericDB.GWG_Legacy.dtsConfig"
    #$odwConfigOISX = "$odwProductInstallPath\Source Systems\OIS-X\Omada ODW OISX.dtsConfig"
    #$odwConfigOISXConnectionStrings = "$odwProductInstallPath\Source Systems\OIS-X\Omada ODW OISX ConnectionString.dtsConfig"

    $LDAPPath = "LDAP://Megamart.com/OU=Megamart,DC=Megamart,DC=com"
    $adUserName = "odwad\administrator"
    $adUserPassword = "###+Ssd95KnzbqMjj1hiJgEi5HqqgF6oQYuNBsGSQG97RU="

    $dtexecDir = Get-DtexecPath -SQLVersion $SQLVersion

    $licenseKey = "company=OIMDEMO;address1=Østerbrogade 135;address2=;address3=;contact=;exp_date=31122016;issue_date=07012016;lictype=1;usr_limit=0;id_limit=0;proctmpl_limit=0;modules=OMADADATAWAREHOUSE,ODWGENERIC,ODWSAP,SURVEY_MODULE,SOD_MODULE,AO_MODULE,SAP_MA,OIS,PASSWORDRESET,OPS,EXCHANGE;signature=KShD7BY6Kor0xaWqjSXAWECCpfw1MRl6+m3dG6ZiZ8+tW72RMEcc/A=="

    $ropeProductInstallPath = "C:\Program Files\Omada Identity Suite\Role and Policy Engine"
    $ropeConnStrFile = "$ropeProductInstallPath\Service\ConfigFiles\connectionStrings.config"
    $ropeAppSettingsFile = "$ropeProductInstallPath\Service\ConfigFiles\AppSettings.config"
    $ropeFileEngineConfiguration = "$ropeProductInstallPath\Service\ConfigFiles\EngineConfiguration.config"
    $RopeConnStrName = "OISXConnection"
    $ropeConnStrValue = "Integrated Security=SSPI;Initial Catalog=OIS;Data Source=.;"
    $ropeAppSettingsNode = "WebPortalUrl"
    $ropeAppSettingsValue = "http://enterpriseserver/main.aspx"
    $ropeDemoExtension = "Omada.OE.Custom.OIMDEMO.PolicyEngineExtension.PolicyEngineExtension, Omada.OE.Custom.OIMDEMO.PolicyEngineExtension"
    $pushServiceUrl = "http://enterpriseserver/WebService/OPSWebService.asmx?op=PushConfiguration"
    #?

    ###ES (restore connectionstring from registry)
    if ($ConnectionString -eq ''){
    Write-Host "Connection string was not provided, looking in registry.." -ForegroundColor Yellow

    $t = New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
    #$temp = ($ESVersion.Split(".",3) | Select -Index 0,1) -join "."
    $ConnectionString = (Get-ItemProperty -Path ("HKCR:\Software\Omada\Omada Enterprise\{0}" -F $softMajorVersion)).ConnStr
    Remove-PSDrive -Name HKCR
        if (($null -eq $ConnectionString) -or ($ConnectionString -eq '')){
            Write-Host "Connection string was Was not found in registry! Please provide one manually" -ForegroundColor Red
            break
        }
        else{
            Write-Host "Connection string found" -ForegroundColor Green
            Write-Host "Connection string: $ConnectionString" -ForegroundColor DarkYellow
        }
    }

    if (($Action -eq "Uninstall") -or ($Action -eq "Update")){
        Write-Host "Starting uninstall..." -ForegroundColor yellow

    ###stop services
    Write-Host "Stopping services..." -ForegroundColor yellow
    Restart-Service -ServiceName ("*{0}*" -f $timerServiceName) -Action "Stop"
    Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Stop"
    #sometimes this service doesn't stop
    try{
        Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Stop"
    }
    catch{
        $ServicePID = (Get-CimInstance win32_service | Where-Object { $_.name -eq $opsServiceName}).processID
        Stop-Process $ServicePID -Force
    }

    #wait couple of seconds so evething will stop...
    Write-Host "Waiting for all systems to be stopped..." -ForegroundColor Yellow
    Start-Sleep -s 15
    Write-Host "Resuming" -ForegroundColor Green

    ### uninstall ROPE

    Uninstall-Software -ProductName $ropeName

    ### uninstall OPS ($/CustomerProjects/Omada/Demo Image/Next Release/New Scripts/OPE.Reinstall.ps1)

    #OPS requires following services to stop: OETSVC111 (Timer service) and RoPE

    Uninstall-Software -ProductName $opsName

    #remove DB
    if ($IncludeDBs){
        #$\CustomerProjects\Omada\Demo Image\Next Release\New Scripts\OPE.Reinstall.ps1:38
    }

    ###uninstall ODW

    #uninstall
    Uninstall-Software -ProductName $odwName

    #removeDBs
    if ($IncludeDBs){
        #$\CustomerProjects\Omada\Demo Image\Next Release\New Scripts\ODW.Reinstall.ps1:19-21
    }

    ###uninstall ES

    #unistall
    Uninstall-Software -ProductName $esName

    #uninstall DBs
    if ($IncludeDBs){
        #some guide here: $\CustomerProjects\Omada\Demo Image\Next Release\New Scripts\ReinstallEverything.ps1:47-48
    }

    Write-Host "Uninstall finished" -ForegroundColor green
    }

    if (($Action -eq "Install") -or ($Action -eq "Update")){
        Write-Host "Starting install..." -ForegroundColor green

    $credential = Get-Credential -Message "Please provide user and password to Omada in order to check and download packages. Username: omada\xxx" -ErrorAction Stop

    ###Get latest version if $Version=Newest
    if ($Version -eq "Newest"){

        $ESVersion = Get-LatestSoftwareVersion -DropFolder $ESDropFolder -Credential $credential
        $ODWVersion = Get-LatestSoftwareVersion -DropFolder $ODWDropFolder -Credential $credential
        $RoPEVersion = Get-LatestSoftwareVersion -DropFolder $RoPEDropFolder -Credential $credential
        $OPSVersion = Get-LatestSoftwareVersion -DropFolder $OPSDropFolder -Credential $credential

        Write-Host ("Current version of Enterprise Server is {0}" -F $ESVersion) -ForegroundColor Green
        Write-Host ("Current version of Data Warehouse is {0}" -F $ODWVersion) -ForegroundColor Green
        Write-Host ("Current version of Role and Policy Engine is {0}" -F $OPSVersion) -ForegroundColor Green
        Write-Host ("Current version of Provision Service is {0}" -F $RoPEVersion) -ForegroundColor Green
        if (($null -eq $ESVersion) -or ($null -eq $OPSVersion) -or ($null -eq $ODWVersion) -or ($null -eq $RoPEVersion)){
            Write-Host "Not all product versions were found, please provide them manually" -ForegroundColor Red
            break
        }

        #leave just major and minor version
        #$result = ($result.Split(".",3) | Select -Index 0,1) -join "."

    }
    else{
        #verify versions
        if (($ESVersion -eq '') -or ($OPSVersion -eq '') -or ($ODWVersion -eq '') -or ($RoPEVersion -eq '')){
            Write-Host "Not all product versions were provided, please provide all and rerun this script" -ForegroundColor Red
            break
        }
    }


###install ES
    ###(restore connectiostring)
    Write-Host "Adding connection string to registry" -ForegroundColor Yellow
    $t = New-PSDrive -name HKCR -PSProvider Registry -root HKEY_LOCAL_MACHINE -ErrorAction SilentlyContinue
    if ((Test-Path "HKCR:\Software\Omada") -eq $false){
        New-Item -Path "HKCR:\Software" -Name "\Omada" -ErrorAction SilentlyContinue
    }
    if ((Test-Path "HKCR:\Software\Omada\Omada Enterprise") -eq $false){
        New-Item -Path "HKCR:\Software\Omada" -Name "\Omada Enterprise" -ErrorAction SilentlyContinue
    }
    $temp = (($ESVersion.Split(".",3) | Select-Object -Index 0,1) -join ".")
    if ((Test-Path ("HKCR:\Software\Omada\Omada Enterprise\{0}" -F $temp)) -eq $false){
        New-Item -Path "HKCR:\Software\Omada\Omada Enterprise" -Name (($ESVersion.Split(".",3) | Select-Object -Index 0,1) -join ".") -ErrorAction SilentlyContinue
    }
    Set-ItemProperty -Path ("HKCR:\Software\Omada\Omada Enterprise\{0}" -F (($ESVersion.Split(".",3) | Select-Object -Index 0,1) -join ".")) -Name ConnStr -Value $ConnectionString -ErrorAction SilentlyContinue
    Write-Host "Connection string added" -ForegroundColor green

    ###install

    if ($Version -ne "LocalCopy"){
        Write-Host "Use installation files from network share" -ForegroundColor Green
        #Use copy function
        $r = Copy-UpgradeFiles -Credential $credential -TempPath $TempPath -ESVersion $ESVersion -OPSVersion $OPSVersion -ODWVersion $ODWVersion -RoPEVersion $RoPEVersion -ESDropFolder $ESDropFolder -OPSDropFolder $OPSDropFolder -ODWDropFolder $ODWDropFolder -RoPEDropFolder $RoPEDropFolder
        if ($r){
            Write-Host "Files copied" -ForegroundColor Green
        }
        else{
            Write-Host "Some problem occured with connection to network share" -ForegroundColor Red
            break
        }


    }
    else{
           Write-Host "Use local copy of installation files" -ForegroundColor Green
    }

    Write-Host "Enterprise Server installation starting..." -ForegroundColor Yellow
    $args = ("/l*v {0}\installlog_es.log" -F $TempPath)
    $args +=  " SERVICETYPE=\""2\"""
    $args +=  " SERVICEDOMAIN=\""$domain\"""
    $args +=  " SERVICEUSER=\""$omadaServiceAccount\"""
    $args +=  " SERVICEPASSWORD=\""$omadaServicePassword\"""
    $args +=  " ADDLOCAL=\""$esFeaturesToInstall\"""

    $t = Start-Process -Wait -WorkingDirectory (Join-Path -Path $TempPath -ChildPath "ES\install") -FilePath "OIS Enterprise Server.exe" -ArgumentList " /V""$args /qr"" " -PassThru

    ###start website in order to "refresh" some date in DB
    Start-WebSite -Url $esUrl -User $esUserName -Password $esUserPassword -Domain $domain

    if ($IncludeDBs){
        #$\CustomerProjects\Omada\Demo Image\Next Release\New Scripts\ReinstallEverything.ps1:446-447
    }

    Write-Host "Enterprise Server installed" -ForegroundColor Green

    ###!order based on $\CustomerProjects\Omada\Demo Image\Next Release\New Scripts\ReinstallEverything.ps1

    ###Install rope

    Write-Host "Role and Policy Engine installation starting..." -foregroundcolor yellow


    $args = ("/l*v {0}\installlog_rope.log" -F $TempPath)
    $args +=  " IS_SQLSERVER_SERVER=\""$databaseInstance\"""
    $args += " IS_SQLSERVER_DATABASE=\""$ropeProductDatabase\"""
    $args += " SERVICETYPE=\""2\"""
    $args += " SERVICEDOMAIN=\""$domain\"""
    $args += " SERVICEUSER=\""$omadaServiceAccount\"""
    $args += " SERVICEPASSWORD=\""$omadaServicePAssword\"""

    $t = Start-Process -Wait -WorkingDirectory (Join-Path -Path $TempPath -ChildPath "RoPE\install\RoPE") -FilePath "OIS Role and Policy Engine.exe" -ArgumentList "/S /V""$args /qr"" " -PassThru
    Write-Host "Role and Policy Engine installed" -ForegroundColor Green

    ###Install OPS

    Write-Host "Omada Provisioning Service installation starting..." -foregroundcolor yellow

    $args = ("/l*v {0}\installlog_ops.log" -F $TempPath)
    $args += " IS_SQLSERVER_SERVER=\""$databaseInstance\"""
    $args += " IS_SQLSERVER_DATABASE=\""$opsProductDatabase\"""
    $args += " SERVICETYPE=\""2\"""
    $args += " SERVICEDOMAIN=\""$domain\"""
    $args += " SERVICEUSER=\""$omadaServiceAccount\"""
    $args += " SERVICEPASSWORD=\""$omadaServicePAssword\"""
    #$args += " ADDLOCAL=\""$opsFeaturesToInstall\"""
    $args += " OISXCONN=\""$odwProductNameOISConnstr\"""

    $t = Start-Process -Wait -WorkingDirectory (Join-Path -Path $TempPath -ChildPath "OPS\install\Default Configuration\Release\DiskImages\DISK1") -FilePath "Omada Provisioning Service.exe" -ArgumentList "/S /V""$args /qr"" " -PassThru
    Write-Host "Omada Provisioning Service installed" -ForegroundColor Green

    ###esSetSSRSPath

    ###esStartTimerService
    Restart-Service -ServiceName ("*{0}*" -f $timerServiceName) -Action "Start"
    Set-Service -Name ("*{0}*" -f $timerServiceName) -StartupType Automatic

    ###Install ODW

        Write-Host "Omada Data Warehouse installation starting..." -foregroundcolor yellow

    $args = ("/l*v {0}\installlog_odw.log" -F $TempPath)

    $args +=  " IS_SQLSERVER_SERVER=\""$databaseInstance\"""
    $args +=  " IS_SQLSERVER_AUTHENTICATION=\""2\"""
    $args +=  " IS_SQLSERVER_USER=\""$databaseUserId\"""
    $args +=  " IS_SQLSERVER_PASSWORD=\""$databasePassword\"""

    $args +=  " SSISSERVER=\""$databaseSSISInstance\"""

    $args += " IS_SQLSERVER_DATABASE=\""$odwProductDatabase\"""
    $args += " ODWSTAGINGDB=\""$odwProductDatabaseStaging\"""
    $args += " ODWMASTER=\""$odwProductDatabaseMaster\"""
    $args += " CONNSTROISX=\""$odwConnstrOISX\"""
	$args += " LICENSEKEY=\""$licenseKey\"""

    $t = Start-Process -Wait -WorkingDirectory (Join-Path -Path $TempPath -ChildPath "ODW\install\SQL$sqlVersion") -FilePath "Omada Data Warehouse.x64 SQL $sqlVersion.exe" -ArgumentList "/S /V""$args /qr"" " -PassThru
    Write-Host "Omada Data Warehouse installed" -ForegroundColor Green

    ###RunConfigPackage $PSScriptRoot

    Write-Host "Running configuration package" -ForegroundColor Yellow
    $args = "/DTS ""\MSDB\Omada\ODW\Omada ODW Configuration"" /SERVER ""."" /DECRYPT OmadaEncryptionKey /CHECKPOINTING OFF  /REPORTING E" # E shows error, V shows verbose log
    $t = Start-Process -Wait -WorkingDirectory $dtexecDir -FilePath dtexec.exe -ArgumentList $args -PassThru
    Write-Host "Configuration package applied" -ForegroundColor Green

    ###ODWSetup

    Write-Host "Configuring Omada Data Warehouse" -foregroundcolor yellow;

    Run-SqlFromFile $databaseUserId $databasePassword $databaseInstance "master" (Join-Path -Path $SQLScriptPath -ChildPath "ODW\setupReports.sql")

        Write-Host "Setting values in xml files" -ForegroundColor Yellow
        ## Common
        Set-XMLValue -XMLFile $odwConfigCommonConfiguration -XMLNode "GenericDB::ListOfSourceSystemNames" -NewValue "HR,GWG_Legacy"
        Set-XMLValue -XMLFile $odwConfigCommonImport -XMLNode "User::ImportSourceSystemNames" -NewValue "HR,OIS-X,AD,GWG_Legacy";

        ## Export
        Set-XMLValue -XMLFile $odwConfigCommonExport -XMLNode "User::ExportSystemNames" -NewValue "OISX";
        Set-XMLValue -XMLFile $odwConfigOISXExport -XMLNode "User::ExportSourceSystemNames" -NewValue "AD,GWG_Legacy";
        Set-XMLValue -XMLFile $odwConfigOISXExport -XMLNode "User::WebServiceURL" -NewValue "http://enterpriseserver/webservice/dataobjectexchangewebservice.asmx";
        Set-XMLValue -XMLFile $odwConfigOISXExport -XMLNode "User::UseDefaultCredentials" -NewValue "True"

        Write-Host "Setting license key" -ForegroundColor Yellow
        $query = "USE [$odwProductDatabase]; UPDATE [tblApplicationSetting] set [ValueStr] = '$licenseKey' WHERE [Key] = 'licenseString';"
        Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query $query
        Write-Host "License key updated" -ForegroundColor Green

        ##Setup AD
        Set-XMLValue -XMLFile $odwConfigAD -XMLNode "User::UserExtensionFieldsWithHistory" -NewValue "Mail";
        #Set-XMLValue -XMLFile $odwConfigAD -XMLNode "User::EnableExactJoin" -NewValue "False";
        #Set-XMLValue -XMLFile $odwConfigAD -XMLNode "User::CustomJoinPackage" -NewValue "Omada ODW Custom Join";
        #Set-XMLValue -XMLFile $odwConfigAD -XMLNode "User::FuzzyJoinSimilarityThreshold" -NewValue "0.7";
        #Set-XMLValue -XMLFile $odwConfigAD -XMLNode "User::FuzzyJoinConfidenceThreshold" -NewValue "0.9";
        #Set-XMLValue -XMLFile $odwConfigAD -XMLNode "User::EnableFuzzyJoin" -NewValue "False"; ##custom join package will piggy bag on the above variables, but product fuzzy join must be disabled

        ##Setup legacy
        Set-XMLValue -XMLFile $odwConfigLegacy -XMLNode="User::EnableExactJoin" -NewValue "True"
        Set-XMLValue -XMLFile $odwConfigLegacy -XMLNode="User::CustomJoinPackage" -NewValue "Omada ODW GWG Custom Join ADM_";
        Set-XMLValue -XMLFile $odwConfigLegacy -XMLNode="User::FuzzyJoinSimilarityThreshold" -NewValue "0.7";
        Set-XMLValue -XMLFile $odwConfigLegacy -XMLNode="User::FuzzyJoinConfidenceThreshold" -NewValue "0.9";
        Set-XMLValue -XMLFile $odwConfigLegacy -XMLNode="User::EnableFuzzyJoin" -NewValue "True";
        #FlushLDAPPaths
        $query = "USE [$odwProductDatabaseStaging];Declare @no int; select @no=count(*) from AD.LDAP where LDAPPath=N'$LDAPPath'; if @no=0 begin EXEC [dbo].[InsertADLDAP] @LDAPPath = N'$LDAPPath', @UserName = N'$adUserName', @EncryptedPassword = N'$adUserPassword'; end;"
        Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query $query

        Write-Host "Omada Data Warehouse configured" -ForegroundColor Green

    ###SetupRoPE

    Write-Host "Configuring Role and Policy Engine" -ForegroundColor Yellow
    Set-XMLValue -XMLFile $ropeConnStrFile -XMLNode $RopeConnStrName -NewValue $ropeConnStrValue -Action "ConnectionString"
    Add-XMLNode -XMLFile  $ropeFileEngineConfiguration -XMLParentNode "//extensions" -ParentElementName "add" -KeyAttribute "type" -KeyValue $ropeDemoExtension
    Set-XMLValue -XMLFile $ropeAppSettingsFile -XMLNode $ropeAppSettingsNode -NewValue $ropeAppSettingsValue -Action "Key"

    Write-Host "Creating users in DBs" -ForegroundColor Yellow
    Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query "USE [$ropeProductDatabase];Declare @no int; SELECT @no=COUNT(*) FROM sys.database_principals WHERE name = 'megamart\srvc_omada'; if @no=0 begin CREATE USER [megamart\$omadaServiceAccount] FOR LOGIN [megamart\$omadaServiceAccount]; end;"
    Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query "USE [$ropeProductDatabase];ALTER ROLE [db_owner] ADD MEMBER [megamart\$omadaServiceAccount];"

    Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query "USE [$odwProductDatabase];Declare @no int; SELECT @no=COUNT(*) FROM sys.database_principals WHERE name = 'megamart\srvc_omada'; if @no=0 begin CREATE USER [megamart\$omadaServiceAccount] FOR LOGIN [megamart\$omadaServiceAccount];end;"
    Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query "USE [$odwProductDatabase];ALTER ROLE [db_datareader] ADD MEMBER [megamart\$omadaServiceAccount];"

    Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query "USE [$odwProductDatabaseMaster];Declare @no int; SELECT @no=COUNT(*) FROM sys.database_principals WHERE name = 'megamart\srvc_omada'; if @no=0 begin CREATE USER [megamart\$omadaServiceAccount] FOR LOGIN [megamart\$omadaServiceAccount];end;"
    Invoke-Sqlcmd -Username $databaseUserId -Password $databasePassword -ServerInstance $databaseInstance -Query "USE [$odwProductDatabaseMaster];ALTER ROLE [db_owner] ADD MEMBER [megamart\$omadaServiceAccount];"

    Write-Host "Role and Policy Engine configured" -ForegroundColor Green

    ###RunConfigPackage $PSScriptRoot
    Write-Host "Running configuration package (second run)" -ForegroundColor Yellow
    $args = "/DTS ""\MSDB\Omada\ODW\Omada ODW Configuration"" /SERVER ""."" /DECRYPT OmadaEncryptionKey /CHECKPOINTING OFF  /REPORTING E" # E shows error, V shows verbose log
    $t = Start-Process -Wait -WorkingDirectory $dtexecDir -FilePath dtexec.exe -ArgumentList $args -PassThru
    Write-Host "Configuration package applied (second run)" -ForegroundColor Green

    Write-Host "Starting services" -ForegroundColor Yellow
    Restart-Service -ServiceName ("*{0}*" -f $ropeServiceName) -Action "Start"
    Restart-Service -ServiceName ("*{0}*" -f $opsServiceName) -Action "Start"
    Set-Service -Name ("*{0}*" -f $ropeServiceName) -StartupType Automatic
    Set-Service -Name ("*{0}*" -f $opsServiceName) -StartupType Automatic
    Write-Host "Services started" -ForegroundColor Green

    ###pushing configuration

    Write-Host "Pushing Role and Policy Engine configuration..." -ForegroundColor Yellow
    $secstr = New-Object -TypeName System.Security.SecureString
    $esUserPassword.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $esUserName, $secstr
    $ws = New-WebServiceProxy -uri $pushServiceUrl -Credential $cred
    $t = $ws.PushConfiguration()
    Write-Host "Configuration pushed: $t" -ForegroundColor Green


    #delete installation files

    if ((Test-Path $TempPath) -and ($Version -ne "LocalCopy")){
        Write-Host "Removing installation files..." -ForegroundColor Yellow
        Get-ChildItem -Path $TempPath -Recurse | Remove-Item -force -recurse
        Remove-Item $TempPath -Force
        Write-Host "Files removed" -ForegroundColor Green
    }

    #finish
    c:
    Write-Host "Install completed" -ForegroundColor green

    }

 }