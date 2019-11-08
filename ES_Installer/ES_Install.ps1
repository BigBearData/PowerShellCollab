Add-Type -AssemblyName PresentationFramework

##################################################
##FUNCTIONS###############################################
	Function Get-FileName($initialDirectory)
	{   
		 [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

		 $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
		 #$OpenFileDialog.Description = "Select the ODW Installation File." #does not work.
		 $OpenFileDialog.initialDirectory = $initialDirectory
		 $OpenFileDialog.filter = "All files (*.*)| *.*"
		 $OpenFileDialog.ShowDialog() | Out-Null
		 $OpenFileDialog.filename
	} #end function Get-FileName
	

 	 Function Get-Folder($initialDirectory, $Description){
		[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null

		$foldername = New-Object System.Windows.Forms.FolderBrowserDialog
		$foldername.Description = $Description #"Select the ODW Installation File." #$Description
		$foldername.rootfolder = "MyComputer"
		$foldername.SelectedPath = $initialDirectory

		if($foldername.ShowDialog() -eq "OK")
		{
			$Folder += $foldername.SelectedPath
		}
		return $Folder
	} #end function Get-Folder
	
Function Add-UserToDatabase {

    <#
    .SYNOPSIS
        Adds user to DB
    .DESCRIPTION
        Adds user to role in DB
    .PARAMETER User
        DB user name
    .PARAMETER Role
        Name of role
    .PARAMETER Instance
        Instance of DB server
    .PARAMETER DBName
        Name of DB
    .PARAMETER IsCI
        If this a manual install or CI triggered
		
    .EXAMPLE
        Add-UserToDatabase -DBLogin 'megamart\srvc_omada' -Instance "." -DBName "testDB" -Role "db_owner -User sa -Password "Omada12345"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$User,

    [Parameter (Mandatory)]
    [string]$Password,

    [Parameter (Mandatory)]
    [string]$Role,

    [Parameter (Mandatory)]
    [string]$Instance,

    [Parameter (Mandatory)]
    [string]$DBName,

    [Parameter (Mandatory)]
    [string]$DBLogin, 

    [Parameter ()]
    [bool]$useSQLUser = $false,
    
	[Boolean]$IsCI = $false

    )

        $RoPE_Install_Output.text += ("Adding {0} as {1} to {2}`r`n" -F $DBLogin,$Role, $DBName)

        $c = "

        USE [$DBName]
        GO
        IF NOT EXISTS 
            (SELECT name  
            FROM master.sys.server_principals
            WHERE name = '$DBLogin')
        BEGIN
            CREATE LOGIN [$DBLogin] FROM WINDOWS WITH DEFAULT_LANGUAGE=[us_english]
        END
        
		BEGIN TRY 
			IF EXISTS 
				(SELECT name 
				FROM sys.database_principals
				WHERE name = '$DBLogin')
			BEGIN
				DROP USER [$DBLogin] 
				;
			END
        END TRY  
		BEGIN CATCH 
			print 'error'
		END CATCH


        IF NOT EXISTS 
            (SELECT name 
            FROM sys.database_principals
            WHERE name = '$DBLogin')
        BEGIN
            CREATE USER [$DBLogin] FOR LOGIN [$DBLogin]
            ;
            ALTER ROLE [db_owner] ADD MEMBER [$DBLogin]
            ;
        END
        
        "    
        if ($useSQLUser){
            Invoke-Sqlcmd -Username $User -Password $Password -ServerInstance $Instance -Query $c
        }
        else{
            Invoke-Sqlcmd -ServerInstance $Instance -Query $c
        }

    $RoPE_Install_Output.text += ("Finished adding {0}`r`n" -F $DBLogin) 
} #end of function Add-UserToDatabase

Function Create-Database { 
param(
	[Parameter(Mandatory)]
	[string]$ServerName,

	[Parameter(Mandatory)]
	[string]$DatabaseName
)
$srv=$ServerName
$DbName=$DatabaseName

If ( ! (Get-module SqlServer ) -And !(Get-Module SqlPS)) {
Import-Module .\SqlServer\21.1.18080\SqlServer.psm1
}

$DbExists=Test-SqlConnection -sqlServer $srv -DBName $DbName
#$ES_Install_Output.text += $DbExists
##this could also be done before calling the Create-Database function NB!
	If ($DbExists -eq $true){
		$ES_Install_Output.text += "The Database $DbName on $srv already exists`r`n"
	}
	else {
		$db = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Database -argumentlist $srv, $DbName  
		$db.Create() 


				$c = "
				USE [$DBName]
				declare @dbname varchar(256)
				declare @sql nvarchar(256)
				select @dbname=db_name(dbid) from master..sysprocesses where spid=@@SPID
				set @sql = 'ALTER DATABASE [' + @dbname + '] SET ALLOW_SNAPSHOT_ISOLATION ON'
				exec sp_executesql @sql
				set @sql = 'ALTER DATABASE [' + @dbname + '] SET READ_COMMITTED_SNAPSHOT ON'
				exec sp_executesql @sql
				;
					
			   "

		Invoke-Sqlcmd -ServerInstance $srv -Query $c
	}
}#end of function create_database

function Set-ServicesStartAndDependency{
    <#
    .SYNOPSIS
        Set similar services start type and dependencies.
    .DESCRIPTION
        Show error information and save step in which error did happen
    .PARAMETER ServiceName
        Service name on which should changes be made
    .PARAMETER StartType
        Start type that will be passed to sc command [eq. delayed-auto] 
    .PARAMETER Dependencies
        Services names from which the service will be dependend 
    .EXAMPLE
       Set-ServicesStartAndDependency -ServiceName RoPE -StartType delayed-auto -Dependencies MSSQLSERVER
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$ServiceName,
        [String]$StartType = 'delayed-auto',
        [String[]]$Dependencies
    )

    $dependenciesFormat = "{0}/{1}"
    $initDependencies = $null

    foreach ($dependency in $Dependencies){
        if(Get-WmiObject -Class Win32_Service -Filter "Name='$dependency'"){
            if($null -eq $initDependencies){
                $initDependencies = $dependency
            } else {
                $initDependencies = $dependenciesFormat -f $initDependencies, $dependency
            }
        }
    }

    $services = Get-Service -ServiceName ("*{0}*" -f $ServiceName)

    $services | ForEach-Object {
        $dependentServices = $initDependencies

        $_.RequiredServices | ForEach-Object {
            if($null -eq $dependentServices){
                $dependentServices = $_.Name    
            }
            elseif($dependentServices -notcontains $_){
                $dependentServices = $dependenciesFormat -f $dependentServices, $_.Name                   
            }
        }
        
        $dependencyParam = ""
        if($null -ne $dependentServices) {
            $dependencyParam = "depend={0}" -f $dependentServices
        }

        Invoke-Expression -Command ("sc.exe \\localhost config `"{0}`" start={1} {2}" -f $_.Name, $StartType, $dependencyParam) | Out-Null
    }
}

Function Test-SqlConnection([string]$sqlServer, [string]$DBName)
{
 $exists = $FALSE
 try
 {
  $conn = New-Object system.Data.SqlClient.SqlConnection
  $conn.connectionstring = [string]::format("Server={0};Database={1};Integrated Security=SSPI;",$sqlServer,$DBName)
  $conn.open()
  $exists = $true
 }
 catch
 {
  #Write-Error "Failed to connect to DB $DBNAME on $sqlServer"
  #$ES_Install_Output.text += "The Database $DBNAME on $sqlServer already exists`r`n"
 }
 
 Return $exists
}

#READ THE XAML FILE
[xml]$Form = Get-Content ".\ES_Install.xaml"
$NR = (New-Object System.Xml.XmlNodeReader $Form)

try{
    #$Form=[Windows.Markup.XamlReader]::Load( $reader )
	$Win = [Windows.Markup.XamlReader]::Load($NR)
}
catch{
    Write-Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged or TextChanged properties in your textboxes (PowerShell cannot process them)"
    throw
}

<# If (!(Get-module OISEssential)) {
Import-Module OISEssential
} #>

#VARIABLES AND DEFINITIONS

#RoPE Variables###################################################
$RoPE_ServerName = $Win.FindName("RoPE_ServerName")
$RoPE_ServiceAccount = $Win.FindName("RoPE_ServiceAccount")
$MSSQL_ServerName = $Win.FindName("MSSQL_ServerName")
$But_RoPE_Install = $Win.FindName("But_RoPE_Install")
$RoPE_DBName = $Win.FindName("RoPE_DBName")
$RoPE_ServicePassword = $Win.FindName("RoPE_ServicePassword")
$RoPE_Install_Output = $Win.FindName("RoPE_Install_Output")
$RoPE_InstDir = $Win.FindName("RoPE_InstDir")

$RoPE_ServerName.text = $Env:Computername

#ES Variables########################################################
$ES_ServerName = $Win.FindName("ES_ServerName")
$ES_ServiceAccount = $Win.FindName("ES_ServiceAccount")
$ES_MSSQL_ServerName = $Win.FindName("ES_MSSQL_ServerName")
$But_ES_Install = $Win.FindName("But_ES_Install")
$ES_DBName = $Win.FindName("ES_DBName")
$ES_ServicePassword = $Win.FindName("ES_ServicePassword")
$ES_Install_Output = $Win.FindName("ES_Install_Output")
$ES_InstDir = $Win.FindName("ES_InstDir")

$ES_ServerName.text = $Env:Computername

################################################

##INSTALL Enterprise Server#################################
$But_ES_Install.Add_Click({
	#From Form
	$ESServer = $ES_ServerName.Text
	$ESEUser = $ES_ServiceAccount.Text
	$MSSQLServerName = $ES_MSSQL_ServerName.Text
	$MSSQL_ServerName.Text=$MSSQLServerName ####DO THE SAME FOR OPS!!!
	$ESEUser = $ES_ServiceAccount.Text
	$esDBName = $ES_DBName.Text
	$ESPassword = $ES_ServicePassword.Text
	$ES_ServicePassword.Text = " "
	$ESInstallationPath = $ES_InstDir.Text
	
	#Constants
	$SQLInstance = $MSSQLServerName
	$serviceUserDomain=$env:UserDomain
	$ConnectionString = "Initial Catalog ="+$esDBName+";Integrated Security=SSPI;Data Source="+$MSSQLServerName+";"
	$serviceUser=$ESEUser
	$serviceUserPassword=$ESPassword
	$ESServiceName=""#"ROPE_0"
	$ESDBUser=$serviceUser
	$ESProductDB=$esDBName
	$SQLAdmUser = 'unknown'
	$SQLAdmPass = '404'
	$esSourceSystemDBName="Omada Source System Data DB"
	$esAuditDBName="OISAudit"
	
	#Process:
	#
            #Show-Info -IsCI $IsCI -Message "2.1 Enterprise Server installation" -ForegroundColor DarkGreen
			$ES_Install_Output.text += "***2.1 Enterprise Server installation***`r`n" 

	####Prep#########
	[System.Windows.MessageBox]::Show("Please select the relevant intallation file for Enterprise Server `r`nExample: C:\Omada\Install\OIS Enterprise Server.exe ", "Select ES Install File")
	$ESInstallPath=Get-FileName -initialDirectory "C:\Omada\Install\"
	$InstallerFolder = Split-Path -Path $ESInstallPath
	$sqlFilePath = Join-Path -Path $ESInstallationPath -ChildPath "\Sql scripts\"
	#$ES_Install_Output.text += $sqlFilePath
	$sqlFile_OIS_dbcr=Join-Path -Path $sqlFilePath -ChildPath "dbcr_14_0.sql"
	$sqlFile_OIS_dbcr_oim=Join-Path -Path $sqlFilePath -ChildPath "dbcr_oim_14_0.sql"
	$sqlFile_OIS_SourceSystemDB=Join-Path -Path $sqlFilePath -ChildPath "CreateSourceSystemDataDB.sql"
	$ESEexe=""
 	$RootInstallerFolder = Split-Path -Path $InstallerFolder
	$logPath = Join-Path -Path $RootInstallerFolder -ChildPath "\Logs"
	$PSCommandPath = Join-Path -Path $RootInstallerFolder -ChildPath "\DO-UpgradeTools"
	#$ES_Install_Output.text += $PSCommandPath
	
	$esFeaturesToInstall="Omada_Enterprise,Omada_Identity_Manager,Tools"
	
            $args = ("/l*v \""{0}\installlog_es.log\""" -F $logPath)
            $args +=  " SERVICETYPE=\""2\"""
            $args +=  " SERVICEDOMAIN=\""$serviceUserDomain\"""
            $args +=  " SERVICEUSER=\""$serviceUser\"""
            $args +=  " SERVICEPASSWORD=\""$serviceUserPassword\"""
            $args +=  " INSTALLDIR=\""$esInstallationPath\"""
            $args +=  " ADDLOCAL=\""$esFeaturesToInstall\"""
		#$ES_Install_Output.text += $args
		#minimum .Net 4.6.1!!!!
			#$t = Start-Process -Wait -FilePath "$RoPEInstallPath" -ArgumentList " /V""$args /qn"" " -PassThru
            #$t = Start-Process -Wait -WorkingDirectory $esInstallerPath -FilePath $esExe -ArgumentList " /V""$args /qn"" " -PassThru -WindowStyle Hidden
			$t = Start-Process -Wait -FilePath $ESInstallPath -ArgumentList " /V""$args /qn"" " -PassThru -WindowStyle Hidden

<# 			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_es.log" -f $esName, $logPath) -ForegroundColor Red
				break
			} #>
	#Create databases
	        $ES_Install_Output.text +="Creating DB {0}...`r`n" -F $esDBName
            #Show-Info -IsCI $IsCI -Message ("main script: Use SQL user: {0} {1}" -F $useSQLUser, $SQLAdmUser)
            Create-Database -ServerName $SQLInstance -DatabaseName $esDBName #-SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

            $ES_Install_Output.text += "Creating Source System Data DB...`r`n" 
            Create-Database -ServerName $SQLInstance -DatabaseName $esSourceSystemDBName #-SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI

            $ES_Install_Output.text += "Creating Audit DB...`r`n" 
            Create-Database -ServerName $SQLInstance -DatabaseName $esAuditDBName #-SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
			
			$ES_Install_Output.text += "`r`n**Running initial SQL scripts...**`r`n" 
			#$ES_Install_Output.text += "Running {0} of {1} script(s) in {3}: {2}" -F ($i + 1),$nodes.Count, $sqlFile, $sqlDB) -ForegroundColor Yellow
			
			#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_14_0.sql
			if ((Test-Path $sqlFile_OIS_dbcr) -eq $true){
				$c = Get-Content -Encoding UTF8 -path $sqlFile_OIS_dbcr -Raw
				$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
					Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
			}
			else {
				$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $sqlFile_OIS_dbcr
			}
			#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_oim_14_0.sql
				if ((Test-Path $sqlFile_OIS_dbcr_oim) -eq $true){
					$c = Get-Content -Encoding UTF8 -path $sqlFile_OIS_dbcr_oim -Raw
					$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
						Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c
				}
				else {
					$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $sqlFile_OIS_dbcr_oim
				}
				#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\CreateSourceSystemDataDB.sql
					if ((Test-Path $sqlFile_OIS_SourceSystemDB) -eq $true){
						$c = Get-Content -Encoding UTF8 -path $sqlFile_OIS_SourceSystemDB -Raw
						$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
							Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esSourceSystemDBName -QueryTimeout 300 -query $c
					}
					else {
						$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $sqlFile_OIS_SourceSystemDB
					}
				#$ES_Install_Output.text += "Running initial SQL scripts..." 
				#$initialScripts = $xmlcfg.SelectNodes("/Configuration/Version/ES/DBInitialScripts")

$ES_Install_Output.text += "`r`n***Installation of Enterprise Server finished.***`r`n"
$ES_Install_Output.text += "`r`n*************************************************`r`n"
})

##INSTALL RoPE#################################
$But_RoPE_Install.Add_Click({
	
	#From Form
	$RoPEServer = $RoPE_ServerName.Text
	$RoPEUser = $RoPE_ServiceAccount.Text
	$MSSQLServerName = $MSSQL_ServerName.Text
	$RoPEUser = $RoPE_ServiceAccount.Text
	$RoPEDB = $RoPE_DBName.Text
	$RoPEPassword = $RoPE_ServicePassword.Text
	$RoPE_ServicePassword.Text = " "
	$RoPEInstallationPath = $RoPE_InstDir.Text
	
	#Constants
	$SQLInstance = $MSSQLServerName
	$serviceUserDomain=$env:UserDomain
	$ConnectionString = "Initial Catalog ="+$RoPEDB+";Integrated Security=SSPI;Data Source="+$MSSQLServerName+";"
	$serviceUser=$RoPEUser
	$serviceUserPassword=$RoPEPassword
	$ropeServiceName="ROPE_0"
	$ropeDBUser=$serviceUser
	$RoPEProductDB=$RoPEDB
	$SQLAdmUser = 'unknown'
	$SQLAdmPass = '404'
	
	If ($RoPEServer -ne $Env:Computername){
	[System.Windows.MessageBox]::Show("Please make sure the RoPE Server Name is entered", "Missing Values")
	}

		$RoPE_Install_Output.text +=  "4.1 Role and Policy Engine installation `r`n"
	####Prep#########
	[System.Windows.MessageBox]::Show("Please select the relevant intallation file for RoPE `r`nExample: C:\Omada\Install\OIS Role and Policy Engine.exe ", "Select RoPE Install File")
	$RoPEInstallPath=Get-FileName -initialDirectory "C:\Omada\Install\"
	$InstallerFolder = Split-Path -Path $RoPEInstallPath
	$RoPEexe=""
 	$RootInstallerFolder = Split-Path -Path $InstallerFolder
	$logPath = Join-Path -Path $RootInstallerFolder -ChildPath "\Logs"
	$PSCommandPath = Join-Path -Path $RootInstallerFolder -ChildPath "\DO-UpgradeTools"
	#$RoPE_Install_Output.text += $RoPEInstallPath
	
	
	$args = (" /l*v \""{0}\installlog_rope.log\""" -F $logPath)
	$args +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
	$args +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
 	$args +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""
	$args +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\""" 
	$args += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $RoPEDB)
	$args += " SERVICETYPE=\""2\"""#1=user account, 2=Service account
	$args += " SERVICEDOMAIN=\""$serviceUserDomain\"""
	$args += " SERVICEUSER=\""$serviceUser\"""
	$args += " SERVICEPASSWORD=\""$serviceUserPassword\"""
	$args +=  " INSTALLDIR=\""$ropeInstallationPath\"""
	$args += " CONNSTROISX=\""$ConnectionString\"""
	#$RoPE_Install_Output.text +=  $logPath 
	
	#####Pre-Checking#####
	$RoPE_Install_Output.text +=  "`r`nRunning RoPE Pre-Installation Checks `r`n"
	#AD user check, SQL login check, connection string check
	#create the database 
	#Create-Database -User sa -Password 'P@55word' -Instance "demodb" -DBName $RoPEDB -SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $ropeDBUser) -DBAdmin 'sa' -DBPass 'Omada12345'
	
	####Installation####
	    $RoPE_Install_Output.text += "`r`nRole and Policy Engine installation starting...`r`n" 
		#$t = Start-Process -Wait -WorkingDirectory $InstallerFolder -FilePath "$RoPEexe" -ArgumentList " /V""$args /qn"" " -PassThru
		
		#Use this:
		$t = Start-Process -Wait -FilePath "$RoPEInstallPath" -ArgumentList " /V""$args /qn"" " -PassThru
		
		Start-Sleep -Seconds 2
		$RoPE_Install_Output.text += "`r`nRole and Policy Engine Post-Installation Configuration`r`n"
	
	####Post-Config####
	        netsh http add urlacl url=http://+:8733/RoPERemoteApi/ user=$serviceUserDomain\$serviceUser >$null
			#netsh http add urlacl url=http://+:8010/RoPERemoteApi/ user=$serviceUserDomain\$serviceUser >$null
		$RoPE_Install_Output.text += "`r`nConfiguring Service Start-Type`r`n"
			Set-ServicesStartAndDependency -ServiceName $ropeServiceName -StartType "delayed-auto"
		#$RoPE_Install_Output.text += "`r`nAdding User to Database`r`n"
			Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $ropeDBUser) -Instance $SQLInstance -DBName $RoPEProductDB -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass
			#Add-UserToDatabase -DBLogin 'megamart\srvc_omada' -Instance "." -DBName "testDB" -Role "db_owner" -User sa -Password "Omada12345"
        <# 
 


			
			#Data Connections
			#Validate connection string - ConnectionString.config #>
			Start-Sleep -Seconds 1
			$RoPE_Install_Output.text += "`r`nRole and Policy Engine installed`r`n"
})

<# 
$SSRS_ServiceAccount = $Win.FindName("SSRS_ServiceAccount")
$SSRS_ServerName = $Win.FindName("SSRS_ServerName")
$MSSQL_ServerName = $Win.FindName("MSSQL_ServerName")
$SSRS_URL = $Win.FindName("SSRS_URL")
$Output_SSRS_PreCheck = $Win.FindName("Output_SSRS_PreCheck")
$Button_RunPreCheck = $Win.FindName("Button_RunPreCheck")
$Button_InstallODW = $Win.FindName("Button_InstallODW")
$Button_UploadReports = $Win.FindName("Button_UploadReports")
$LicenseKey=$Win.FindName("LicenseKey")

$SQLAdmUser = 'unknown'
$SQLAdmPass = '404'
$ODWProductDB = 'Omada Data Warehouse'
$ODWProductDBStaging = 'Omada Data Warehouse Staging'
$ODWProductDBMaster = 'Omada Data Warehouse Master'
$odwName = "Omada Identity Suite Data Warehouse"
$ODWAdminsGroup = "ODWAdmins"
$ODWAuditorsGroup="ODWAuditors"
$ODWUsersGroup="ODWUsers"
$serviceUserDomain = $env:userdomain #>

$Win.ShowDialog()