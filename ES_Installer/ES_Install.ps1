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

Function Run-SqlScript {
param(
$FileName,
$SQLInstance,
$DBName,
$serviceUserDomain=$env:UserDomain
)
			#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_14_0.sql
			if ((Test-Path $FileName) -eq $true){
				$c = Get-Content -Encoding UTF8 -path $FileName -Raw
				$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
					Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $DBName -QueryTimeout 300 -query $c | Out-Null
			}
			else {
				$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $FileName
			}
} #end of function run-SqlScript

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
	
<# 	$esWebSitePath = $esInstallationPath # (Join-Path -Path $esInstallationPath -ChildPath "website")
	$u = ("{0}\{1}" -F $serviceUserDomain, $serviceUser) #>
	

        if(Test-Path IIS:\AppPools\$IISAppPoolName){
            $ES_Install_Output.text +="App pool {0} exists, skipping.`r`n" -F $IISAppPoolName 
			#write-host "App pool exists"
        }else{
            $ES_Install_Output.text +="Creating app pool {0}...`r`n" -F $IISAppPoolName
			#Write-host "Crating App Pool $IISAppPoolName"
            $t = New-WebAppPool -Name $IISAppPoolName
            Set-ItemProperty iis:\apppools\$IISAppPoolName -name processModel -value @{userName=$AppPoolUser;password=$serviceUserPassword;identitytype=3}
            Sleep -Seconds 5
            $ES_Install_Output.text +="App pool created`r`n" 
			#write-host "App Pool $IISAppPoolName created."
        }
$WSexists=get-website $IISWebSite
	$ES_Install_Output.text +="Website {0} info {1}`r`n" -F $IISWebSite, $WSexists
    #$ws = Get-Website –Name $IISWebSite
    if ($WSexists -eq $null){
			$ES_Install_Output.text += "Adding http binding" 
			#Show-Info -IsCI $IsCI -Message ("Adding binding for {0}" -f $ip) -ForegroundColor Yellow 
			#write-host "Creating Website $IISWebSite with binding"
			$t = New-Item iis:\Sites\$IISWebSite -PhysicalPath $esWebSitePath -Bindings @{protocol="http";bindingInformation="*:" + [string]$Port + ":$WebSiteBinding"} -ApplicationPool $IISAppPoolName -AutoStart $true
			
				$ip = ((Get-NetIPAddress -PrefixOrigin "dhcp").IPAddress | Where-Object {$_ -ne "127.0.0.1"})
				#$ip
				$ES_Install_Output.text +="Adding binding for {0}`r`n" -f $ip
				#write-host "Adding binding for $ip"
				if ($ip -ne $null){
					$ES_Install_Output.text += "Binding added {0}`r`n" -f $ip
					#write-Host "Binding added for $ip"
					New-WebBinding -Name $IISWebSite -IPAddress $ip -Port 80 -HostHeader '' | Out-Null
				}else{
					#Show-Info -IsCI $IsCI -Message ("Binding not added {0}" -f $ip) -ForegroundColor Red
					$ES_Install_Output.text += "Unable to add binding to ES web site!!`r`n" 
					#write-host "Unable to add binding to ES web site!!"
				}
		
	}
	else{
        $ES_Install_Output.text +="Web site {0} exists, skipping`r`n" -F $IISWebSite
		#write-host "Web site $IISWebSite exists."
    }

		$ES_Install_Output.text += "Creating default document main.aspx`r`n"
		Remove-WebConfigurationProperty //defaultDocument ("IIS:\sites\" + $IISWebSite) -name files.collection -atIndex 0
		Add-WebConfiguration //defaultDocument/files ("IIS:\sites\" +  $IISWebSite) -atIndex 0 -Value @{value="main.aspx"}
		
		
		$ES_Install_Output.text += "Disable anonymous authentication`r`n" 
		#Write-host "Disabling anonymous authentication."
		$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/AnonymousAuthentication" -name Enabled -location $IISWebSite -Value $false
			
    	$ES_Install_Output.text += "Enable and configure windows authentication`r`n" 
		#Write-host "Enable and configure windows authentication"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication" -name Enabled -location $IISWebSite -Value $true
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication/extendedProtection" -name tokenChecking -location $IISWebSite -Value "Require"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication/extendedProtection" -name flags -location $IISWebSite -Value "None"
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/WindowsAuthentication" -name useKernelMode -location $IISWebSite -Value $true

		$ES_Install_Output.text += "Enable basic authentication`r`n" 
		#write-Host "Enabling basic authentication."
    	$t = Set-WebConfigurationProperty -filter "/system.WebServer/security/authentication/BasicAuthentication" -name Enabled -location $IISWebSite -Value $true

}


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
$ropeServiceName="ROPE_0"

#ES Variables########################################################
$ES_ServerName = $Win.FindName("ES_ServerName")
$ES_ServiceAccount = $Win.FindName("ES_ServiceAccount")
$ES_MSSQL_ServerName = $Win.FindName("ES_MSSQL_ServerName")
$But_ES_Install = $Win.FindName("But_ES_Install")
$But_Clear = $Win.FindName("But_Clear")
$ES_DBName = $Win.FindName("ES_DBName")
$ES_ServicePassword = $Win.FindName("ES_ServicePassword")
$ES_Install_Output = $Win.FindName("ES_Install_Output")
$ES_InstDir = $Win.FindName("ES_InstDir")

$ES_ServerName.text = $Env:Computername
$esTimerService="OETSVC"#"ROPE_0"

################################################
$But_Clear.Add_Click({
$ES_Install_Output.text =""
})

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
	$LicenseKey =$ES_LicenseKey.Text
	
	#Constants
	$SQLInstance = $MSSQLServerName
	$serviceUserDomain=$env:UserDomain
	$ConnectionString = "Initial Catalog ="+$esDBName+";Integrated Security=SSPI;Data Source="+$MSSQLServerName+";"
	$serviceUser=$ESEUser
	$serviceUserPassword=$ESPassword
	$esAppPool = "Enterprise server" 
	$esWebSite = "Enterprise Server"
	$esBinding ="enterpriseserver"
	
	$ESDBUser=$serviceUser
	$ESProductDB=$esDBName
	$SQLAdmUser = 'unknown'
	$SQLAdmPass = '404'
	$esSourceSystemDBName="Omada Source System Data DB"
	$esAuditDBName="OISAudit"
	
	#Process:
	#
            #Show-Info -IsCI $IsCI -Message "2.1 Enterprise Server installation"#-ForegroundColor DarkGreen
			$ES_Install_Output.text += "***2.1 Enterprise Server installation***`r`n" 

	####Prep#########
	[System.Windows.MessageBox]::Show("Please select the relevant intallation file for Enterprise Server `r`nExample: C:\Omada\Install\OIS Enterprise Server.exe ", "Select ES Install File")
	$ES_Install_Output.text += "Installation in progress...`r`n"
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
			#$ES_Install_Output.text += "Installation in progress...`r`n"
			$t = Start-Process -Wait -FilePath $ESInstallPath -ArgumentList " /V""$args /qn"" " -PassThru -WindowStyle Hidden
			
<# 			if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $esName} )){
				Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation log for details - {1}\installlog_es.log" -f $esName, $logPath) -ForegroundColor Red
				break
			} #>
	#Create databases
	        $ES_Install_Output.text +="Creating DB {0}...`r`n" -F $esDBName
            #Show-Info -IsCI $IsCI -Message ("main script: Use SQL user: {0} {1}" -F $useSQLUser, $SQLAdmUser)
			$esDbExists=Test-SqlConnection -sqlServer $SQLInstance -DBName $esDBName
				If ($esDbExists -eq $true){
					$ES_Install_Output.text += "The Database $esDBName on $SQLInstance already exists`r`n"
				}
				else {
					Create-Database -ServerName $SQLInstance -DatabaseName $esDBName #-SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
					Run-SqlScript -FileName $sqlFile_OIS_dbcr -SQLInstance  $SQLInstance -DBName $esDBName
					Run-SqlScript -FileName $sqlFile_OIS_dbcr_oim -SQLInstance  $SQLInstance -DBName $esDBName
				}

            $ES_Install_Output.text += "Creating Source System Data DB...`r`n" 
			$esSourceDbExists=Test-SqlConnection -sqlServer $SQLInstance -DBName $esSourceSystemDBName
				If ($esSourceDbExists -eq $true){
					$ES_Install_Output.text += "The Database $esSourceSystemDBName on $SQLInstance already exists`r`n"
				}
				else {
					Create-Database -ServerName $SQLInstance -DatabaseName $esSourceSystemDBName #-SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
					Run-SqlScript -FileName $sqlFile_OIS_SourceSystemDB -SQLInstance  $SQLInstance -DBName $esSourceSystemDBName
				}

            $ES_Install_Output.text += "Creating Audit DB...`r`n" 
			$AuditDbExists=Test-SqlConnection -sqlServer $SQLInstance -DBName $esAuditDBName
				If ($AuditDbExists -eq $true){
					$ES_Install_Output.text += "The Database $esAuditDBName on $SQLInstance already exists`r`n"
				}
				else {
					Create-Database -ServerName $SQLInstance -DatabaseName $esAuditDBName #-SnapshotIsolation $false -DBLogin ("{0}\{1}" -F $serviceUserDomain, $esDBUser) -DBAdmin $SQLAdmUser -DBPass $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
				}
			
<# 			$ES_Install_Output.text += "`r`n**Running initial SQL scripts...**`r`n" 
			#$ES_Install_Output.text += "Running {0} of {1} script(s) in {3}: {2}" -F ($i + 1),$nodes.Count, $sqlFile, $sqlDB) -ForegroundColor Yellow
			
			#Run SQL Scripts
			#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_14_0.sql
			if ((Test-Path $sqlFile_OIS_dbcr) -eq $true){
				$c = Get-Content -Encoding UTF8 -path $sqlFile_OIS_dbcr -Raw
				$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
					Try {
					Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c | Out-Null
					} Catch {
					$ES_Install_Output.text += "Error when running sql file $sqlFile_OIS_dbcr. The script may already been run.`r`n"
					}
			}
			else {
				$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $sqlFile_OIS_dbcr
			}
			#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_oim_14_0.sql
				if ((Test-Path $sqlFile_OIS_dbcr_oim) -eq $true){
					$c = Get-Content -Encoding UTF8 -path $sqlFile_OIS_dbcr_oim -Raw
					$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
						Try {
							Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c | Out-Null
						} Catch {
						$ES_Install_Output.text += "Error when running sql file $sqlFile_OIS_dbcr_oim. The script may already been run.`r`n"
						}
				}
				else {
					$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $sqlFile_OIS_dbcr_oim
				}
				#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\CreateSourceSystemDataDB.sql
					if ((Test-Path $sqlFile_OIS_SourceSystemDB) -eq $true){
						$c = Get-Content -Encoding UTF8 -path $sqlFile_OIS_SourceSystemDB -Raw
						$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
							Try {						
							Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esSourceSystemDBName -QueryTimeout 300 -query $c | Out-Null
							} Catch {
							$ES_Install_Output.text += "Error when running sql file $sqlFile_OIS_SourceSystemDB. The script may already been run.`r`n"
							}							
					}
					else {
						$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $sqlFile_OIS_SourceSystemDB
					}
				#$ES_Install_Output.text += "Running initial SQL scripts..." 
				#$initialScripts = $xmlcfg.SelectNodes("/Configuration/Version/ES/DBInitialScripts") #>
				
	#config AuthenticationType in tblCustomerAuth
	Restart-Service -ServiceName ("*{0}*" -f $esTimerService) #-Action "Start"
	$ES_Install_Output.text += "Generating additional columns in tblCustomer...`r`n" 
	Start-Sleep -s 10
	$c = "Update dbo.tblCustomerAuth SET AuthenticationType = 'Integrated' WHERE CustomerID = 1000;"
    Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName -QueryTimeout 300 -query $c #-inputfile $sqlFile
    Stop-Service -ServiceName ("*{0}*" -f $esTimerService) #-Action "Stop"
	
	#Add licence $LicenseKey
	If ($LicenseKey.Length -gt 10){ 	#THIS MAY WORK!
	$ES_Install_Output.text +=  "Adding licence...`r`n" 
	#Add-Licence -DBInstance $SQLInstance -DBName $esDBName -LicenseKey $cfgVersion.OIS.LicenseKey -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
	Add-Licence -DBInstance $SQLInstance -DBName $esDBName -LicenseKey $LicenseKey -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $false
	
	}
	else {
	[System.Windows.MessageBox]::Show("No License Key provided. `r`nLicence Key will need to be installed manually.", "Missing Values")
	}

##Create Web Site###########################################################################
$ES_Install_Output.text += "`r`n***2.4 Creating a web site for Enterprise Server.***`r`n"
			$c = ("Update tblUser set UserName=UPPER('{0}') where UserName='ADMINISTRATOR'" -F $env:USERNAME)
            invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database $esDBName
			
            $esWebSitePath = (Join-Path -Path $esInstallationPath -ChildPath "website")
            $u = ("{0}\{1}" -F $serviceUserDomain, $serviceUser)
            #$t = New-OISWebSite -IISAppPoolName $esAppPool -IISWebSite $esWebSite -AppPool $true -WebSitePath $esWebSitePath -WebSiteBinding $esBinding -Firewall $true -AppPoolUser $u -AppPoolUserPassword $serviceUserPassword -CertThumbprint "" #-IsCI $IsCI -isDemo $demoEnabled -isTA $demoTA
			#New-OISWebSite -IISAppPoolName "Enterprise server" -IISWebSite "Enterprise Server" -AppPool $true -WebSitePath "C:\Program Files\Omada Identity Suite\Enterprise Server 12\website" -WebSiteBinding "enterpriseserver" -Firewall $true -AppPoolUser "megamart\srvc_omada" -AppPoolUserPassword "Omada12345" -CertThumbprint '629159577035C3939AE852EB29468DEB116424E8'
            
			#New-ES-Website -serviceUser $serviceUser -serviceUserPassword $serviceUserPassword -IISAppPoolName -esInstallationPath -WebSiteName -WebSiteBinding
			$t = New-ES-Website -serviceUser $u -serviceUserPassword $serviceUserPassword -esInstallationPath $esWebSitePath -WebSiteName "Enterprise Server"
			
			#Show-Info -IsCI $IsCI -Message "Starting a web site..." -ForegroundColor Yello
			$ES_Install_Output.text +=  "Finished creating a web site`r`n"
			
			#Create Proxy Accounts
			$ES_Install_Output.text += "***2.5 Creating proxy account in MS SQL***`r`n" 

				#create SQL credentials

				$c = "if not exists (select * from sys.credentials where name = N'$($serviceUserDomain)\$($serviceUser)')
				BEGIN
				CREATE CREDENTIAL [$($serviceUserDomain)\$($serviceUser)] WITH IDENTITY = N'$($serviceUserDomain)\$($serviceUser)', SECRET = N'$($serviceUserPassword)'
				END"

					invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database "master"



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

					invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database "msdb"



            $ES_Install_Output.text +=  "Proxy account created`r`n" 
            $ES_Install_Output.text +=  "***************************`r`n" 
			
<# 					if ($InputFile -eq "K"){
						$n = "core packages"
					}else{
						$n = "suggested packages"
					}
					Show-Info -IsCI $IsCI -Message ("Importing {0}, it might take couple of minutes..." -F $n) -ForegroundColor Yellow
					#$args = @("-C", "$Customer", "-f", "$inputFile", "-L", "$logFile")#
					$t = ('"{3}ChangeSetImportUtil.exe" -C {0} -{1} -L "{2}" -S' -F $Customer, $InputFile, $LogFile, ($ESProductInstallPath + "\website\bin\")) #>


$ES_Install_Output.text += "`r`n***Installation of Enterprise Server finished.***`r`n"
$ES_Install_Output.text += "*************************************************`r`n"
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