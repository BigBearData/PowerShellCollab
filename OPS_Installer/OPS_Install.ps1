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

################################################
##INSTALL RoPE#################################
$But_RoPE_Install.Add_Click({

	$RoPEServer = $RoPE_ServerName.Text
	$RoPEUser = $RoPE_ServiceAccount.Text
	$MSSQLServerName = $MSSQL_ServerName.Text
	$RoPEUser = $RoPE_ServiceAccount.Text
	$RoPEDB = $RoPE_DBName.Text
	$RoPEPassword = $RoPE_ServicePassword.Text
	$RoPE_ServicePassword.Text = " "
	$RoPEInstallationPath = $RoPE_InstDir.Text
	
	$SQLInstance = $MSSQLServerName
	$serviceUserDomain=$env:UserDomain
	$ConnectionString = "Initial Catalog ="+$RoPEDB+";Integrated Security=SSPI;Data Source="+$MSSQLServerName+";"
	$serviceUser=$RoPEUser
	$serviceUserPassword=$RoPEPassword
	$ropeServiceName="ROPE_0"
	
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
<# 	$args +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""
	$args +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\""" #>
	$args += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $RoPEDB)
	$args += " SERVICETYPE=\""2\"""#1=user account, 2=Service account
	$args += " SERVICEDOMAIN=\""$serviceUserDomain\"""
	$args += " SERVICEUSER=\""$serviceUser\"""
	$args += " SERVICEPASSWORD=\""$serviceUserPassword\"""
	$args +=  " INSTALLDIR=\""$ropeInstallationPath\"""
	$args += " CONNSTROISX=\""$ConnectionString\"""
	#$RoPE_Install_Output.text +=  $args 
	
	#####Pre-Checking#####
	$RoPE_Install_Output.text +=  "`r`nRunning RoPE Pre-Installation Checks `r`n"
	#AD user check, SQL login check, connection string check
	
	####Installation####
	    $RoPE_Install_Output.text += "`r`nRole and Policy Engine installation starting...`r`n" 
		#$t = Start-Process -Wait -WorkingDirectory $InstallerFolder -FilePath "$RoPEexe" -ArgumentList " /V""$args /qn"" " -PassThru
		
		#Use this:
		#$t = Start-Process -Wait -FilePath "$RoPEInstallPath" -ArgumentList " /V""$args /qn"" " -PassThru
		
		
		$RoPE_Install_Output.text += "`r`nRole and Policy Engine installed`r`n"
	
	####Post-Config####
        <# 
            netsh http add urlacl url=http://+:8733/RoPERemoteApi/ user=$serviceUserDomain\$serviceUser >$null
			Set-ServicesStartAndDependency -ServiceName $ropeServiceName -StartType "delayed-auto" 
			
			Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $ropeDBUser) -Instance $SQLInstance -DBName $RoPEProductDB -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLUser $useSQLUser -IsCI $IsCI
			#Add-UserToDatabase -DBLogin 'megamart\srvc_omada' -Instance "." -DBName "testDB" -Role "db_owner" -User sa -Password "Omada12345"
			
			#Data Connections
			#Validate connection string - ConnectionString.config
 #>
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