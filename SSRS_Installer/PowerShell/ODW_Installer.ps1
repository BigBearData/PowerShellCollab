Add-Type -AssemblyName PresentationFramework

###################################################################################
#FUNCTIONS GO HERE:

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

Function Get_UserSPN { 
param(
$EntUserName
)

$Result = Get-ADUser -LDAPFilter "(SamAccountname=$EntUserName)" -Properties name, serviceprincipalname -ErrorAction Stop | Select-Object @{Label = "Service Principal Names";Expression = {$_.serviceprincipalname}} | Select-Object -ExpandProperty "Service Principal Names" 
 
	If ($Result) {   
		$SPNText = "The Service Principal names found for $EntUserName are listed below: "   
		$Result  
	} 
	 
	Else { 
		$SPNText = "No Service Principal name found for $EntUserName "
		$SPNText
	}  
<#
.SYNOPSIS

Primary command for prerequisites testing before Essential deployment.

.DESCRIPTION

Checks if a user account has any SPNs and lists them if found.  
Requires PS module ActiveDirectory to be installed. 
This command can also be used for other user objects then Enterprise User. 

.PARAMETER EntUserName
Default value is null. 

.EXAMPLE

PPS C:\> OIS_GetEntUserSPN -EntUserName salesadm
No Service Principal name found for salesadm

#> 
}

Function Publish-SSRSReports {
    <#
    .SYNOPSIS
        Script uploads report definitions
    .DESCRIPTION
        Script is used to upload reports to SSRS server
    .PARAMETER rsHttps
        SSRS is using SSL
    .PARAMETER remoteDB
        DB server is remove
    .PARAMETER rsOnAppServer
        SSRS is on Application server
    .PARAMETER rsServer
        Name of SSRS server  
    .PARAMETER odwUploadReportsToolPath
        Path to tool used to upload reports
    .PARAMETER odwInstallationPath
        Path to installation of ODW
    .PARAMETER logPath
        Path to logs
    .PARAMETER scriptPath     
        Path to scripts
    .PARAMETER SQLInstanceName
        Name of SQL server
    .PARAMETER SQLInstanceWithout
        Name of SQL server without instance name
    .PARAMETER SSRSPath
        Path to installation of SSRS
    .PARAMETER credDB
        Credential used to connect to SQL server

    .EXAMPLE
        Publish-Reports -rsHttps $false -remoteDB $false -rsOnAppServer $false -rsServer 'testapp' -odwUploadReportsToolPath 'c:\Powershell\tools' -odwInstallationPath '' -logPath '' -scriptPath '' -SQLInstanceName '' -SQLInstanceWithout '' -SSRSPath '' -credDB $null
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        [Parameter (Mandatory)]
        [boolean]$rsHttps,

	[Parameter (Mandatory)]
    [boolean]$remoteDB,

	[Parameter (Mandatory)]
    [boolean]$rsOnAppServer,

	[Parameter (Mandatory)]
    [string]$rsServer,
 
	[Parameter (Mandatory)]
    [string]$odwUploadReportsToolPath,

	[Parameter (Mandatory)]
    [string]$odwInstallationPath,

	[Parameter (Mandatory)]
    [string]$logPath,

	[Parameter (Mandatory)]
    [string]$scriptPath,

	[Parameter (Mandatory)]
    [string]$SQLInstanceName,

	[Parameter (Mandatory)]
    [string]$SQLInstanceWithout,

	[Parameter (Mandatory)]
    [string]$SSRSPath,

    $credDB

    )



    $Output_SSRS_PreCheck.text +="Creating batch file to upload reports..."  +"`r`n" #-ForegroundColor Yellow
    $s = ""
    if ($rsHttps -eq $true) {
        $s = "s"
    }
    if ($remoteDB -and $rsOnAppServer) {
        $rsUrl = ("http{0}://{1}/ReportServer/" -F $s, 'localhost')
        $ScriptBlock = {
            $rsUrl = $args[0]
            $odwUploadReportsToolPath = $args[1]
            $odwInstallationPath = $args[2]
            if (!(Test-Path -Path $args[3])){
                $tt = New-Item -Path $args[3] -ItemType Directory
            }
            $logFile = ("{0}\reportUpload.log" -F $args[3])
            $reportsPath = Join-Path $args[4] -ChildPath 'Private\ODW'
            $c = Get-Content ("{0}\NativeLoadReports.bat.template" -F $odwUploadReportsToolPath)
            $t = $c.Replace("{demoServerUrl}", $rsUrl).Replace("{reportLoaderPath}", $odwUploadReportsToolPath).Replace("{odwInstallationPath}", $odwInstallationPath).Replace('C:\Program Files\Omada Identity Suite\Datawarehouse\Support Files', $reportsPath)
            if (!(Test-Path -Path ("{0}\NativeLoadReports.bat" -F $odwUploadReportsToolPath))) {
                $tt = New-Item -ItemType file -Path ("{0}\NativeLoadReports.bat" -F $odwUploadReportsToolPath)
            }
            $t | Set-Content ("{0}\NativeLoadReports.bat" -F $odwUploadReportsToolPath)
                
            $Output_SSRS_PreCheck.text +=   "Uplading reports..."  +"`r`n" #-ForegroundColor Yellow

            $f = ('"{0}\NativeLoadReports.bat" > "{1}"' -F $odwUploadReportsToolPath, $logFile)
            Invoke-Expression "& $f"
            $Output_SSRS_PreCheck.text +=   "Reports added"  +"`r`n" #-ForegroundColor Green
            #remove folder
        }
        Invoke-Command  -ScriptBlock $ScriptBlock -ArgumentList $rsUrl, $odwUploadReportsToolPath, $odwInstallationPath, $logPath, $scriptPath
                    
    }
    else {
        if ($SQLInstanceName -ne $SQLInstanceWithout) {
            $rsUrl = ("http{0}://{1}/ReportServer_{2}/" -F $s, $SQLInstanceWithout, $SQLInstanceName)#'localhost'
        }
        else {
            $rsUrl = ("http{0}://{1}/ReportServer/" -F $s, $rsServer)#'localhost'
        }
        $ScriptBlock = {
                        
            $rsUrl = $args[0]
            $odwUploadReportsToolPath = $args[1]
            $odwInstallationPath = $args[2]
            $logFile = ("{0}\reportUpload.log" -F $args[3])
            $ssrsPath = $args[4]
            $server = $args[5]
            
            if (Test-Path -Path (Join-Path -Path $odwInstallationPath -ChildPath 'Support Files\SSRS Reports')){
                $reportsPath = (Join-Path -Path $odwInstallationPath -ChildPath 'Support Files')
            }else{
                $reportsPath = $odwUploadReportsToolPath 
            }

            if ((Test-Path -Path $ssrsPath)) {
                $c = Get-Content ("{0}\NativeLoadReports.bat.template" -F $odwUploadReportsToolPath)
                $t = $c.Replace("{demoServerUrl}", $rsUrl).Replace("{reportLoaderPath}", $odwUploadReportsToolPath).Replace("{odwInstallationPath}", $odwInstallationPath).Replace('C:\Program Files\Omada Identity Suite\Datawarehouse\Support Files', $reportsPath)
                if (!(Test-Path -Path ("{0}\NativeLoadReports.bat" -F $odwUploadReportsToolPath))) {
                    $tt = New-Item -ItemType file -Path ("{0}\NativeLoadReports.bat" -F $odwUploadReportsToolPath)
                }
                $t | Set-Content ("{0}\NativeLoadReports.bat" -F $odwUploadReportsToolPath)
                    
                $toolPath = ('{0}\ReportServer\bin\Omada.ODW.SSRS.Utils.dll' -F $ssrsPath)

                if (!(Test-Path -Path $toolPath)) {
                    #when there is a default instance and a named one - this dll is copied by installer to default not named insance folder, fix 
                    if (Test-Path -Path (Join-Path -Path $odwInstallationPath -ChildPath "Support Files\Omada.ODW.SSRS.Utils.dll")) {
                        $Output_SSRS_PreCheck.text +=  "Omada.ODW.SSRS.Utils.dll is missing - fixing"  +"`r`n" #-ForegroundColor Yellow
                        Copy-Item -Path (Join-Path -Path $odwInstallationPath -ChildPath "Support Files\Omada.ODW.SSRS.Utils.dll") -Destination $toolPath  -Force
                        $Output_SSRS_PreCheck.text +=   "Fixed"  +"`r`n" #-ForegroundColor Green 
                    }
                }
                $Output_SSRS_PreCheck.text +=   "Uplading reports..."  +"`r`n" #-ForegroundColor Yellow

                $f = ('"{0}\NativeLoadReports.bat" > "{1}"' -F $odwUploadReportsToolPath, $logFile)
                Invoke-Expression "& $f"

                $Output_SSRS_PreCheck.text +=   "Reports added"  +"`r`n" #-ForegroundColor Green
            }
            else {
                $Output_SSRS_PreCheck.text +=   "Reporting server path not found, not critical error - skipping"  +"`r`n" #-ForegroundColor Red
                $Output_SSRS_PreCheck.text +=   ("({0}) {1}" -F $server, $ssrsPath)  +"`r`n"  +"`r`n" #-ForegroundColor Red
            }
        }
			#$Output_SSRS_PreCheck.text += $SQLInstance
			#$Output_SSRS_PreCheck.text += $rsUrl +"`r`n" 
			#$Output_SSRS_PreCheck.text += $odwUploadReportsToolPath +"`r`n" 
			#$Output_SSRS_PreCheck.text += $odwInstallationPath +"`r`n" 
			#$Output_SSRS_PreCheck.text += $logPath +"`r`n" 
			#$Output_SSRS_PreCheck.text += $SSRSPath +"`r`n" 
			#$Output_SSRS_PreCheck.text += $SQLInstanceWithout +"`r`n" 
        #if ($SQLInstance -eq 'localhost' -or $SQLInstance.startswith($env:ComputerName)) {
            #$SSISInstance

			
            Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $rsUrl, $odwUploadReportsToolPath, $odwInstallationPath, $logPath, $SSRSPath, $SQLInstanceWithout
<#         }
        else {
            Invoke-Command -ScriptBlock $ScriptBlock -Credential $credDB -ComputerName $SQLInstanceWithout -ArgumentList $rsUrl, $odwUploadReportsToolPath, $odwInstallationPath, $logPath, $SSRSPath, $SQLInstanceWithout
        } #>
    }
}#end of function Publish-SSRSReports

 Function Get-SQLName {
    
        <#
        .SYNOPSIS
            Checks the name of SQL and it's instance
        .DESCRIPTION
            Gets the instance name and ssrs
        .PARAMETER SQLInstance
            Information from the config file about SQL
        .PARAMETER rsOnAppServer
            if SSRS is on the App server
        
        .EXAMPLE
            Get-SQLName -SQLInstance 'testdb\instancename,6666;NodeName' -rsOnAppServer $true
        #>
        [cmdletbinding(SupportsShouldProcess)]
        Param(
        [Parameter (Mandatory)]
        [string]$SQLInstance,

        [Parameter (Mandatory)]
        [bool]$rsOnAppServer
        )

         #$SQLName = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
		#$Output_SSIS_PreCheck.text += $SQLInstance
         #strip for cluster node	DOES NOT WORK
          if ($SQLInstance.IndexOf(";") -ge 0){
            #$Output_SSIS_PreCheck.text += "SQL server is using cluster`r`n" 
            $SQLInstance = $SQLInstance.Substring(0, $SQLInstance.IndexOf(";"))
	   		$SQLNodeName = $SQLInstance.Substring($SQLInstance.IndexOf(";") + 1)
         }
         else{
            $Output_SSIS_PreCheck.text += "SQL server is not using cluster`r`n" 
         }
         #strip from port
         if ($SQLInstance.IndexOf(",") -ge 0){
            $Output_SSIS_PreCheck.text += "SQL server is using nondefault port`r`n" 
            $SQLInstance = $SQLInstance.Substring(0, $SQLInstance.IndexOf(","))
         }
         else{
               $Output_SSIS_PreCheck.text += "SQL server is using default port`r`n" 
         }
         #strip for instace
         if ($SQLInstance.IndexOf("\") -ge 0){
            $Output_SSIS_PreCheck.text += "SQL server is using named instance`r`n" 
            $SQLInstanceWithout = $SQLInstance.Substring(0, $SQLInstance.IndexOf("\"))
	   		$SQLInstanceName = $SQLInstance.Substring($SQLInstance.IndexOf("\") + 1)
         }
         else{
            $Output_SSIS_PreCheck.text += "SQL server is using default instance`r`n" 
            $SQLInstanceWithout = $SQLInstance
   			$SQLInstanceName = $null
         } 
 
<#          #check where rs should be. #Comment: Should be able to install SSRS on any server. 
         if($rsOnAppServer){
            Show-Info -IsCI $IsCI -Message "SSRS on App server will be used" -ForegroundColor Yellow
            $rsServer = $env:COMPUTERNAME
         }else{
            Show-Info -IsCI $IsCI -Message "SSRS on SQL server will be used" -ForegroundColor Yellow
            $rsServer = $SQLName
         } #>
         #check if remoteDB is true
<#          if($SQLInstance.StartsWith(".")){
            $Output_SSIS_PreCheck.text += "Local SQL will be used, name will be translated to {0}`r`n"  -f (Get-WmiObject win32_computersystem).DNSHostName
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith("localhost")){
            $Output_SSIS_PreCheck.text += "Local SQL will be used, localhost will be translated to {0}`r`n" -f (Get-WmiObject win32_computersystem).DNSHostName
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith((Get-WmiObject win32_computersystem).DNSHostName)){
            $Output_SSIS_PreCheck.text += "Local SQL will be used.`r`n" 
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith($env:COMPUTERNAME)){
            $Output_SSIS_PreCheck.text += "Remote SQL will be used: {0}`r`n"  -f $SQLInstanceWithout
            $remoteDB = $false
         }else{
            $remoteDB = $true
         } #>

          $result = @(
            New-Object PSObject -Property @{SQLName = $SQLName; SQLInstanceWithout = $SQLInstanceWithout; rsServer = $rsServer; remoteDB = $remoteDB; SQLInstanceName = $SQLInstanceName; SQLNodeName = $SQLNodeName}
         )
 
         return $result 

}

function Set-DCOMSecurity{

<#
    .SYNOPSIS
        Updates DCOM security
    .DESCRIPTION
        
    .PARAMETER UserName
        User name which is lauching DCOM
    .PARAMETER Domain
        Domain in which user name is coming from
    .PARAMETER IsCI
        If this a manual install or CI triggered
    .EXAMPLE 
        Set-DCOMSecurity -UserName "administrator" -Domain "megamart" -SQLVersion "11" -SQLServer "localhost" -Credential $null
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [string]$UserName,

    [string]$Domain,

    [string]$SQLVersion,

    [string]$SQLServer = 'localhost',

    $Credential,
    [Boolean]$IsCI = $false
    )

    $ScriptBlock = {
        $UserName = $args[0]
        $Domain = $args[1]
        $SQLVersion = $args[2]
        $SQLServer = $args[3]
      try{
          $appdesc = ("Microsoft SQL Server Integration Services {0}.0" -F $SQLVersion)
          $app = get-wmiobject -query ('SELECT * FROM Win32_DCOMApplicationSetting WHERE Description = "' + $appdesc + '"') -enableallprivileges
          $sdRes = $app.GetLaunchSecurityDescriptor()
          $sd = $sdRes.Descriptor
          $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
          $trustee.Domain = $Domain
          $trustee.Name = $UserName
          $fullControl = 31
          $localLaunchActivate = 11
          $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
          $ace.AccessMask = $localLaunchActivate
          $ace.AceFlags = 0
          $ace.AceType = 0
          $ace.Trustee = $trustee
          [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
          $sd.DACL = $newDACL
          $t = $app.SetLaunchSecurityDescriptor($sd)
          if ($SQLServer -eq "localhost"){
              $Output_SSIS_PreCheck.text += "Setting DCOM Access Security for $UserName on local machine`r`n"
          }
          else{
              $Output_SSIS_PreCheck.text += "($SQLServer) Setting DCOM Access Security for $UserName`r`n"
          }
          $appdesc = ("Microsoft SQL Server Integration Services {0}.0" -F $SQLVersion)
          $app = get-wmiobject -query ('SELECT * FROM Win32_DCOMApplicationSetting WHERE Description = "' + $appdesc + '"') -enableallprivileges
          $sdRes = $app.GetAccessSecurityDescriptor()
          $sd = $sdRes.Descriptor
          $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
          $trustee.Domain = $domain
          $trustee.Name = $UserName
          $fullControl = 31
          $localLaunchActivate = 11
          $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
          $ace.AccessMask = $localLaunchActivate
          $ace.AceFlags = 0
          $ace.AceType = 0
          $ace.Trustee = $trustee
          [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
          $sd.DACL = $newDACL
          $t = $app.SetAccessSecurityDescriptor($sd)
      }
      catch{}
      $t = Set-DtcNetworkSetting -DtcName Local -AuthenticationLevel Incoming -InboundTransactionsEnabled $True -LUTransactionsEnabled $True -OutboundTransactionsEnabled $True -RemoteAdministrationAccessEnabled $True -RemoteClientAccessEnabled $True -XATransactionsEnabled $True -Confirm:$false
  
  }

    if ($SQLServer -eq 'localhost' -or $SQLServer -eq $env:ComputerName){
        $Output_SSIS_PreCheck.text += "Setting DCOM Launch Security for $UserName`r`n"
        $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $UserName, $Domain, $SQLVersion, $SQLServer
    }
    else{
        $Output_SSIS_PreCheck.text += "($SQLServer) Setting DCOM Launch Security for $UserName`r`n"
        $t = Invoke-Command -ComputerName $SQLServer -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $UserName, $Domain, $SQLVersion, $SQLServer
    }

}
 #Set-DCOMSecurity -UserName "administrator" -Domain "megamart" -SQLVersion "11" -SQLServer "localhost" -Credential $null
 
Function Show-Info {
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [string]$Message,
    [string]$ForegroundColor = "White",
    $IsCI = $false,
	$Service
    )
	
	Write-Host $Message -ForegroundColor $ForegroundColor

	switch ($IsCI) {
	
		SSIS {
		$Output_SSIS_PreCheck.text += $Message
		$Output_SSIS_PreCheck.text += "`r`n"
		}
		SSRS {
		$Output_SSRS_PreCheck.text += $Message
		$Output_SSRS_PreCheck.text += "`r`n"
		}
	
	}

}

Function get-sqlversion {
param(
$Sqlversion
)

    switch ( $Sqlversion )
    {
        2012 { $result = '11'    }
        2014 { $result = '12'    }
        2016 { $result = '13'   }
        2017 { $result = '14' }
        2019 { $result = '15'  }
    }

    $result

}

#READ THE XAML FILE
[xml]$Form = Get-Content ".\SSRS.xaml"
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

#SSRS Variables 
$SSRS_ServiceAccount = $Win.FindName("SSRS_ServiceAccount")
$SSRS_ServerName = $Win.FindName("SSRS_ServerName")
$MSSQL_ServerName = $Win.FindName("MSSQL_ServerName")
$SSRS_URL = $Win.FindName("SSRS_URL")
$Output_SSRS_PreCheck = $Win.FindName("Output_SSRS_PreCheck")
$Button_RunPreCheck = $Win.FindName("Button_RunPreCheck")
$Button_InstallODW = $Win.FindName("Button_InstallODW")
$Button_UploadReports = $Win.FindName("Button_UploadReports")
$LicenseKey=$Win.FindName("LicenseKey")
$ODW_InstDir=$Win.FindName("ODW_InstDir")

$SQLAdmUser = 'unknown'
$SQLAdmPass = '404'
#$ODWProductDB = 'Omada Data Warehouse'
#$ODWProductDBStaging = 'Omada Data Warehouse Staging'
#$ODWProductDBMaster = 'Omada Data Warehouse Master'
$odwName = "Omada Identity Suite Data Warehouse"
$ODWAdminsGroup = "ODWAdmins"
$ODWAuditorsGroup="ODWAuditors"
$ODWUsersGroup="ODWUsers"
$serviceUserDomain = $env:userdomain

[string]$SSRSSpnUser = OIS_GetServiceUser -ServiceName SSRS ServerName $SSRS_ServerName -Verbose $False -CheckRemote $False 
If ($SSRSSpnUser -match "\@") {$SSRS_ServiceAccount.text = $SSRSSpnUser.split("@")[0] } Elseif ($SSRSSpnUser -match "\\") {$SSRS_ServiceAccount.text = $SSRSSpnUser.split("\")[1] } Else {$SSRS_ServiceAccount.text = $SSRSSpnUser}  #-ErrorAction SilentlyContinue 
$SSRS_ServerName.text = $Env:Computername
$MSSQL_ServerName.text = $Env:Computername

#SSIS Variables
$SSIS_ServiceAccount = $Win.FindName("SSIS_ServiceAccount")
$SSIS_ServerName = $Win.FindName("SSIS_ServerName")
$MSSQL_ssis_ServerName = $Win.FindName("MSSQL_ssis_ServerName")
$SSIS_URL = $Win.FindName("SSIS_URL")
$Output_SSIS_PreCheck = $Win.FindName("Output_SSIS_PreCheck")
$Button_SSIS_RunPreCheck = $Win.FindName("Button_SSIS_RunPreCheck")
$Button_SSIS_InstallODW = $Win.FindName("Button_SSIS_InstallODW")
$Button_ssis_UploadReports = $Win.FindName("Button_ssis_UploadReports")
$SsisLicenseKey=$Win.FindName("SsisLicenseKey")
$ODW_SSIS_InstDir=$Win.FindName("ODW_SSIS_InstDir")
$ODW_IIS_ProductDB=$Win.FindName("ODWProductDB")
$ODWW_IIS_ProductDBStaging=$Win.FindName("ODWProductDBStaging")
$ODWW_IIS_ProductDBMaster=$Win.FindName("ODWProductDBMaster")
$ES_ServiceAccount=$Win.FindName("ES_ServiceAccount")
$ES_ServicePassword=$Win.FindName("ES_ServicePassword")
$SQLVersion=$Win.FindName("SQLVersion")

$SSIS_ServerName.text = $Env:Computername
#$MSSQL_ssis_ServerName.text = $Env:Computername
[string]$SSISSpnUser = OIS_GetServiceUser -ServiceName SSIS ServerName $SSRS_ServerName -Verbose $False -CheckRemote $False
$SSIS_ServiceAccount.text = $SSISSpnUser

#$Output_SSIS_PreCheck.text += ""

#INSTALL SSIS 
$Button_SSIS_InstallODW.Add_Click({
	#From Form
	$SSISServerName = $SSIS_ServerName.text
	$MSSQLssisServerName = $MSSQL_ssis_ServerName.text
	$ODWProductDB=$ODW_IIS_ProductDB.text
	$ODWProductDBStaging=$ODWW_IIS_ProductDBStaging.text
	$ODWProductDBMaster=$ODWW_IIS_ProductDBMaster.text
	$MSSQLVersion=$SQLVersion.text
	$SQLVersionNo= get-sqlversion -Sqlversion $MSSQLVersion
	#$Output_SSIS_PreCheck.text += $SQLVersionNo
	
	#Constants
	$serviceUser=$ES_ServiceAccount.text
	#$logPath = Join-Path -Path $RootInstallerFolder -ChildPath "\Logs"
	$SQLInstance=$MSSQLssisServerName
	$SSISInstance=$SSISServerName
	$PSScriptRoot=""
	$odwInstallationPath=$ODW_SSIS_InstDir
	$IsCI ="SSIS"
	$SSISServiceInfo = Get-Service | where {$_.Name -like "MsDtsServer*"}
	$SQLVersionNo=$SSISServiceInfo.DisplayName.Split()[-1].Split('.')[0]
	#$Output_SSIS_PreCheck.text += "SQL Verion Number: {0}`r`n" -F $SQLVersionNo
	
	#GET SQL INFORMATION
	$t=(Get-SQLName -SQLInstance $MSSQLssisServerName -rsOnAppServer $false)
	$SQLName = $t.SQLName
	$SQLInstanceWithout = $t.SQLInstanceWithout
	#$rsServer = $t.rsServer
	$sqlInstanceName = $t.SQLInstanceName


	
	$Output_SSIS_PreCheck.text += "***3.1 DCOM configuration***`r`n" 
	#Show-Info -IsCI $IsCI -Message "3.1 DCOM configuration" -ForegroundColor DarkGreen
		#Set-DCOMSecurity
		#Set-KerberosSecurity
		#"Restart Distributed Transaction Coordinator (MSDTC) service"
	 #Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SQLInstanceWithout -Credential $credDB -IsCI $IsCI
<#             Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SQLInstanceWithout -Credential $credDB -IsCI $IsCI
            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -SQLServer $SSISInstance -Credential $credDB -IsCI $IsCI
            Set-DCOMSecurity -UserName $serviceUser -Domain $serviceUserDomain -SQLVersion $SQLVersionNo -IsCI $IsCI #>
	
	#$Output_SSIS_PreCheck.text += "***3.2 Omada Data Warehouse installation`r`n"
	Show-Info -IsCI $IsCI -Message "3.2 Omada Data Warehouse installation" -ForegroundColor DarkGreen
	
	#Pre-install tasks: 
	#copy installation files, add registry (Set-ItemProperty -Path "HKCR:\Software\Omada\Omada Enterprise\$MajorVersion") line 661.
	#Check the MsDtsSrvr.ini.xml file
	[System.Windows.MessageBox]::Show("Please select the relevant intallation file for Omada Data Warehouse `r`nExample: C:\Omada\Install\Omada Data Warehouse.x64 SQL $MSSQLVersion.exe ", "Select ODW Install File")
	$SSISInstallPath=Get-FileName -initialDirectory "C:\Omada\Install\"
	$InstallerFolder = Split-Path -Path $SSISInstallPath
	$RootInstallerFolder = Split-Path -Path $InstallerFolder
	$logPath = Join-Path -Path $RootInstallerFolder -ChildPath "\Logs"
	$PSCommandPath = Join-Path -Path $RootInstallerFolder -ChildPath "\DO-UpgradeTools"
	$PSScriptRoot=$PSCommandPath
	$odwInstallerPath=$InstallerFolder
	$ODWexe=""
	$odwName="Omada Identity Suite Data Warehouse"
	

	
<#             $a = ("/qn /l*v \""{0}\installlog_odw.log\""" -F $logPath)
            $a +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            $a +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            $a +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""
            $a +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""
            $a +=  (" SSISSERVER=\""{0}\""" -F $SQLInstance) #$SSISInstance
            #installation on SSIS and the SSRS is not on that server - force installer to install reports
            #if ($remoteDB -and ($SSISInstance -ne $SQLInstance)){
			if ($SSISInstance -ne $SQLInstance){
                $a += (" SSRSPath=\""{0}\""" -F (Join-Path -Path $PSScriptRoot -ChildPath 'Private\ODW\Omada.exe'))
            }
            $a += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $ODWProductDB)
            $a += (" ODWSTAGINGDB=\""{0}\""" -F $ODWProductDBStaging)
            $a += (" ODWMASTER=\""{0}\""" -F $ODWProductDBMaster)
            $a +=  " INSTALLDIR=\""$odwInstallationPath\"""
            #$a += " OISXCONN=\""$ConnectionString\"""#removed from installer from version rel 12.0.4
	        #$a += (" LICENSEKEY=\""{0}\""" -F $cfgVersion.OIS.LicenseKey) bug 46176,  workaround due to command line parameter length limitations - license is added after the installation #>
			
			$a = ("/qn /l*v \""{0}\installlog_odw.log\""" -F $logPath)   #D:\Omada_Install\BG(bankgirot)\Omada Identity Suite v14.0.3.20\Logs
            $a +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            $a +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            $a +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""	#'unknown'
            $a +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""	#'404'
            $a +=  (" SSISSERVER=\""{0}\""" -F $SQLInstance) #$MSSQLServer
            $a += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $ODWProductDB)  	#'Omada Data Warehouse'
            $a += (" ODWSTAGINGDB=\""{0}\""" -F $ODWProductDBStaging)		#'Omada Data Warehouse Staging'
            $a += (" ODWMASTER=\""{0}\""" -F $ODWProductDBMaster)			#'Omada Data Warehouse Master'
	        $a += (" LICENSEKEY=\""{0}\""" -F $LicenseKey) #ask for this info
			
            Write-Host "Omada Data Warehouse installation starting..."
            $ScriptBlock = {

                $f = $SSISInstallPath # Join-Path -Path $args[0] -ChildPath $args[1] #CHANGED!!!
                #(" /V""{0} /qn"" " -F $args[2])
                Start-Process -Wait -FilePath $f -ArgumentList (" /V""{0} /qn"" " -F $args[2]) -PassThru  | Out-Null #-WorkingDirectory $args[0]
				#Start-Process -Wait -NoNewWindow -FilePath $f -ArgumentList (" /V""{0} /qn"" " -F $args[2]) -PassThru  | Out-Null #-WorkingDirectory $args[0]
<# 				if ($null -eq (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $args[3]} ) -or !(Test-Path -Path $args[5])){
					Show-Info -IsCI $IsCI -Message ("{0} was not installed. Please check installation on {2} log for details - {1}\installlog_odw.log`r`n" -f $args[3], $logPath, $args[4]) -ForegroundColor Red
					#break
				} #>
            }
				Show-Info -IsCI $IsCI -Message ("Installation on {0}`r`n" -F $SSISInstance)
				#$Output_SSIS_PreCheck.text += $SSISInstallPath
                $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, "local machine", $odwInstallationPath

})

#RUN SSRS PRE-CHECK
$Button_RunPreCheck.Add_Click({

	$SSRSServer = $SSRS_ServerName.Text
	$SSRSUser = $SSRS_ServiceAccount.Text
	
	If ($SSRSServer -ne $Env:Computername){
	[System.Windows.MessageBox]::Show("Please make sure the SSRS Server Name is entered", "Missing Values")
	}

 			$SoftwMS = $SSRSServer | OIS_GetInstalledPrograms -PN "*Management Studio*" -Property DisplayName,DisplayVersion | format-table
			If ($SoftwMS) {
				#$Output_SSRS_PreCheck.text +=  "Management Studio software is installed on server $SSRSServer. `r`n" 
			}
			elseif (!$SoftwMS) {
				$Output_SSRS_PreCheck.text +=  "Management Studio software is missing on server $SSRSServer. `r`n" 
			}
				
		$SoftwNC = $SSRSServer | OIS_GetInstalledPrograms -PN "*Native Client*" -Property DisplayName,DisplayVersion | format-table
			If ($SoftwNC) {
				#$Output_SSRS_PreCheck.text +=  "Native Client software is installed on server $SSRSServer. `r`n"
			}
			elseif (!$SoftwNC) {
				$Output_SSRS_PreCheck.text +=  "Native Client software is missing on server $SSRSServer. `r`n" 
			} 
	
	$ServerSPN = OIS_GetSPN -ServiceClass MSSQLSvc -ComputerName $SSRSServer 
	$Output_SSRS_PreCheck.text += ($ServerSPN | out-string)
	
	$AuthMethod = OIS_SSRS_GetAuthMethod -ServerName $SSRSServer -CheckRemote $False | format-list
	$Output_SSRS_PreCheck.text += "Authentication Method: "
	$Output_SSRS_PreCheck.text += ($AuthMethod | out-string)
	$Output_SSRS_PreCheck.text += " `r`n"
	
	
 	#Needs to have AD PowerShell module installed!!!
	$UserSPN=Get_UserSPN -EntUserName $SSRSUser
	$Output_SSRS_PreCheck.text += ($UserSPN | out-string)

<# Process:
verify mssql installed - Invoke-Command -ScriptBlock $ScriptBlock
Checking Installed Software - OIS_GetInstalledPrograms
Checking Authentication Methods: - OIS_SSRS_GetAuthMethod 
Checking SPNs for SSRS Server $SSRSServer - OIS_GetSPN #>
})


#INSTALL ODW on SSRS Server
$Button_InstallODW.Add_Click({

	$SSRSServer = $SSRS_ServerName.Text
	$SSRSUser = $SSRS_ServiceAccount.Text
	$MSSQLServer = $MSSQL_ServerName.Text
	$SQLInstance = $MSSQLServer #If Instance name is used....
	#Get-SQLName -SQLInstance 'testdb\instancename,6666' -rsOnAppServer $true
	
	[System.Windows.MessageBox]::Show("Please select the relevant intallation file for ODW `r`nExample: C:\Omada\Install\Omada Data Warehouse.x64 SQL 2016.exe ", "Select ODW Install File")
	$odwInstallerPath=Get-FileName -initialDirectory "C:\Omada\Install\"
	$InstallerFolder = Split-Path -Path $odwInstallerPath
	$RootInstallerFolder = Split-Path -Path $InstallerFolder
	$logPath = Join-Path -Path $RootInstallerFolder -ChildPath "\Logs"
	#Start-Sleep -Seconds 2
	#$odwInstallationDir = Get-Folder -initialDirectory $RootInstallerFolder -Description "Please Select the Installation Directory for ODW.`r`nExample: C:\Program Files"
	$odwInstallationPath = Join-Path -Path $odwInstallationDir -ChildPath "Omada Identity Suite\Datawarehouse"
	$PSCommandPath = Join-Path -Path $RootInstallerFolder -ChildPath "\DO-UpgradeTools"
	
	#$odwInstallationPath = "C:\Program Files\Omada Identity Suite\Datawarehouse" 			#Browse
	
			$a = ("/qn /l*v \""{0}\installlog_odw.log\""" -F $logPath)   #D:\Omada_Install\BG(bankgirot)\Omada Identity Suite v14.0.3.20\Logs
            $a +=  " IS_SQLSERVER_SERVER=\""$SQLInstance\"""
            $a +=  " IS_SQLSERVER_AUTHENTICATION=\""0\"""
            $a +=  " IS_SQLSERVER_USERNAME=\""$SQLAdmUser\"""	#'unknown'
            $a +=  " IS_SQLSERVER_PASSWORD=\""$SQLAdmPass\"""	#'404'
            $a +=  (" SSISSERVER=\""{0}\""" -F $SQLInstance) #$MSSQLServer
            $a += (" IS_SQLSERVER_DATABASE=\""{0}\""" -F $ODWProductDB)  	#'Omada Data Warehouse'
            $a += (" ODWSTAGINGDB=\""{0}\""" -F $ODWProductDBStaging)		#'Omada Data Warehouse Staging'
            $a += (" ODWMASTER=\""{0}\""" -F $ODWProductDBMaster)			#'Omada Data Warehouse Master'
	        $a += (" LICENSEKEY=\""{0}\""" -F $LicenseKey) #ask for this info
			
            $ScriptBlock = {
                $f = $args[0] #Join-Path -Path $args[0] -ChildPath $args[1]  #$odwInstallerPath, $ODWexe COMBINED INTO ONE!!
                #(" /V""{0} /qn"" " -F $args[2])
                $t = Start-Process -Wait -FilePath $f -ArgumentList (" /V""{0} /qn"" " -F $args[1]) -PassThru  #-WorkingDirectory $args[0] 
				if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | Where-Object { $_.DisplayName -contains $args[2]} ) -eq $null -or !(Test-Path -Path $args[4])){
					$Output_SSRS_PreCheck.text += "ODW was not installed. Please check installation log for details - $logPath\installlog_odw.log `r`n"
					break
				}
            }
			
	#$Output_SSRS_PreCheck.text += $a

	
	#Install ODW
	$Output_SSRS_PreCheck.text += "Installation Started `r`n"
	$t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $a, $odwName, "local machine", $odwInstallationPath
	
	#"3.3 Adding Omada Data Warehouse users"
	
<# 	        Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName $cfgVersion.ODW.ODWProductDatabase -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName $cfgVersion.ODW.ODWProductDatabaseStaging -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
            Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName $cfgVersion.ODW.ODWPRoductDatabaseMaster -Role "db_owner" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
			Add-UserToDatabase -DBLogin ("{0}\{1}" -F $serviceUserDomain, $owdDBUser) -Instance $SQLInstance -DBName "msdb" -Role "db_ssisadmin" -User $SQLAdmUser -Password $SQLAdmPass -useSQLuser $useSQLUser -IsCI $IsCI
			$q = ("sp_addrolemember 'db_datareader', '{0}\{1}' " -f $serviceUserDomain, $serviceUser)

                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database "msdb" -Query $q -QueryTimeout 300 #-inputfile $sqlFile
 #>
			
	#"3.4 Changing dtsConfig configuration files" 
	#<DtsConfigUpdates>
	
	#"3.5 Omada Data Warehouse configuration" 
	     #<ConfigurationPackage>
         #<PackageName>MSDB\Omada\ODW\Omada ODW Run</PackageName>
	
	
	$Output_SSRS_PreCheck.text += "Adding user for reports... `r`n"
	$c = (Get-Content -Path (Join-Path -Path $PSCommandPath -ChildPath "Private\ODW\setupReports.sql") -Raw).Replace("[Omada Data Warehouse]",("[{0}]" -f $ODWProductDB))
	$c = $c.Replace("megamart\ODWAdmins",("{0}\{1}" -f $serviceUserDomain, $ODWAdminsGroup)).Replace("megamart\ODWAuditors",("{0}\{1}" -f $serviceUserDomain, $ODWAuditorsGroup)).Replace("megamart\ODWUsers",("{0}\{1}" -f $serviceUserDomain, $ODWUsersGroup)) #$c.Replace("DOMAIN",$serviceUserDomain).Replace("megamart\",("{0}\" -F $serviceUserDomain))
	#Invoke-Sqlcmd -ServerInstance $SQLInstance -Database "master" -Query $c -QueryTimeout 300
	
	#"3.6 Omada Data Warehouse reports upload"
	
	
	
	#$Output_SSRS_PreCheck.text += $c
	
	#Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $a, $odwName, "local machine", $odwInstallationPath
	
	#These need to be run after installation of ODW - Line 1109
	#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_14_0.sql
	#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_oim_14_0.sql
	#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\CreateSourceSystemDataDB.sql
	
	
	#Configure SSRS server to use Kerberos -> AuthenticationTypes
	
	
	
#$t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $odwInstallerPath, $ODWexe, $a, $odwName, "local machine", $odwInstallationPath
#Run the 2 SQL scripts: CreateLogins.sql and CreateUser.sql
	#Invoke-Sqlcmd -ServerInstance $SQLInstance -Database "master" -Query $c -QueryTimeout 300


#Invoke-OmadaInstallv12 -XMLPath "C:\PowerShell\DO-UpgradeTools\Private\installv12.config"
})

$Button_UploadReports.Add_Click({

	$SSRSServer = $SSRS_ServerName.Text #rsServer
	$SSRSUrl=$SSRS_URL.Text
		#Datawarehouse folder path
	$ODWInstPath = Get-Folder -Description "Please Select the Directory for Datawarehouse.`r`nExample: C:\Program Files\Omada Identity Suite\Datawarehouse" #"C:\Program Files\Omada Identity Suite\Datawarehouse" 
	Start-Sleep -Seconds 1
	
	#ReportLoader file path
	[System.Windows.MessageBox]::Show("Please select the ReportLoader.exe file.`r`nExample: C:\Install\DO-UpgradeTools\Private\ODW\ReportLoader.exe ", "Select ODW Install File")
	$odwReportLoaderPath =Get-FileName -initialDirectory "C:\Omada\Install\"
	$ODWFolderPath = Split-Path -Path $odwReportLoaderPath  
	Start-Sleep -Seconds 1
	
	#$SSRSPath="C:\Program Files\Microsoft SQL Server\MSRS13.MSSQLSERVER\Reporting Services" #$toolPath = ('{0}\ReportServer\bin\Omada.ODW.SSRS.Utils.dll' -F $ssrsPath)
	$SSRSPath=OIS_GetServicePath -ServiceName SSRS -ServerName $SSRSServer -CheckRemote false
	$ScriptsPath=  Split-Path -Path $ODWFolderPath  #"E:\Powershell - moved from c drive\DO-UpgradeTools\Private" 
	#$reportsPath = Join-Path $ScriptsPath -ChildPath 'Private\ODW'
	$logPath = $ScriptsPath.Replace("DO-UpgradeTools\Private","Logs")
	$PSScriptRoot = Split-Path -Path $ScriptsPath
	$MSSQLServer = $MSSQL_ServerName.Text

	
	$argumentList = " -rsHttps $false -remoteDB $false -rsOnAppServer $false -rsServer $SSRSServer -odwUploadReportsToolPath $ODWFolderPath -odwInstallationPath $ODWInstPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName '' -SQLInstanceWithout '' -SSRSPath $SSRSUrl -credDB $null"
	$scriptPath = Join-Path -Path $ScriptsPath -ChildPath "\Publish-Reports.ps1"
	$t = $scriptPath+" -rsHttps $false -remoteDB $false -rsOnAppServer $false -rsServer $SSRSServer -odwUploadReportsToolPath $ODWFolderPath -odwInstallationPath $ODWInstPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName '' -SQLInstanceWithout '' -SSRSPath $SSRSUrl -credDB $null"

	Publish-SSRSReports  -rsHttps $false -remoteDB $false -rsOnAppServer $false -rsServer $SSRSServer -odwUploadReportsToolPath $ODWFolderPath -odwInstallationPath $ODWInstPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName $MSSQLServer -SQLInstanceWithout $MSSQLServer -SSRSPath $SSRSPath -credDB $null
	#Invoke-Expression "& $t" #"$scriptPath $argumentList"
<# Publish-Reports -rsHttps $false -remoteDB $false -rsOnAppServer $false -rsServer $SSRSServer -odwUploadReportsToolPath $ODWFolderPath -odwInstallationPath $ODWInstPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName '' -SQLInstanceWithout '' -SSRSPath $SSRSUrl -credDB $null #>

	#Output for testing:
	#$Output_SSRS_PreCheck.text += $SSRSPath


#  Publish-Reports -rsHttps $false -remoteDB $false -rsOnAppServer $false -rsServer $rsServer -odwUploadReportsToolPath $odwUploadReportsToolPath -odwInstallationPath $odwInstallationPath -logPath $logPath -scriptPath $PSScriptRoot -SQLInstanceName $SQLInstance -SQLInstanceWithout $SQLInstanceWithout -SSRSPath $SSRSPath -credDB $null
})


$Win.ShowDialog()