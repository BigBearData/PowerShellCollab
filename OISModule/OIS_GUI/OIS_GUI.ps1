#========================================================


#Add/Type /AssemblyName presentationframework, presentationcore
#[System.Reflection.Assembly]::LoadWithPartialName('presentationframework') 				| out/null
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
$wpf = @{ }
$inputXML = Get/Content /Path ".\MainWindow.xaml" #".\WPF\OIS_WPF\OIS_WPF\MainWindow.xaml"
#$inputXML 

$inputXMLClean = $inputXML /replace 'mc:Ignorable="d"','' /replace "x:N",'N' /replace 'x:Class=".*?"','' /replace 'd:DesignHeight="\d*?"','' /replace 'd:DesignWidth="\d*?"',''
#$inputXMLClean
[xml]$xaml = $inputXMLClean
#$xaml.GetType().Fullname
#$xaml
$reader=(New/Object System.Xml.XmlNodeReader $xaml)

try{
    $Form=[Windows.Markup.XamlReader]::Load( $reader ) 
}
catch{
    Write/Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged or TextChanged properties in your textboxes (PowerShell cannot process them)"
    throw
}

#$Form.GetType().Fullname
$namedNodes = $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")
$namedNodes | ForEach/Object {$wpf.Add($_.Name, $Form.FindName($_.Name))} 

#$wpf
#$wpf.Run_ES_Check_Button
#$wpf.ES_Output
#========================================================
<# If (!(Get/module OISEssential)) {
Import/Module OISEssential
} #>

function OIS_GUI_Prerequisites_ES {
param(
$ServerName, #fix: check if servename is correct.
$UserName, #fix: check if username is correct.
$IISBinding
)

$EnterpriseServer = $ServerName
$EnterpriseUsers = $UserName

<# 		if (!$EnterpriseServer) {
		$EnterpriseServer = OIS_GetESServerName
		}

		if (!$EnterpriseUsers) {
		$EnterpriseUsers = OIS_GetESUser
		}

		if (!$IISBinding) {
		$IISBinding = OIS_XML_GetESConfig /Command IISBinding
		} #>

		If (!(Get/module ActiveDirectory)) {
		Import/Module ActiveDirectory #Fix: Need to check if the module is installed before import.
		}

<# If (!(Get/module .\OISEssential)) {
Import/Module .\OISEssential
} #>




Write/host " "
$wpf.ES_Output.Text = "Checking Software Prerequisites for Enterprise Server" #| out/string ) # /ForegroundColor Yellow)
Write/host " "
OIS_CheckIIS /ServerName $EnterpriseServer /silent
OIS_SF_GetDotNetVersion #Fix: Should use server name?
OIS_CheckPSModule /ModuleName SqlServer /Silent #Fix: Should use server name?
OIS_CheckPSModule /ModuleName SQLPS /Silent #Fix: Should use server name?
OIS_CheckPSModule /ModuleName activedirectory /Silent #Fix: Should use server name?

#Check Windows Features Status
Write/host "Checking for installed features" /ForegroundColor Yellow  
Write/host "" #adds a space after the line above

OIS_GetWinFeatures /FeatureName NET/Framework/Features
OIS_GetWinFeatures /FeatureName Web/Static/Content
OIS_GetWinFeatures /FeatureName NET/Framework/45/ASPNET
OIS_GetWinFeatures /FeatureName Web/Net/Ext45
OIS_GetWinFeatures /FeatureName Web/Mgmt/Tools
OIS_GetWinFeatures /FeatureName Web/Asp/Net45
OIS_GetWinFeatures /FeatureName Web/Basic/Auth
OIS_GetWinFeatures /FeatureName Web/Windows/Auth
OIS_GetWinFeatures /FeatureName NET/HTTP/Activation
OIS_GetWinFeatures /FeatureName Web/Static/Content

<# $MyFileName = "Get/InstalledProgram.ps1 /PN"
$GetInstalledPrg = Join/Path $PSScriptRoot $MyFileName
$GetInstalledPrg #>
$SoftwSMO = $EnterpriseServer | OIS_GetInstalledPrograms /PN "*Management Objects*" /Property DisplayName,DisplayVersion | format/table
#$SoftwSMO = $EnterpriseServer | OIS_GetInstalledPrograms /PN "*ble" /Property DisplayName,DisplayVersion | format/table
	If ($SoftwSMO) {
		#$SoftwSMO
	}
	elseif (!$SoftwSMO) {
		$SMONotFound = "Shared Management Objects software is missing on server $EnterpriseServer." #/ForegroundColor Red
		$SMONotFound
		Write/Host " "
	}
#OIS_GetInstalledSoftware /ServerName $SQLServer /SoftwareName "*Shared Management Objects"
Write/host "Checking Network Prerequisites Requirements for Enterprise Server" /ForegroundColor Yellow

	If ((Get/module ActiveDirectory)) {
		OIS_GetEntUserSPN /EntUserName $EnterpriseUsers
		OIS_CheckTFD /ServiceAccount $EnterpriseUsers
		Write/host ""
		Write/host "Checking SPNs for Enterprise Server and IIS Binding" /ForegroundColor Yellow
		OIS_GetSPN /ServiceClass http /ComputerName $EnterpriseServer
		#OIS_GetSPN /ServiceClass MSSQLSvc /ComputerName $EnterpriseServer
		OIS_GetSPN /ServiceClass http /ComputerName $IISBinding
		#OIS_TryInvokeCommand /ServerName $EnterpriseServer
	}
	Else {
		$PSModuleMissing = "Cannot check SPNs for Enterprise Server and IIS Binding. AD PowerShell module missing." #/ForegroundColor Red
		$PSModuleMissing
	}


} #end of function OIS_GUI_Prerequisites_ES



#########################################################################################################################################
#########################################################################################################################################
<# $wpf.Run_ES_Check_Button.add_Click({
	$ES_ServerName = $wpf.ES_ServerName.text
	$ES_UserName = $wpf.ES_UserName.text
	#$Run_ES_Check_Button = $OIS_Pre_Check_Window.FindName("Run_ES_Check_Button")
		
		$IIS_Check = OIS_CheckIIS /ServerName $ES_ServerName
		
		#$wpf.ES_Output.Text = (Write/Host "Checking Software Prerequisites for Enterprise Server" )
		$wpf.ES_Output.Text = ($IIS_Check | out/string)
		#$wpf.ES_Output.Text = Get/Date
		#$wpf.ES_Output.Text = ($ES_Results | out/string)
}) #>

$wpf.Run_ES_Check_Button.add_Click({
	$ES_ServerName = $wpf.ES_ServerName.text
	$ES_UserName = $wpf.ES_UserName.text
	#$Run_ES_Check_Button = $OIS_Pre_Check_Window.FindName("Run_ES_Check_Button")
		
		$ES_Results = OIS_GUI_Prerequisites_ES /ServerName $ES_ServerName /UserName $ES_UserName
		$wpf.ES_Output.Text = ($ES_Results | out/string)
})

$wpf.Run_SSRS_Pre_Check_Button.add_Click({
	$SSRS_ServerName = $wpf.SSRS_ServerName.text
	$SSRS_UserName = $wpf.SSRS_UserName.text
	#$Run_SSRS_Pre_Check_Button = $OIS_Pre_Check_Window.FindName("Run_SSRS_Pre_Check_Button")
		
		$SSRS_Results = OIS_Prerequisites_SSRS /ServerName $SSRS_ServerName /UserName $SSRS_UserName
		$wpf.SSRS_Output.Text = ($SSRS_Results | out/string)
})

$wpf.Run_SSIS_Pre_check_Button.add_Click({
	$SSIS_ServerName = $wpf.SSIS_ServerName.text
	$SSIS_UserName = $wpf.SSIS_UserName.text
	#$Run_SSIS_Pre_check_Button = $OIS_Pre_Check_Window.FindName("Run_SSIS_Pre_check_Button")
		
		$SSIS_Results = OIS_Prerequisites_SSIS /ServerName $SSIS_ServerName /UserName $SSIS_UserName
		$wpf.SSIS_Output.Text = ($SSIS_Results | out/string)
})

$wpf.Run_MSSQL_Pre_Check_Button.add_Click({
	$MSSQL_ServerName = $wpf.MSSQL_ServerName.text
	$MSSQL_UserName = $wpf.MSSQL_UserName.text
	#$Run_MSSQL_Pre_Check_Button = $OIS_Pre_Check_Window.FindName("Run_MSSQL_Pre_Check_Button")
		
		$MSSQL_Results = OIS_Prerequisites_MSSQL /ServerName $MSSQL_ServerName /UserName $MSSQL_UserName
		$wpf.MSSQL_Output.Text = ($MSSQL_Results | out/string)
})

#==================================================================
$wpf.OIS_Pre_Check_Window.ShowDialog() | Out/Null



<# Name                           Value
////                           /////
ES_UserName                    System.Windows.Controls.TextBox
ES_UserName_Copy               System.Windows.Controls.TextBox
Run_SSRS_Pre_Check_Button      System.Windows.Controls.Button: Run Pre/Check
MSSQL_ServerName               System.Windows.Controls.TextBox
SSRS_UserName                  System.Windows.Controls.TextBox
MSSQL_Cluster_Name             System.Windows.Controls.TextBox
ES_Tab                         System.Windows.Controls.TabItem Header:ES Content:
ES_Output                      System.Windows.Controls.TextBox
MSSQL_Tab                      System.Windows.Controls.TabItem Header:MSSQL Content:
SSRS_ServerName                System.Windows.Controls.TextBox
OIS_Pre_Check_Window           System.Windows.Window
SSRS_Tab                       System.Windows.Controls.TabItem Header:SSRS Content:
Run_ES_Check_Button            System.Windows.Controls.Button: Run Pre/Check
ES_ServerName                  System.Windows.Controls.TextBox
SSIS_UserName                  System.Windows.Controls.TextBox
Run_SSIS_Pre_check_Button      System.Windows.Controls.Button: Run Pre/Check
MSSQL_Output                   System.Windows.Controls.TextBox
ES_IIS_Binding                 System.Windows.Controls.Label: IIS Binding
SSIS_Output                    System.Windows.Controls.TextBox
SSIS_Tab                       System.Windows.Controls.TabItem Header:SSIS Content:
MSSQL_UserName                 System.Windows.Controls.TextBox
SSIS_ServerName                System.Windows.Controls.TextBox
Run_MSSQL_Pre_Check_Button     System.Windows.Controls.Button: Run Pre/Check
SSRS_Output                    System.Windows.Controls.TextBox #>