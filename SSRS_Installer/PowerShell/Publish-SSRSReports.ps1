Function Publish-Reports {
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



    $Output_SSRS_PreCheck.text +="Creating batch file to upload reports..." #-ForegroundColor Yellow
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
                
            $Output_SSRS_PreCheck.text +=   "Uplading reports..." #-ForegroundColor Yellow

            $f = ('"{0}\NativeLoadReports.bat" > "{1}"' -F $odwUploadReportsToolPath, $logFile)
            Invoke-Expression "& $f"
            $Output_SSRS_PreCheck.text +=   "Reports added" #-ForegroundColor Green
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
                        $Output_SSRS_PreCheck.text +=  "Omada.ODW.SSRS.Utils.dll is missing - fixing" #-ForegroundColor Yellow
                        Copy-Item -Path (Join-Path -Path $odwInstallationPath -ChildPath "Support Files\Omada.ODW.SSRS.Utils.dll") -Destination $toolPath  -Force
                        $Output_SSRS_PreCheck.text +=   "Fixed" #-ForegroundColor Green 
                    }
                }
                $Output_SSRS_PreCheck.text +=   "Uplading reports..." #-ForegroundColor Yellow

                $f = ('"{0}\NativeLoadReports.bat" > "{1}"' -F $odwUploadReportsToolPath, $logFile)
                Invoke-Expression "& $f"

                $Output_SSRS_PreCheck.text +=   "Reports added" #-ForegroundColor Green
            }
            else {
                $Output_SSRS_PreCheck.text +=   "Reporting server path not found, not critical error - skipping" #-ForegroundColor Red
                $Output_SSRS_PreCheck.text +=   ("({0}) {1}" -F $server, $ssrsPath) #-ForegroundColor Red
            }
        }

        if ($SQLInstance -eq 'localhost' -or $SQLInstance.startswith($env:ComputerName) -or $rsOnAppServer) {
            #$SSISInstance
            Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $rsUrl, $odwUploadReportsToolPath, $odwInstallationPath, $logPath, $SSRSPath, $SQLInstanceWithout
        }
        else {
            Invoke-Command -ScriptBlock $ScriptBlock -Credential $credDB -ComputerName $SQLInstanceWithout -ArgumentList $rsUrl, $odwUploadReportsToolPath, $odwInstallationPath, $logPath, $SSRSPath, $SQLInstanceWithout
        }
    }
}