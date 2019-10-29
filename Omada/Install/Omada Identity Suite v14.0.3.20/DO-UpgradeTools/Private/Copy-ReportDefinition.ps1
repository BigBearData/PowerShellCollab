Function Copy-ReportDefinition {
    <#
    .SYNOPSIS
        Script copies report definitions
    .DESCRIPTION
        Script is used when reports are uploaded to App server on multiserver environment
    .PARAMETER SSISInstance
        Server with SSIS
    .PARAMETER SQLInstance
        SQL instance
    .PARAMETER targetServer
        Server where reports need to be copied to.
    .PARAMETER odwInstallationPath
        Path to ODW
    .PARAMETER credDB
        Credentials for DB server
    .PARAMETER scriptPath
        Path to powershell script
    .PARAMETER SSRSPath
        Path to SSRS
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Copy-ReportDefinition -SSISInstance 'testis' -SQLInstance 'testdb' -SQLInstanceWithout 'testdb' -odwInstallationPath 'C:\Powershell' -credDB $null -scriptPath 'C:\Powershell' -SSRSPath 'c:\powershell\ssrs' -IsCI $true
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
        [Parameter (Mandatory)]
        [string]$SSISInstance,

        [Parameter (Mandatory)]
        $credDB,

        [Parameter (Mandatory)]
        [string]$SQLInstance,

        [Parameter (Mandatory)]
        [string]$targetServer,

        [Parameter (Mandatory)]
        [string]$odwInstallationPath,

        [Parameter (Mandatory)]
        [string]$scriptPath,

        [Parameter (Mandatory)]
        [string]$SSRSPath,

        [Boolean]$IsCI = $false

    )

    $ScriptBlock = {
        $source = Join-Path -Path $args[0] -ChildPath 'Support Files\Omada.ODW.SSRS.Utils.dll'
        $destination = Join-Path -Path $args[1] -ChildPath 'Private\ODW\Omada.ODW.SSRS.Utils.dll'
        $t = Copy-Item -Path $source -Destination $destination -Force
                    
        $source = Join-Path -Path $args[0] -ChildPath 'Support Files\SSRS Reports'
        $destination = Join-Path -Path $args[1] -ChildPath 'Private\ODW\SSRS Reports'
        $t = Copy-Item -Path $source -Destination $destination -Force -Recurse
    }
    Show-Info -IsCI $IsCI -Message ("Reports will be uploaded to {0}, copying Omada.ODW.SSRS.Utils.dll from {1}" -F $targetServer, $SSISInstance) -ForegroundColor Yellow
    Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $odwInstallationPath, $scriptPath
    if ($env:COMPUTERNAME -eq $targetServer) {
        $p = Join-Path -Path $scriptPath -ChildPath 'Private\ODW\Omada.ODW.SSRS.Utils.dll'
        $p2 = Join-Path -Path $scriptPath -ChildPath 'Private\ODW\SSRS Reports'
    }
    else {
        $p = ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\ODW\Omada.ODW.SSRS.Utils.dll" -F $targetServer) 
        $p2 = ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\ODW\SSRS Reports" -F $targetServer)
        $p4 = ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\rssrvpolicy.config" -F $targetServer)
    }
    if (Test-Path -Path $p2) {
        $t = Get-ChildItem -Path $p2 -Include *.* -Recurse | foreach { try {$_.FullName | Remove-Item -Force}catch {}} -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path -Path $p -ChildPath '*') -Force -Recurse
    }
    else {
        $t = New-Item -Path $p2 -ItemType Directory
    }
    if ($env:COMPUTERNAME -eq $targetServer) {
        try{
            Copy-Item -Path ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\ODW\Omada.ODW.SSRS.Utils.dll" -F $SSISInstance) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\c$\Powershell\Do-UpgradeTools\Private\ODW\Omada.ODW.SSRS.Utils.dll" -F $targetServer) -Force
            Copy-Item -Path ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\rssrvpolicy.config" -F $SSISInstance) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\c$\Powershell\Do-UpgradeTools\Private\rssrvpolicy.config" -F $targetServer) -Force -ErrorAction SilentlyContinue
            Copy-Item -Path ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\ODW\SSRS Reports\*" -F $SSISInstance) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\c$\Powershell\Do-UpgradeTools\Private\ODW\SSRS Reports" -F $targetServer) -Force -Recurse -ErrorAction SilentlyContinue
        }catch{
            Write-Host ("there was a problem with copy of files required by the ODW reports: {0} This is not a critical error..." -f $_.Exception.Message) -BackgroundColor Red
        }
    }
    else {
        try {
            Copy-Item -Path ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\ODW\Omada.ODW.SSRS.Utils.dll" -F $SSISInstance) -Destination $p -Force
            Copy-Item -Path ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\rssrvpolicy.config" -F $SSISInstance) -Destination $p4 -Force -ErrorAction SilentlyContinue
            Copy-Item -Path ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\Private\ODW\SSRS Reports\*" -F $SSISInstance) -Destination $p2 -Force -Recurse -ErrorAction SilentlyContinue
        }catch{
            Write-Host ("there was a problem with copy of files required by the ODW reports: {0} This is not a critical error..." -f $_.Exception.Message) -BackgroundColor Red
        }
    }
    $scriptBlock = {
        $scriptPath = $args[0]
        $p2 = $args[1]
        $SQLInstance = $args[2]
        $SSRSPath = $args[3]
        $p = $args[4]
        $p3 = Join-Path -Path $scriptPath -ChildPath 'Private\ODW\SSRS Reports\SSRS Reports'
        if (Test-Path -Path $p3) {
            $t = Remove-Item -Path $p3 -Force -Recurse
        }
        #change the sql in datasource
        $f = Get-ChildItem -Path $p2 -Recurse -Filter 'ODW.rds'
        $c = Get-Content -Encoding UTF8 -Path $f.FullName 
        $c = $c.Replace('(local)', $SQLInstance)
        $c | Set-Content -Path $f.FullName -Force
        $f = Get-ChildItem -Path $p2 -Recurse -Filter 'ESARC.rds'
        $c = Get-Content -Encoding UTF8 -Path $f.FullName 
        $c = $c.Replace('(local)', $SQLInstance)
        $c | Set-Content -Path $f.FullName -Force
        $d = Join-Path -Path $SSRSPath -ChildPath 'ReportServer\bin\Omada.ODW.SSRS.Utils.dll'
        Copy-Item -Path $p -Destination $d -Force
        #get the value from rssrvpolicy and add it to proper one...
        $pathSource = Join-Path -Path $scriptPath -ChildPath 'Private\rssrvpolicy.config'
        $pathDest = Join-Path -Path $SSRSPath -ChildPath 'ReportServer\rssrvpolicy.config'
        if ((Test-Path $pathSource) -and (Test-Path $pathDest)) {
            [xml]$xmlSource = Get-Content -Encoding UTF8 $pathSource
            $tXml = ($xmlSource.configuration.mscorlib.security.policy.policyLevel.CodeGroup | select -ExpandProperty childnodes | where {$_.class -like 'FirstMatchCodeGroup*'}).InnerXml
            [xml]$xmlDest = Get-Content -Encoding UTF8 $pathDest
            if (($xmlDest.configuration.mscorlib.security.policy.policyLevel.CodeGroup | select -ExpandProperty childnodes | where {$_.class -like 'FirstMatchCodeGroup*'} | select -ExpandProperty childnodes | where {$_.name -like 'Omada.ODW.SSRS.Utils'}) -eq $null) {
                ($xmlDest.configuration.mscorlib.security.policy.policyLevel.CodeGroup | select -ExpandProperty childnodes | where {$_.class -like 'FirstMatchCodeGroup*'}).InnerXml += $tXml
                $xmlDest.Save($pathDest)
            }
        }
        else {
            Write-Host ("rssrvpolicy.config is missing, skipping update of its content") -ForegroundColor Yellow
        }

    }
    if ($env:COMPUTERNAME -eq $targetServer) {
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $scriptPath, $p2, $SQLInstance, $SSRSPath, $p
    }
    else {
        Invoke-Command -ComputerName $targetServer -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $scriptPath, $p2, $SQLInstance, $SSRSPath, $p
    }
}
