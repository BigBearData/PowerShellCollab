Function Copy-FilesToRemoteServers {
    
        <#
        .SYNOPSIS
            Copies files used in installation process to remote servers
        .DESCRIPTION
            When this is a multiserver installation, this script copies files to DB and SSIS servers
        .PARAMETER SSISInstance
            Name of the computer with SSIS
        .PARAMETER SQLInstanceWithout
            Name of the computer with SQL (if named instance, then the instance name needs to be removed)
        .PARAMETER credDB
            Credential used to connect to both SSIS and SQL computers
        .PARAMETER tempPath
            Path to temporary folder on App server
        .PARAMETER logPath
            Path to logs
        .PARAMETER scriptsPath
            Path to scripts
        .PARAMETER administratorDomain
            Domain of administrator user
        .PARAMETER administratorUser
            Administrator user
        
        .EXAMPLE
            Copy-FilesToRemoteServers -SSISInstance 'testis' -SQLInstanceWithout 'testdb' -credDB $null -tempPath 'c:\powershell\install' -logPath 'C:\powershell\logs' -scriptsPath 'C:\Powershell\DO-UpdateTools' -administratorDomain 'megamart' -administratorUser 'administrator'
        #>
        [cmdletbinding(SupportsShouldProcess)]
        Param(
        [Parameter (Mandatory)]
        [string]$SSISInstance,
        
        [Parameter (Mandatory)]
        [string]$SQLInstanceWithout,
    
        [Parameter (Mandatory)]
        $credDB,
    
        [Parameter (Mandatory)]
        [string]$tempPath,
    
        [Parameter (Mandatory)]
        [string]$logPath,
    
        [Parameter (Mandatory)]
        [string]$scriptsPath<#,
    
        [Parameter (Mandatory)]
        [string]$administratorDomain,
    
        [Parameter (Mandatory)]
        [string]$administratorUser    #>
        )

    $ScriptBlock = {
                #$administratorDomain = $args[3]
                #$administratorUser = $args[4]
        $name = "OmadaInstall"
        foreach ($s in $args){
            if (!(Test-Path $s)) { 
                new-item $s -type Directory }
            else{
                Get-ChildItem -Path $s -Recurse | Remove-Item -force -recurse
            }
            $Shares=[WMICLASS]"WIN32_Share"
            #remove share if one existed (from previous installations)
            If (Test-Path -Path ("\\localhost\{0}" -F $name)){
                Remove-SmbShare -Name $name -Force
            }
            #create share
            $Shares.Create($s,$name,0) 
            #grant access
            Grant-SmbShareAccess -name $name -AccountName "Everyone" -AccessRight Full -Force #("{0}\{1}" -F $administratorDomain, $administratorUser)
            if ($name -eq "OmadaInstall"){
                $name = "OmadaLogs"
            }
            elseif ($name -eq "OmadaLogs"){
                $name = "OmadaScript"
            }
        }
    }
    if ($SSISInstance.Split('.')[0].ToUpper() -ne $env:ComputerName.ToUpper() -or (!$SSISInstance.Split('.')[0].ToUpper().StartsWith($env:ComputerName.ToUpper()))){
		$t = Invoke-Command -ComputerName $SSISInstance -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $tempPath,$logPath, $scriptsPath #, $administratorDomain, $administratorUser
		Copy-Item -Path ("{0}\*" -F $tempPath) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaInstall\" -F $SSISInstance) -Recurse -Force
		Copy-Item -Path ("{0}\*" -F $scriptsPath) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\" -F $SSISInstance) -Recurse -Force 
	}
    if ($SQLInstanceWithout -ne $SSISInstance){
	    if ($SQLInstanceWithout.ToUpper() -ne $env:ComputerName.ToUpper() -or (!$SQLInstanceWithout.ToUpper().StartsWith($env:ComputerName.ToUpper()))){
			$t = Invoke-Command -ComputerName $SQLInstanceWithout -Credential $credDB -ScriptBlock $ScriptBlock -ArgumentList $tempPath,$logPath, $scriptsPath #, $administratorDomain, $administratorUser
			Copy-Item -Path ("{0}\*" -F $tempPath) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaInstall\" -F $SQLInstanceWithout) -Recurse -Force
			Copy-Item -Path ("{0}\*" -F $scriptsPath) -Destination ("Microsoft.PowerShell.Core\FileSystem::\\{0}\OmadaScript\" -F $SQLInstanceWithout) -Recurse -Force 
		}
    }
}