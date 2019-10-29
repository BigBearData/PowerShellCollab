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
            Get-SQLName -SQLInstance 'testdb\instancename,6666' -rsOnAppServer $true
        #>
        [cmdletbinding(SupportsShouldProcess)]
        Param(
        [Parameter (Mandatory)]
        [string]$SQLInstance,

        [Parameter (Mandatory)]
        [bool]$rsOnAppServer
        )

         $SQLName = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain

         #strip from port
         if ($SQLInstance.IndexOf(",") -ge 0){
            Show-Info -IsCI $IsCI -Message "SQL server is using nondefault port" -ForegroundColor Yellow
            $SQLInstance = $SQLInstance.Substring(0, $SQLInstance.IndexOf(","))
         }
         else{
               Show-Info -IsCI $IsCI -Message "SQL server is using default port" -ForegroundColor Yellow
         }
         #strip for instace
         if ($SQLInstance.IndexOf("\") -ge 0){
            Show-Info -IsCI $IsCI -Message "SQL server is using named instance" -ForegroundColor Yellow
            $SQLInstanceWithout = $SQLInstance.Substring(0, $SQLInstance.IndexOf("\"))
	   		$SQLInstanceName = $SQLInstance.Substring($SQLInstance.IndexOf("\") + 1)
         }
         else{
            Show-Info -IsCI $IsCI -Message "SQL server is using default instance" -ForegroundColor Yellow
            $SQLInstanceWithout = $SQLInstance
   			$SQLInstanceName = $null
         }
 
         #check where rs should be
         if($rsOnAppServer){
            Show-Info -IsCI $IsCI -Message "SSRS on App server will be used" -ForegroundColor Yellow
            $rsServer = $env:COMPUTERNAME
         }else{
            Show-Info -IsCI $IsCI -Message "SSRS on SQL server will be used" -ForegroundColor Yellow
            $rsServer = $SQLName
         }
         #check if remoteDB is true
         if($SQLInstance.StartsWith(".")){
            Show-Info -IsCI $IsCI -Message ("Local SQL will be used, name will be translated to {0}" -f (Get-WmiObject win32_computersystem).DNSHostName) -ForegroundColor Yellow
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith("localhost")){
            Show-Info -IsCI $IsCI -Message ("Local SQL will be used, localhost will be translated to {0}" -f (Get-WmiObject win32_computersystem).DNSHostName) -ForegroundColor Yellow
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith((Get-WmiObject win32_computersystem).DNSHostName)){
            Show-Info -IsCI $IsCI -Message "Local SQL will be used." -ForegroundColor Yellow
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith($env:COMPUTERNAME)){
            Show-Info -IsCI $IsCI -Message ("Remote SQL will be used: {0}" -f $SQLInstanceWithout) -ForegroundColor Yellow
            $remoteDB = $false
         }else{
            $remoteDB = $true
         }

         $result = @(
            New-Object PSObject -Property @{SQLName = $SQLName; SQLInstanceWithout = $SQLInstanceWithout; rsServer = $rsServer; remoteDB = $remoteDB; SQLInstanceName = $SQLInstanceName}
         )
 
         return $result

}