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

         $SQLName = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain

         #strip for cluster node
         if ($SQLInstance.IndexOf(";") -ge 0){
            $Output_SSRS_PreCheck.text += "SQL server is using cluster`r`n" 
            $SQLInstance = $SQLInstance.Substring(0, $SQLInstance.IndexOf(";"))
	   		$SQLNodeName = $SQLInstance.Substring($SQLInstance.IndexOf(";") + 1)
         }
         else{
            Show-Info -IsCI $IsCI -Message "SQL server is not using cluster`r`n" 
         }
         #strip from port
         if ($SQLInstance.IndexOf(",") -ge 0){
            $Output_SSRS_PreCheck.text += "SQL server is using nondefault port`r`n" 
            $SQLInstance = $SQLInstance.Substring(0, $SQLInstance.IndexOf(","))
         }
         else{
               Show-Info -IsCI $IsCI -Message "SQL server is using default port`r`n" 
         }
         #strip for instace
         if ($SQLInstance.IndexOf("\") -ge 0){
            $Output_SSRS_PreCheck.text += "SQL server is using named instance`r`n" 
            $SQLInstanceWithout = $SQLInstance.Substring(0, $SQLInstance.IndexOf("\"))
	   		$SQLInstanceName = $SQLInstance.Substring($SQLInstance.IndexOf("\") + 1)
         }
         else{
            $Output_SSRS_PreCheck.text += "SQL server is using default instance`r`n" 
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
         if($SQLInstance.StartsWith(".")){
            $Output_SSRS_PreCheck.text += "Local SQL will be used, name will be translated to {0}`r`n"  -f (Get-WmiObject win32_computersystem).DNSHostName
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith("localhost")){
            $Output_SSRS_PreCheck.text += "Local SQL will be used, localhost will be translated to {0}`r`n" -f (Get-WmiObject win32_computersystem).DNSHostName
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith((Get-WmiObject win32_computersystem).DNSHostName)){
            $Output_SSRS_PreCheck.text += "Local SQL will be used.`r`n" 
            $remoteDB = $false
         }elseif ($SQLInstance.StartsWith($env:COMPUTERNAME)){
            $Output_SSRS_PreCheck.text += "Remote SQL will be used: {0}`r`n"  -f $SQLInstanceWithout
            $remoteDB = $false
         }else{
            $remoteDB = $true
         }

         $result = @(
            New-Object PSObject -Property @{SQLName = $SQLName; SQLInstanceWithout = $SQLInstanceWithout; rsServer = $rsServer; remoteDB = $remoteDB; SQLInstanceName = $SQLInstanceName; SQLNodeName = $SQLNodeName}
         )
 
         return $result

}