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
              Show-Info -IsCI $IsCI -Message "Setting DCOM Access Security for $UserName on local machine" -ForegroundColor Yellow
          }
          else{
              Show-Info -IsCI $IsCI -Message "($SQLServer) Setting DCOM Access Security for $UserName" -ForegroundColor Yellow
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
        write-host "Setting DCOM Launch Security for $UserName" -ForegroundColor Yellow
        $t = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $UserName, $Domain, $SQLVersion, $SQLServer
    }
    else{
        Show-Info -IsCI $IsCI -Message "($SQLServer) Setting DCOM Launch Security for $UserName" -ForegroundColor Yellow
        $t = Invoke-Command -ComputerName $SQLServer -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $UserName, $Domain, $SQLVersion, $SQLServer
    }

}
 #Set-DCOMSecurity -UserName "administrator" -Domain "megamart" -SQLVersion "11" -SQLServer "localhost" -Credential $null