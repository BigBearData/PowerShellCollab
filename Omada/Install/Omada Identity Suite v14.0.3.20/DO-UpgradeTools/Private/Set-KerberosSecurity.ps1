Function Set-KerberosSecurity{
    <#
    .SYNOPSIS
        Changes configuration so kerberos should be working
    .DESCRIPTION
        
    .PARAMETER ESBinding
        Binding of ES web site
    .PARAMETER ServiceUser
        Es service user
    .PARAMETER Domain
        User domain
    .PARAMETER FullDomain
        Full user domain
    .PARAMETER ComputerName
        Computer name where this function will be executed
    .PARAMETER Credential
        Credentials (if computer on which code is executed is remote)
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        Set-KerberosSecurity -ESBinding 'enterpriseserver' -ServiceUser 'srvc_omada' -Domain 'ldl' -FullDomain 'ldl.com' -ComputerName 'testIS' -Credential $cred -SQLNo '13'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$ESBinding,
    
    [Parameter (Mandatory)]
    [string]$ServiceUser,

    [Parameter (Mandatory)]
    [string]$Domain,

    [Parameter (Mandatory)]
    [string]$FullDomain,

    [string]$ComputerName = 'localhost',

    [Parameter (Mandatory)]
    [string]$SQLNo,

    $Credential,
    [Boolean]$IsCI = $false
    )

        $setKerberosDelegation = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]
            if ($report){
                Write-Host "Configuration of security for Kerberos on $env:ComputerName" -ForegroundColor Yellow
            }
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            #$groups = $id.Groups | foreach-object {
            #    $_.Translate([Security.Principal.NTAccount])
            #}
            $groups =  $id.Groups.Value
            if ($report){
                $admins = (Get-ADGroup -Filter '*' | Where-Object {$_.SID -like "S-1-5-21-*-512"}).sid.value
            }
            if ($isAppServer){
                if ($groups -contains $admins){
        
                    if ($report){
                        Write-Host "SPNs for ES web site are not set by OISIT tool" -ForegroundColor Yellow
                    }
                    <#Write-Host "Setting up SPNs for ES web site" -ForegroundColor Yellow
                    $param = ('-a',("http/{0}" -F $ESBinding),("{0}\{1}" -f $Domain,$ServiceUser)) 
                    $t = & 'C:\Windows\System32\setspn.exe' $param
                    if ($ESBinding -notlike '*.*'){
                        $param = ('-a',("http/{0}.{1}" -F $ESBinding,$FullDomain),("{0}\{1}" -f $Domain,$ServiceUser)) 
                        $t = & 'C:\Windows\System32\setspn.exe' $param
                    }#>
                    
                    if ($report){
                        Write-Host ("Trusting user {0} for delegation" -F $ServiceUser) -ForegroundColor Yellow
                    }
                    $accountName = $ServiceUser
                    $TRUSTED_FOR_DELEGATION = 524288;
                    $gc="GC://" + $([adsi] "LDAP://RootDSE").Get("RootDomainNamingContext")
                    $filter = ("(&(userPrincipalName={0}@{1}))" -F $ServiceUser, $FullDomain) #"(cn=$accountName)"
                    $domainl = New-Object System.DirectoryServices.DirectoryEntry($gc)
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = $domainl
                    $searcher.Filter = $filter
                    $results = $searcher.FindAll()
                    if($results.count -eq 0){ 
                        if ($report){
                            Write-Host ("User {0} not found - please set delegation manually, using 'Active directory users and computers' application" -F $accountName) -ForegroundColor Yellow 
                        }
        
                    }else{
                        foreach ($result in $results){
                            $dn=[string]$($result.properties["adspath"]).replace("GC://","LDAP://")
                            $account=New-Object System.DirectoryServices.DirectoryEntry($dn)
                            #"Trusting $($account.cn) for Delegation..."
                            $uac=$account.userAccountControl[0] -bor $TRUSTED_FOR_DELEGATION
                            $account.userAccountControl[0]=$uac
                            $result=$account.CommitChanges()
                            if ($report){
                                Write-Host "User $($account.cn) trusted for kerberos delegation" -ForegroundColor Green
                            }
                        }
                    }
        
                }else{
                    if ($report){
                        Write-Host "Current user is not a domain administration - skipping following:" -ForegroundColor Yellow
                        Write-Host "Set up of SPNs" -ForegroundColor Yellow
                        $param = ('-a',("http/{0}" -F $ESBinding),("{0}\{1}" -f $Domain,$ServiceUser)) 
                        Write-Host ('setspn.exe {0}' -f $param) -ForegroundColor Yellow
                        $param = ('-a',("http/{0}.{1}" -F $ESBinding,$FullDomain),("{0}\{1}" -f $Domain,$ServiceUser)) 
                        Write-Host ('setspn.exe {0}' -f $param) -ForegroundColor Yellow
                        Write-Host "Set up of kerberos delegation" -ForegroundColor Yellow
                    }
                }
            }
            else{
                    if ($report){
                    Write-Host "Script is run on Integration Services or Database server, skipping following:" -ForegroundColor Yellow
                    Write-Host "Set up of SPNs" -ForegroundColor Yellow
                    Write-Host "Set up of kerberos delegation" -ForegroundColor Yellow
                }
            }

        }

        $setBackupOperatorsUser = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]

            if ($report){
                Write-Host ("Adding {0} to local Backup Operators group" -f $ServiceUser) -ForegroundColor Yellow
            }
            try{
                $backOps = Get-ADGroup -Filter '*' | Where-Object {$_.SID -like "S-1-5-32-551"}
                Add-ADGroupMember $backOps -Member $ServiceUser
                if ($report){
                    Write-Host "User added" -ForegroundColor Green
                }
            }
            catch{
                if ($report){
                    Write-Host "User is already a member" -ForegroundColor Green
                }
            }
        
        }

        $setDCOMOnMachineLevel = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]

            if ($report){
                Write-Host "Changing DCOM access on machine level" -ForegroundColor Yellow 
            }
                $DSIdentity = ("{0}\{1}" -F $domain, $ServiceUser)
            $ID = new-object System.Security.Principal.NTAccount($DSIdentity)
            $sid = $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
            
            if ($report){
                Write-Host "Setting up Default Access Permission" -ForegroundColor Yellow
            }
            $DCOMSDDLDefaultLaunchPermission = "A;;CCDCLCSWRP;;;$sid"
            $DCOMSDDLDefaultAccessPermision = "A;;CCDCLC;;;$sid"
            $DCOMSDDLPartialMatch = "A;;\w+;;;$sid"
        
             # Get the respective binary values of the DCOM registry entries
             $Reg = [WMIClass]"\\$env:ComputerName\root\default:StdRegProv"
             $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
             $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue
        
             # Convert the current permissions to SDDL
             $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
             $CurrentDCOMSDDLDefaultLaunchPermission = $converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)
             $CurrentDCOMSDDLDefaultAccessPermission = $converter.BinarySDToSDDL($DCOMDefaultAccessPermission)
        
             # Build the new permissions
             if (($CurrentDCOMSDDLDefaultLaunchPermission.SDDL -match $DCOMSDDLPartialMatch) -and ($CurrentDCOMSDDLDefaultLaunchPermission.SDDL -notmatch $DCOMSDDLDefaultLaunchPermission))
             {
               $NewDCOMSDDLDefaultLaunchPermission = $CurrentDCOMSDDLDefaultLaunchPermission.SDDL -replace $DCOMSDDLPartialMatch, $DCOMSDDLDefaultLaunchPermission
             }
             else
             {
               $NewDCOMSDDLDefaultLaunchPermission = $CurrentDCOMSDDLDefaultLaunchPermission.SDDL + "(" + $DCOMSDDLDefaultLaunchPermission + ")"
             }
        
             if (($CurrentDCOMSDDLDefaultAccessPermission.SDDL -match $DCOMSDDLPartialMatch) -and ($CurrentDCOMSDDLDefaultAccessPermission.SDDL -notmatch $DCOMSDDLDefaultAccessPermision))
             {
               $NewDCOMSDDLDefaultAccessPermission = $CurrentDCOMSDDLDefaultAccessPermission.SDDL -replace $DCOMSDDLPartialMatch, $DCOMSDDLDefaultAccessPermision
             }
             else
             {
               $NewDCOMSDDLDefaultAccessPermission = $CurrentDCOMSDDLDefaultAccessPermission.SDDL + "(" + $DCOMSDDLDefaultAccessPermision + ")"
             }
        
             $DCOMbinarySDDefaultLaunchPermission = $converter.SDDLToBinarySD($NewDCOMSDDLDefaultLaunchPermission)
             $DCOMconvertedPermissionDefaultLaunchPermission = ,$DCOMbinarySDDefaultLaunchPermission.BinarySD
             $DCOMbinarySDDefaultAccessPermission = $converter.SDDLToBinarySD($NewDCOMSDDLDefaultAccessPermission)
             $DCOMconvertedPermissionsDefaultAccessPermission = ,$DCOMbinarySDDefaultAccessPermission.BinarySD
        
             if ($CurrentDCOMSDDLDefaultLaunchPermission.SDDL -match $DCOMSDDLDefaultLaunchPermission)
             {
                if ($report){
                    Write-Host "Current DefaultLaunchPermission matches desired value." -ForegroundColor Green
                }
             }
             else
             {   
               $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission", $DCOMbinarySDDefaultLaunchPermission.binarySD)
           
               if($result.ReturnValue='0'){if ($report){Write-Host "Applied DefaultLaunchPermission" -ForegroundColor Green}}
             }
        
             if ($CurrentDCOMSDDLDefaultAccessPermission.SDDL -match $DCOMSDDLDefaultAccessPermision)
             {
                if ($report){
                    Write-Host "Current DefaultAccessPermission matches desired value." -ForegroundColor Green
                }
             }
             else
             {
               $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission", $DCOMbinarySDDefaultAccessPermission.binarySD)
               if($result.ReturnValue='0'){if ($report){Write-Host "Applied DefaultAccessPermission" -ForegroundColor Green}}
        
             }
        }

        $setActivationPermissions = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]

            if ($report){
                Write-Host "Setting up Launch and Activation permissions" -ForegroundColor Yellow
            }
            $DSIdentity = ("{0}\{1}" -F $domain, $ServiceUser)
            $ID = new-object System.Security.Principal.NTAccount($DSIdentity)
            $sid = $ID.Translate( [System.Security.Principal.SecurityIdentifier] ).toString()
            $SDDL = "A;;CCWP;;;$sid"
            $DCOMSDDL = "A;;CCDCLCSWRP;;;$sid"
        
            $Reg = [WMIClass]"\\$env:ComputerName\root\default:StdRegProv"
            $DCOM = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
            $security = Get-WmiObject -ComputerName $env:ComputerName -Namespace root/cimv2 -Class __SystemSecurity
            $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
            $binarySD = @($null)
            $result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
            $outsddl = $converter.BinarySDToSDDL($binarySD[0])
            $outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
            $oldDCOMSDDL = $outDCOMSDDL.SDDL
            
            $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
            $newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
            $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
            $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
            $DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
            $DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD
        
            if ($oldDCOMSDDL.IndexOf($sid) -gt 0)
             {
                if ($report){
                    Write-Host ("User {0} has already Launch and Activation permissions set" -F $ServiceUser) -ForegroundColor Green
                }
             }
             else
             {  
                $result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
                $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction", $DCOMbinarySD.binarySD)
                if ($report){
                    Write-Host "Applied MachineAccessRestriction" -ForegroundColor Green 
                }
             }
        }
        $setAccessPermissions = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]

            if ($report){
                Write-Host "Setting up Access permissions" -ForegroundColor Yellow
             }
            $DCOMSDDL = "A;;CCDCLCSWRP;;;$sid"
            $Reg = [WMIClass]"\\$env:ComputerName\root\default:StdRegProv"
            $DCOM = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
            $security = Get-WmiObject -ComputerName $env:ComputerName -Namespace root/cimv2 -Class __SystemSecurity
            $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
            $binarySD = @($null)
            $result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
            $outsddl = $converter.BinarySDToSDDL($binarySD[0])
            $outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
            $oldDCOMSDDL = $outDCOMSDDL.SDDL
            $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
            $newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
            $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
            $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
            $DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
            $DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD
        
            if ($oldDCOMSDDL.IndexOf($sid) -gt 0)
             {
                if ($report){
                    Write-Host ("User {0} has already Access permissions set" -F $ServiceUser) -ForegroundColor Green
                }
             }
             else
             {  
                $result = $security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
                $result = $Reg.SetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction", $DCOMbinarySD.binarySD)
                if ($report){
                    Write-Host "Applied MachineAccessRestriction" -ForegroundColor Green 
                }
             }
        }
        $setWMISecurity = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]

            if ($report){
                Write-Host "Setting up WMI Namespace security" -ForegroundColor Yellow 
            }
            $namespace = 'root/cimv2'
            $operation = 'add'
            $account = ("{0}\{1}" -F $Domain, $ServiceUser)
            $permissions = 'Enable','RemoteAccess'
            $allowInherit = $true
            $deny = $false
            $computerName = $env:COMPUTERNAME
             Function Get-AccessMaskFromPermission($permissions) {
                $WBEM_ENABLE            = 1
                        $WBEM_METHOD_EXECUTE = 2
                        $WBEM_FULL_WRITE_REP   = 4
                        $WBEM_PARTIAL_WRITE_REP              = 8
                        $WBEM_WRITE_PROVIDER   = 0x10
                        $WBEM_REMOTE_ACCESS    = 0x20
                        $WBEM_RIGHT_SUBSCRIBE = 0x40
                        $WBEM_RIGHT_PUBLISH      = 0x80
                $READ_CONTROL = 0x20000
                $WRITE_DAC = 0x40000
                $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,`
                    $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,`
                    $READ_CONTROL,$WRITE_DAC
                $WBEM_RIGHTS_STRINGS = "Enable","MethodExecute","FullWrite","PartialWrite",`
                    "ProviderWrite","RemoteAccess","ReadSecurity","WriteSecurity"
        
                $permissionTable = @{}
        
                for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
                    $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
                }
                $accessMask = 0
        
                foreach ($permission in $permissions) {
                    if (-not $permissionTable.ContainsKey($permission.ToLower())) {
                        throw "Unknown permission: $permission`nValid permissions: $($permissionTable.Keys)"
                    }
                    $accessMask += $permissionTable[$permission.ToLower()]
                }
                $accessMask
            }
                $remoteparams = @{ComputerName=$env:COMPUTERNAME}
            $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $remoteParams
            $output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor
            if ($output.ReturnValue -ne 0) {
                throw "GetSecurityDescriptor failed: $($output.ReturnValue)"
            }
            $acl = $output.Descriptor
            $OBJECT_INHERIT_ACE_FLAG = 0x1
            $CONTAINER_INHERIT_ACE_FLAG = 0x2
            $computerName = (Get-WmiObject @remoteparams Win32_ComputerSystem).Name
            if ($account.Contains('\')) {
                $domainaccount = $account.Split('\')
                $domain = $domainaccount[0]
                if (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
                    $domain = $computerName
                }
                $accountname = $domainaccount[1]
            } elseif ($account.Contains('@')) {
                $domainaccount = $account.Split('@')
                $domain = $domainaccount[1].Split('.')[0]
                $accountname = $domainaccount[0]
            } else {
                $domain = $computerName
                $accountname = $account
            }
                $name = ('{0}@{1}' -F $accountName, $FullDomain)
            try{#sometimes sid cannot be translated - workaround to avoid crushing the installation...
                $accountSid = (Get-ADUser -Identity $accountName | select SID).sid.value
            }
            catch{}
            if ($accountSid -eq $null){
                if ($report){
                    Write-Host "Account was not found: $account, please set up WMI Namespace security manually..." -ForegroundColor Red
                }
            }
            else{
                switch ($operation) {
                    "add" {
                        if ($permissions -eq $null) {
                            throw "-Permissions must be specified for an add operation"
                        }
                        $accessMask = Get-AccessMaskFromPermission($permissions)
        
                        $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
                        $ace.AccessMask = $accessMask
                        if ($allowInherit) {
                            #
                            $ace.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
                            #
                        } else {
                            $ace.AceFlags = 0
                        }
                        $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
                        #$trustee.SidString = $win32account.Sid
                        $trustee.SidString = $accountSid
                        $ace.Trustee = $trustee
        
                        $ACCESS_ALLOWED_ACE_TYPE = 0x0
                        $ACCESS_DENIED_ACE_TYPE = 0x1
                        if ($deny) {
                            $ace.AceType = $ACCESS_DENIED_ACE_TYPE
                        } else {
                            $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
                        }
        
                        $acl.DACL += $ace.psobject.immediateBaseObject
                    }
        
                    "delete" {
                        if ($permissions -ne $null) {
                            throw "Permissions cannot be specified for a delete operation"
                        }
        
                        [System.Management.ManagementBaseObject[]]$newDACL = @()
                        foreach ($ace in $acl.DACL) {
                            #if ($ace.Trustee.SidString -ne $win32account.Sid) {
                            if ($ace.Trustee.SidString -ne $accountSid) {
                                $newDACL += $ace.psobject.immediateBaseObject
                            }
                        }
                        $acl.DACL = $newDACL.psobject.immediateBaseObject
                    }
        
                    default {
                        throw "Unknown operation: $operation`nAllowed operations: add delete"
                    }
                }
            }
        
            $setparams = @{Name="SetSecurityDescriptor";ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams
            $output = Invoke-WmiMethod @setparams
            if ($output.ReturnValue -ne 0) {
                throw "SetSecurityDescriptor failed: $($output.ReturnValue)"
            }
            try{
                if ($isAppServer){
                    Restart-Service "Winmgmt"
                }
                else{
                    Restart-Service "Winmgmt" -Force
                }
            }catch{}
            if ($report){
                Write-Host "WMI Namespace security changed" -ForegroundColor Green
            }
        }
        $setDCOMSecurity = {
            $ESBinding = $args[0]
            $ServiceUser = $args[1]
            $Domain = $args[2]
            $FullDomain = $args[3]
            $cred = $args[4]
            #run on app server
            $isAppServer = $args[5]
            $SQLNo = $args[6]
            $report = $args[7]

            if ($report){
                Write-Host "Changing DCOM Security for Windows Management and Instrumentation" -ForegroundColor Yellow
            }
            $UserName = $ServiceUser
              $appdesc = "Windows Management and Instrumentation"
              try{
                if ($report){
                    Write-Host "($env:ComputerName) Setting DCOM Launch Security of $appdesc for $UserName" -ForegroundColor Yellow
                }
                  $app = get-wmiobject -query ('SELECT * FROM Win32_DCOMApplicationSetting WHERE Description = "' + $appdesc + '"') -enableallprivileges
                  $sdRes = $app.GetLaunchSecurityDescriptor()
                  $sd = $sdRes.Descriptor
                  $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
                  $trustee.Domain = $Domain
                  $trustee.Name = $UserName
                  $fullControl = 31
                  $localLaunchActivate = 11
                  $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
                  #$ace.AccessMask = $localLaunchActivate
                  $ace.AccessMask = $fullControl
                  $ace.AceFlags = 0
                  $ace.AceType = 0
                  $ace.Trustee = $trustee
                  [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
                  $sd.DACL = $newDACL
                  $t = $app.SetLaunchSecurityDescriptor($sd)
                  if ($report){
                    Write-Host "($env:ComputerName) Setting DCOM Access Security of $appdesc for $UserName" -ForegroundColor Yellow
                  }
                  $app = get-wmiobject -query ('SELECT * FROM Win32_DCOMApplicationSetting WHERE Description = "' + $appdesc + '"') -enableallprivileges
                  $sdRes = $app.GetAccessSecurityDescriptor()
                  $sd = $sdRes.Descriptor
                  $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
                  $trustee.Domain = $domain
                  $trustee.Name = $UserName
                  $fullControl = 31
                  $localLaunchActivate = 11
                  $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
                  #$ace.AccessMask = $localLaunchActivate
                  $ace.AccessMask = $fullControl
                  $ace.AceFlags = 0
                  $ace.AceType = 0
                  $ace.Trustee = $trustee
                  [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
                  $sd.DACL = $newDACL
                  $t = $app.SetAccessSecurityDescriptor($sd)
              }
              catch{}
              $appdesc = ("Microsoft SQL Server Integration Services {0}.0" -F $SQLNo)
              try{
                  $app = get-wmiobject -query ('SELECT * FROM Win32_DCOMApplicationSetting WHERE Description = "' + $appdesc + '"') -enableallprivileges
                  if ($app -ne $null){
                    if ($report){
                        Write-Host "($env:ComputerName) Setting DCOM Launch Security of $appdesc for $UserName" -ForegroundColor Yellow
                    }
                      $sdRes = $app.GetLaunchSecurityDescriptor()
                      $sd = $sdRes.Descriptor
                      $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
                      $trustee.Domain = $Domain
                      $trustee.Name = $UserName
                      $fullControl = 31
                      $localLaunchActivate = 11
                      $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
                      #$ace.AccessMask = $localLaunchActivate
                      $ace.AccessMask = $fullControl
                      $ace.AceFlags = 0
                      $ace.AceType = 0
                      $ace.Trustee = $trustee
                      [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
                      $sd.DACL = $newDACL
                      $t = $app.SetLaunchSecurityDescriptor($sd)
                      if ($report){
                        Write-Host "($env:ComputerName) Setting DCOM Access Security of $appdesc for $UserName" -ForegroundColor Yellow
                    }
                      $app = get-wmiobject -query ('SELECT * FROM Win32_DCOMApplicationSetting WHERE Description = "' + $appdesc + '"') -enableallprivileges
                      $sdRes = $app.GetAccessSecurityDescriptor()
                      $sd = $sdRes.Descriptor
                      $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
                      $trustee.Domain = $domain
                      $trustee.Name = $UserName
                      $fullControl = 31
                      $localLaunchActivate = 11
                      $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
                      #$ace.AccessMask = $localLaunchActivate
                      $ace.AccessMask = $fullControl
                      $ace.AceFlags = 0
                      $ace.AceType = 0
                      $ace.Trustee = $trustee
                      [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
                      $sd.DACL = $newDACL
                      $t = $app.SetAccessSecurityDescriptor($sd)
                  }
              }
              catch{}
              $t = Set-DtcNetworkSetting -DtcName Local -AuthenticationLevel Incoming -InboundTransactionsEnabled $True -LUTransactionsEnabled $True -OutboundTransactionsEnabled $True -RemoteAdministrationAccessEnabled $True -RemoteClientAccessEnabled $True -XATransactionsEnabled $True -Confirm:$false
            if ($report){
              Write-Host "($env:ComputerName)DCOM Security for Windows Management and Instrumentation is set" -ForegroundColor Green
            }
        }

     $pos = $ComputerName.IndexOf(".")
    If ($ComputerName -eq 'localhost' -or $ComputerName -eq '.' -or (($pos -gt 0 -and ($ComputerName.Substring(0,$ComputerName.IndexOf(".")) -eq $env:COMPUTERNAME.ToLower())) -or $ComputerName -eq $env:COMPUTERNAME)){
        Show-Info -IsCI $IsCI -Message "Setting Kerberos delegation" -ForegroundColor Yellow 
        Invoke-Command -ScriptBlock $setKerberosDelegation -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
        Show-Info -IsCI $IsCI -Message "Adding user to local groups" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setBackupOperatorsUser -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
        Show-Info -IsCI $IsCI -Message "Setting DCOM security" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setDCOMOnMachineLevel -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
        Show-Info -IsCI $IsCI -Message "Setting Activation Permissions" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setActivationPermissions -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
        Show-Info -IsCI $IsCI -Message "Setting Access permissions" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setAccessPermissions -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
        Show-Info -IsCI $IsCI -Message "Setting WMI security" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setWMISecurity -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
        Show-Info -IsCI $IsCI -Message "Setting DCOM security" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setDCOMSecurity -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $true, $SQLNo, $true
    }else{
        Show-Info -IsCI $IsCI -Message "Setting Kerberos delegation" -ForegroundColor Yellow 
        Invoke-Command -ScriptBlock $setKerberosDelegation -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
        Show-Info -IsCI $IsCI -Message "Adding user to local groups" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setBackupOperatorsUser -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
        Show-Info -IsCI $IsCI -Message "Setting DCOM security" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setDCOMOnMachineLevel -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
        Show-Info -IsCI $IsCI -Message "Setting Activation Permissions" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setActivationPermissions -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
        Show-Info -IsCI $IsCI -Message "Setting Access permissions" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setAccessPermissions -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
        Show-Info -IsCI $IsCI -Message "Setting WMI security" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setWMISecurity -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
        Show-Info -IsCI $IsCI -Message "Setting DCOM security" -ForegroundColor Yellow
        Invoke-Command -ScriptBlock $setDCOMSecurity -ComputerName $ComputerName -Credential $Credential -ArgumentList $ESBinding, $ServiceUser, $Domain, $FullDomain, $Credential, $false, $SQLNo, $false
    }
	if ($report){
		Show-Info -IsCI $IsCI -Message "Security for Kerberos configured on $ComputerName" -ForegroundColor DarkGreen
	}


}
