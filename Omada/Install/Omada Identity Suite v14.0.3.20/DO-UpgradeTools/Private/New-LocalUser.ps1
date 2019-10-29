
Function New-LocalUser {

    <#
    .SYNOPSIS
        Creates local user
    .DESCRIPTION
        Creates user on local machine
    .PARAMETER UserName
        Name of new user
    .PARAMETER Password
        Password of new user
    .PARAMETER Description
        Description of user
    .PARAMETER Type
        Type of user
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
        New-LocalUser -UserName "srvc_omada9" -Password "Omada12345" -Description "Service user for omada products" -Type "Service" -fullDomain "megamart.com" -tempPath "C:\Powershell\install" -logPath "C:\Powershell\logs"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$UserName,
    
    [Parameter (Mandatory)]
    [string]$Password,

    [Parameter ()]
    [string]$Description,

    [Parameter ()]#left for legacy reasons
    [boolean]$OverridePolicy = $false,

    [Parameter ()]
    [string]$fullDomain,

    [Parameter ()]
    [string]$tempPath,
    
    [Parameter ()]
    [string]$logPath,

    [Parameter (Mandatory)]
    [ValidateSet("Service", "User", "Administrator")]
    [string]$Type,

    [Parameter ()]
    [string]$SQLInstance = 'localhost',
    
    [Parameter ()]
    [string]$SSISInstance = 'localhost',
    
    $CredDB,
    $domain,
    [Boolean]$IsCI = $false
    )
	$uexists = Get-ADUser -Filter {sAMAccountName -eq $UserName}
    if ($uexists -ne $null){#(dsquery user -samid $UserName)
        Show-Info -IsCI $IsCI -Message ("User {0} already exists" -F $UserName) -ForegroundColor Green
    }
    else{

        $principalName = ("{0}@{1}" -F $UserName, $fullDomain)
        $t = $fullDomain.Split(".")
        $path = "CN=Users"
        for($i = 0;$i -lt $t.Length;$i++){
            $path += ",DC=" + $t[$i]
        }
        Show-Info -IsCI $IsCI -Message ("Adding user {0} to path {1}" -F $UserName,$path) -ForegroundColor Yellow
        New-ADUser -SamAccountName $UserName -Name $UserName  -Description "$Description" -UserPrincipalName $principalName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -Enabled $true -PasswordNeverExpires $true -Path $path #'CN=Users,DC=megamart,DC=com'
        Show-Info -IsCI $IsCI -Message "User added" -ForegroundColor Green
        Grant-LogAsService -Type $Type -UserName $UserName -principalName ("{0}@{1}" -F $UserName, $fullDomain) -tempPath $tempPath -SQLInstance $SQLInstance -CredDB $CredDB -LogPath $logPath -domain $domain
    }
    

}


function Grant-LogAsService{

Param(
$Type,
$UserName,
$principalName,
$tempPath,
$SQLInstance,
$CredDB,
$logPath,
$domain
)
    if ($Type -eq "Administrator"){
            Add-ADGroupMember -Identity "Administrators" -Members $UserName
            Show-Info -IsCI $IsCI -Message "User added to Administrators group" -ForegroundColor Red
        }
        elseif ($Type -eq "Service"){
            $ScriptBlock = {
                $Type = $args[0]
                $UserName = $args[1]
                $principalName = $args[2]
                $tempPath = $args[3]
                $SQLInstance = $args[4]
                $logPath = $args[5]
				$report = $args[6]

                $prefix = ("({0}) " -F $SQLInstance)
                if ($SQLInstance -eq 'localhost' -or $SQLInstance -eq '' -or $SQLInstance.startswith($env:ComputerName)){
                    $prefix = ""
                }
                
               
                $objUser = New-Object System.Security.Principal.NTAccount($principalName)
                $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
                $sid = $strSID.Value

                #add sql service user to allow log as a service
                $sid3 = ''
                try{                
                    $t = Get-WmiObject win32_service | Where {$_.Name -eq 'MSSQLSERVER'} | Select startName 
                    if ($t.startName.ToLower().StartsWith($domain)){
						if ($report){
							Show-Info -IsCI $IsCI -Message "SQL is running on custom account"
						}
                         $objUser3 = New-Object System.Security.Principal.NTAccount($t.startName)
                         $strSID3 = $objUser3.Translate([System.Security.Principal.SecurityIdentifier])
                         $sid3 = $strSID3.Value
                    }
                }
                catch{}

				#add ssis service user to allow log as a service
                $sid4 = ''
                try{                
                    $t = Get-WmiObject win32_service | Where {$_.Name -eq 'MSDTSServer120' -or $_.Name -eq 'MSDTSServer110' -or $_.Name -eq 'MSDTSServer130' -or $_.Name -eq 'MSDTSServer140'} | Select startName 
                    if ($t.startName.ToLower().StartsWith($domain)){
						if ($report){
							Show-Info -IsCI $IsCI -Message "SSIS is running on custom account"
						}
                         $objUser4 = New-Object System.Security.Principal.NTAccount($t.startName)
                         $strSID4 = $objUser4.Translate([System.Security.Principal.SecurityIdentifier])
                         $sid4 = $strSID4.Value
                    }
                }
                catch{}


                #NT Service/ALL SERVICES
                $objUser2 = New-Object System.Security.Principal.NTAccount("NT SERVICE", "ALL SERVICES")
                $strSID2 = $objUser2.Translate([System.Security.Principal.SecurityIdentifier])
                $sid2 = $strSID2.Value

                $infFile =  Join-Path $tempPath "GrantLogOnAsService.inf"
                if(Test-Path $infFile){
                    Remove-Item -Path $infFile -Force
                }
                $logFile =  Join-Path $logPath "GrantLogOnAsService.log"
               
                Add-Content $infFile "[Unicode]"
                Add-Content $infFile "Unicode=yes"
                Add-Content $infFile "[Version]"
                Add-Content $infFile "signature=`"`$CHICAGO$`""
                Add-Content $infFile "Revision=1"
                Add-Content $infFile "[Registry Values]"
                Add-Content $infFile "[Profile Description]"
                Add-Content $infFile "Description=This is security template to grant log on as service access"
                Add-Content $infFile "[Privilege Rights]"
                if ($sid3.Length -gt 0 -and $sid4.Length -gt 0){
                    Add-Content $infFile "SeServiceLogonRight = *$sid,*$sid2,*$sid3,*$sid4"
                }
				elseif($sid3.Length -gt 0){
					Add-Content $infFile "SeServiceLogonRight = *$sid,*$sid2,*$sid3"
				}
				elseif($sid4.Length -gt 0){
					Add-Content $infFile "SeServiceLogonRight = *$sid,*$sid2,*$sid4"
				}
                else{
                    Add-Content $infFile "SeServiceLogonRight = *$sid,*$sid2"
                }

                $seceditFile = "c:\Windows\security\database\secedit.sdb"
                #Make sure it exists
                if((Test-Path $seceditFile) -eq $false){
                    Write-Error ($prefix + "Security database does not exist $seceditFile")
                }
				if ($report){
					Show-Info -IsCI $IsCI -Message ($prefix + "Validating new security template .inf file") -ForegroundColor Yellow
				}
                #validate if template is correct
                $t = secedit /validate $infFile
                $exitcode = $LASTEXITCODE
                if($exitcode -ne 0){
                    Write-Error ($prefix + "Error in validating template file, $infFile exit code $exitcode")
                    exit $exitcode
                }
				if ($report){
					Show-Info -IsCI $IsCI -Message ($prefix + "Appliying security template to default secedit.sdb") -ForegroundColor Yellow
				}
                $t = secedit /configure /db secedit.sdb /cfg "$infFile" /log "$logFile"

                if(Test-Path $infFile){
                    Remove-Item -Path $infFile -Force
                }


                $exitcode = $LASTEXITCODE
                if($exitcode -ne 0){
                    Write-Error ($prefix + "Error in secedit call, exit code $exitcode")
                    exit $exitcode
                }
                #get-content "$logFile"
				if ($report){
					Show-Info -IsCI $IsCI -Message ($prefix + "Successfully granted log on as service access to user $UserName") -ForegroundColor Green
				}
                $t = gpupdate /force
				if ($report){
					Show-Info -IsCI $IsCI -Message ($prefix + "GPO updated") -ForegroundColor Green
				}
            }

            Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $Type, $UserName, $principalName, $tempPath, '', $logPath, $true
            if ($SQLInstance -ne 'localhost'){
                Invoke-Command -ComputerName $SQLInstance -Credential $CredDB -ScriptBlock $ScriptBlock -ArgumentList $Type, $UserName, $principalName, $tempPath, $SQLInstance, $logPath, $false
                 Invoke-Command -ComputerName $SQLInstance -Credential $CredDB -ScriptBlock {
                    $SQLInstance = $args[0]
                    $DomainName = $args[1]
                    $UserName = $args[2]
                    try{
                        $t = ('net localgroup "Administrators" "{0}\{1}" /add' -F $DomainName, $UserName)
                        $tt = Invoke-Expression -Command $t -ErrorAction SilentlyContinue
                    }
                    catch{
                        Show-Info -IsCI $IsCI -Message "User $UserName is already an local administrator, skipping" -ForegroundColor Yellow 
                    }
                 } -ArgumentList $SQLInstance, $domain, $UserName -ErrorAction SilentlyContinue

                if ($SQLInstance -ne $SSISInstance){
                     Invoke-Command -ComputerName $SSISInstance -Credential $CredDB -ScriptBlock {
                        $SQLInstance = $args[0]
                        $DomainName = $args[1]
                        $UserName = $args[2]
                        try{
                            $t = ('net localgroup "Administrators" "{0}\{1}" /add' -F $DomainName, $UserName)
                            $tt = Invoke-Expression -Command $t -ErrorAction SilentlyContinue
                        }
                        catch{
                            Show-Info -IsCI $IsCI -Message "User $UserName is already an local administrator, skipping" -ForegroundColor Yellow 
                        }
                     } -ArgumentList $SSISInstance, $domain, $UserName -ErrorAction SilentlyContinue

                }

            }
        }

}