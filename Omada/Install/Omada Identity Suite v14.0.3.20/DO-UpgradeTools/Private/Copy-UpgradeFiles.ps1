Function Copy-UpgradeFiles {
    
        <#
        .SYNOPSIS
            Copies installation files to local drive
        .DESCRIPTION
            Copy of installation files in needed version
        .PARAMETER TempPath
            Path for temporary files
        .PARAMETER ESVersion
            Version of Enterprise Server
        .PARAMETER ESDropFolder
            Location of ES drop folder
        .PARAMETER OPSVersion
            Version of Omada Provisioning Service
        .PARAMETER OPSDropFolder
            Location of OPS drop folder
        .PARAMETER ODWVersion
            Version of Data Warehouse 
        .PARAMETER ODWDropFolder
            Location of ODW drop folder
        .PARAMETER RoPEVersion
            Version of Provisioning Engine
        .PARAMETER RoPEDropFolder
            Location of RoPE drop folder
        .PARAMETER Credential
            Credential required to connect to drop folders
        .PARAMETER CopyES
            Should ES sources should be copied
        .PARAMETER CopyODW
            Should ODW sources should be copied
        .PARAMETER CopyRoPE
            Should ODW sources should be copied
        .PARAMETER CopyOPS
            Should OPS sources should be copied
        .PARAMETER IsCI
            If this a manual install or CI triggered
        .EXAMPLE
            Copy-UpgradeFiles -TempPath "c:\InstallTempFiles"
        #>
        [cmdletbinding(SupportsShouldProcess)]
        Param(
        [Parameter (Mandatory)]
        [string]$TempPath = "c:\InstallTempFiles",
    
        [string]$ESVersion,# = '11.1.253',
        [string]$ESDropFolder,# = '\\OVMS09\drop\OE\OE11.1\rel',
        [string]$OPSVersion,# = '11.1.76',
        [string]$OPSDropFolder,# = '\\ovms09\drop\OPS\Rel\11.1',
        [string]$ODWVersion,# = '11.1.129',
        [string]$ODWDropFolder,# = '\\OVMS09\drop\common\ODW\Rel\v11.1',
        [string]$RoPEVersion,# = '11.1.120',
        [string]$RoPEDropFolder,# = '\\ovms09\drop\PolicyEngine\Rel\V11.1'
        [System.Management.Automation.CredentialAttribute()]$credential,
        [boolean]$CopyES = $true,
        [boolean]$CopyODW = $true,
        [boolean]$CopyRoPE = $true,
        [boolean]$CopyOPS = $true,
        [Boolean]$IsCI = $false,
        [string]$esExe = 'OIS Enterprise Server.exe',
        [string]$odwExe = 'Omada Data Warehouse.x64 SQL 2012.exe',
        [string]$opsExe = 'Omada Provisioning Service.exe',
        [string]$ropeExe = 'OIS Role and Policy Engine.exe'
    
        )
        $result = $false
        #$credential = Get-Credential -Message "Please provide user and password to Omada in order to check and download packages. Username: omada\xxx" -ErrorAction Stop
       
        if ($CopyES -eq $true){
            if (($ESVersion -eq $null) -or ($ESVersion -eq '')){
                Show-Info -IsCI $IsCI -Message "No ES version provided, checking newest version..." -ForegroundColor Yellow
                $ESVersion = Get-LatestSoftwareVersion -DropFolder $ESDropFolder -Credential $credential
                Show-Info -IsCI $IsCI -Message ("Version of Enterprise Server is {0}" -F $ESVersion) -ForegroundColor Green
            }
        }
        if ($CopyODW -eq $true){
            if (($ODWVersion -eq $null) -or ($ODWVersion -eq '')){
                Show-Info -IsCI $IsCI -Message "No ODW version provided, checking newest version..." -ForegroundColor Yellow
                $ODWVersion = Get-LatestSoftwareVersion -DropFolder $ODWDropFolder -Credential $credential
                Show-Info -IsCI $IsCI -Message ("Version of Data Warehouse is {0}" -F $ODWVersion) -ForegroundColor Green
            }
        }
        if ($CopyRoPE -eq $true){
            if (($RoPEVersion -eq $null) -or ($RoPEVersion -eq '')){
                Show-Info -IsCI $IsCI -Message "No RoPE version provided, checking newest version..." -ForegroundColor Yellow
                $RoPEVersion = Get-LatestSoftwareVersion -DropFolder $RoPEDropFolder -Credential $credential
                Show-Info -IsCI $IsCI -Message ("Version of Role and Policy Engine is {0}" -F $OPSVersion) -ForegroundColor Green
            }
        }
        if ($CopyOPS -eq $true){
            if (($OPSVersion -eq $null) -or ($OPSVersion -eq '')){
                Show-Info -IsCI $IsCI -Message "No OPS version provided, checking newest version..." -ForegroundColor Yellow
                $OPSVersion = Get-LatestSoftwareVersion -DropFolder $OPSDropFolder -Credential $credential
                Show-Info -IsCI $IsCI -Message ("Version of Provision Service is {0}" -F $RoPEVersion) -ForegroundColor Green
            }
        }
            
    
        Show-Info -IsCI $IsCI -Message "Starting to copy..." -ForegroundColor Yellow
        if ((Test-Path -Path $TempPath) -eq $false){
            $t = New-Item -Path $TempPath -type directory
            Show-Info -IsCI $IsCI -Message "Creating folder for source files" -ForegroundColor yellow
        }
        else{
            $t = Remove-Item -Path (Join-Path -Path $TempPath -ChildPath "*") -Recurse
            Show-Info -IsCI $IsCI -Message "Cleaning folder for source files" -ForegroundColor yellow
        }
    
        #coping
        $copyMatrix = ($CopyES, $esExe, (Join-Path -Path $ESDropFolder -ChildPath $ESVersion)),
        ($CopyODW, $odwExe, (Join-Path -Path $OdwDropFolder -ChildPath $OdwVersion)),
        ($CopyOPS, $opsExe, (Join-Path -Path $OpsDropFolder -ChildPath $OpsVersion)),
        ($CopyRoPE, $ropeExe, (Join-Path -Path $RoPEDropFolder -ChildPath $RoPEVersion))
        
        $result = $true
        foreach($t in $copyMatrix){
            if ($t[0]){
                $x = New-PSDrive -Name O -PSProvider FileSystem -Root $t[2] -Credential $Credential
                $tt = Get-ChildItem -Path 'o:\' -recurse -filter $t[1] -File
                if ($tt -eq $null){
                    Show-Info -IsCI $IsCI -Message ("{0} not found!" -f $t[1]) -ForegroundColor Red
                    $result = $false
                    break
                }
                Remove-PSDrive -Name O
                $x = New-PSDrive -Name O -PSProvider FileSystem -Root $tt.Directory.FullName -Credential $Credential
                Copy-Item (Join-Path -Path 'o:\' -ChildPath $t[1]) -Destination $TempPath
                Show-Info -IsCI $IsCI -Message ("{0} copied from drop folder" -f $t[1]) -ForegroundColor green    
                Remove-PSDrive -Name O
            }
        }
            return $result
    }