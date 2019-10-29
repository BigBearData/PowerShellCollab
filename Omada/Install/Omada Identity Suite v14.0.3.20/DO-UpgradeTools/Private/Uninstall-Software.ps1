function Uninstall-Software{

    <#
    .SYNOPSIS
        Uninstalls software
    .DESCRIPTION
        Uninstall software based on software name
    .PARAMETER ProductName
        Name of software
    .PARAMETER IsCI
        If this a manual install or CI triggered
     
    .EXAMPLE
        Uninstall-Software -ProductName 'Omada Provisioning Service'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$ProductName,
    $ComputerName = 'localhost',
    $Cred = $null,
	
    [Boolean]$IsCI = $false 
    )

    
    $ScriptBlock = {
        $ProductName = $args[0]
		$report = $args[1]
        if ([IntPtr]::Size -eq 4) {
            $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        }
        else {
            $path = @(
                'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
                'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
        }
        #Check if this product is installed
        $Installed = Get-ItemProperty $path |
        # use only with name and unistall information
        .{process{ if ($_.DisplayName -eq $ProductName -and $_.UninstallString) { $_ } }}

        if ($Installed){
            
            
           $properties = "identifyingnumber","name","vendor","version"
               $prodGUID = (Get-ChildItem HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products | ForEach-Object {
                $root  = $_.PsPath
                $_.GetSubKeyNames() | ForEach-Object {
                try {
                    $RegKeyPath = (Join-Path -Path (Join-Path -Path $root -ChildPath $_) -ChildPath InstallProperties)
                    $obj = Get-ItemProperty -Path $RegKeyPath -ErrorAction Stop
                    if ($obj.UninstallString) {
                        [PSCustomObject]@{
                            Path = $RegKeyPath;
                            Name = $obj.DisplayName ;
                            Vendor = $obj.Publisher ;
                            Version = $obj.DisplayVersion ; 
                            IdentifyingNumber = ($obj.UninstallString -replace "msiexec\.exe\s/[IX]{1}","")
                            }
                        }
                    } 
                    catch {
                    }
                }
            } | Select -Property $properties | Where {$_.Name -eq $ProductName}).IdentifyingNumber

        
            
            #$prodGUID = Get-SoftwareGUID -Name $ProductName
			if($report){
				Show-Info -IsCI $IsCI -Message "Uninstalling $ProductName" -foregroundcolor yellow;
			}
            $x = Start-Process -Wait -FilePath "msiexec.exe" -ArgumentList ("/qr /x {0}" -F $prodGUID) -PassThru
            if($report){
				Show-Info -IsCI $IsCI -Message "Uninstalled" -ForegroundColor Green
			}
        }
        else {
			if($report){
				Show-Info -IsCI $IsCI -Message ("Product {0} is not installed" -F $ProductName) -ForegroundColor Yellow
			}
        }

    }

    if ($ComputerName -eq "localhost"){
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ProductName, $true
    }
    else{
        Invoke-Command -ScriptBlock $ScriptBlock -Credential $Cred -ComputerName $ComputerName -ArgumentList $ProductName, $false
    }


}