
function Import-ChangeSet{
    <#
    .SYNOPSIS
        imports changesets into ES
    .DESCRIPTION
        imports changesets into ES
    .PARAMETER Customer
        Customer to whom it should be added
    .PARAMETER InputFile
        File with changestes
    .PARAMETER LogFile
        Location of log file
    .PARAMETER InstallationPath
        Path where ES is installed    
    .PARAMETER ESServiceName
        Name of ES service to restart after import
    .PARAMETER IsCI
        If this a manual install or CI triggered

    .EXAMPLE
       Import-ChangeSet -Customer omada -InputFile "C:\temp\temp\packages.xml" -LogFile "C:\temp\log.txt" -InstallationPath "c:\Program Files\Omada Identity Suite\Enterprise Server 12\"
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$Customer,
        [Parameter(Mandatory=$true)]
        [String]$InputFile,
        [Parameter(Mandatory=$true)]
        [String]$LogFile,
        [String]$ESProductInstallPath,
        [String]$ESServiceName = "OETSVC120",
		[Boolean]$IsCI = $false
    )
    if ($InputFile.Length -gt 1){#import files with changesets
		$i = (Get-Item $InputFile).length/1MB
		$i = [int]$i
		Show-Info -IsCI $IsCI -Message ("Importing changeset {0}, it might take up to {1} minute(s)..." -F $inputFile, (1 + $i)) -ForegroundColor Yellow
		$args = @("-C", "$Customer", "-f", "$inputFile", "-L", "$logFile")#
		$t = ('"{3}ChangeSetImportUtil.exe" -C {0} -f "{1}" -L "{2}" -S' -F $Customer, $InputFile, $LogFile, ($ESProductInstallPath + "\website\bin\"))
    }
	else{#import build in core or suggested packages
		$i = 15
		if ($InputFile -eq "K"){
			$n = "core packages"
		}else{
			$n = "suggested packages"
		}
		Show-Info -IsCI $IsCI -Message ("Importing {0}, it might take couple of minutes..." -F $n) -ForegroundColor Yellow
		#$args = @("-C", "$Customer", "-f", "$inputFile", "-L", "$logFile")#
		$t = ('"{3}ChangeSetImportUtil.exe" -C {0} -{1} -L "{2}" -S' -F $Customer, $InputFile, $LogFile, ($ESProductInstallPath + "\website\bin\"))
	}
	#Show-Info -IsCI $IsCI -Message $t -ForegroundColor Blue
	Invoke-Expression ("& cd '{0}\website\bin\'" -F $ESProductInstallPath)
	Invoke-Expression "& $t"
    
    for($j = 0; $j -le ($i * 10);$j++){
        Show-Info -IsCI $IsCI -Message "...import in progress..." -ForegroundColor Yellow
        Start-Sleep -s 20
        $changeimport = Get-Process ChangeSetImportUtil -ErrorAction SilentlyContinue
        if ($changeimport -eq $null) {
            break
        }
    }
    $changeimport = Get-Process ChangeSetImportUtil -ErrorAction SilentlyContinue
    if ($changeimport) {
        Show-Info -IsCI $IsCI -Message "Import is still running - waiting additional 2 munites..." -ForegroundColor Yellow
        Start-Sleep -s 120
        $changeimport = Get-Process ChangeSetImportUtil -ErrorAction SilentlyContinue
        if ($changeimport) {
            Show-Info -IsCI $IsCI -Message "Import is still running - waiting another 2 minutes..." -ForegroundColor Yellow
            Start-Sleep -s 120
        }
        else{
            Show-Info -IsCI $IsCI -Message "...and it looks like import is finished" -ForegroundColor Green
        }
    }
    else{
        Show-Info -IsCI $IsCI -Message "...and it looks like import is finished" -ForegroundColor Green
    }
    
    Show-Info -IsCI $IsCI -Message "Restarting Enterprise Server service after changeset import" -ForegroundColor Yellow
    Restart-Service -ServiceName $ESServiceName -Action "Restart"
    Show-Info -IsCI $IsCI -Message "Enterprise server is digesting..." -ForegroundColor Yellow
    Start-Sleep -s 20
    Show-Info -IsCI $IsCI -Message "...changeset absorbed" -ForegroundColor Green


    Show-Info -IsCI $IsCI -Message "Finished importing changeset" -ForegroundColor Green
}