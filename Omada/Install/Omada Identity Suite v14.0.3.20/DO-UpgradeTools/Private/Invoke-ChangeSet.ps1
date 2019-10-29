function Invoke-ChangeSet{
    <#
    .SYNOPSIS
        Invokes changesets import into ES
    .DESCRIPTION
        Function responsible for importing changes to ES - it is called by main script and calls Import-ChangeSet
    .PARAMETER Step
        Step in which script is executed (needed to query xml)
    .PARAMETER xml
        Xml with configuration
    .PARAMETER Customer
        Customer to whom it should be added
    .PARAMETER LogFilePath
        Path to folder in which log files are placed
    .PARAMETER InstallationPath
        Path where ES is installed    
    .PARAMETER ESServiceName
        Name of ES service to restart after import
    .PARAMETER SkipErrors
        If any error during import should abort installation process
    .PARAMETER IsCI
        If this a manual install or CI triggered

	.EXAMPLE
       
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$Step,
        [Parameter(Mandatory=$true)]
        [Xml]$xml,
        [Parameter(Mandatory=$true)]
        [String]$Customer,
        [Parameter(Mandatory=$true)]
        [String]$LogFilePath,
        [Parameter(Mandatory=$true)]
        [String]$ESProductInstallPath,
        [bool]$SkipErrors,
        [String]$ESServiceName,
		[Boolean]$IsCI = $false,
		[Boolean]$noMerge = $false
    )

    $changesets = $xmlcfg.SelectNodes("/Configuration/Version/ES/Changesets")
    $fChangesets = $changesets.ChangeSet | where { $_.Step -eq "$Step"}
                
    if ($fChangesets.ChildNodes.Count -gt 0){
        Show-Info -IsCI $IsCI -Message ("{0} Applying changeset" -F $Step) -ForegroundColor DarkGreen
             
			if ($fChangesets.Count -le 1 -or $noMerge){ # as suggested packages are applied in a different way, so removed: $Step -eq "6.1.1" -or 
			$i = 0 
			#Suggested packages step - don't mess with it
				foreach ($node in $fChangesets) {
					if ($node.Name.Length -gt 0){
						$l =  ("{0}\changeset_{3}_{1}_{2}.log" -F $LogFilePath, ($i + 1), $node.Name, $Step)
						Show-Info -IsCI $IsCI -Message ("Applying changeset {0} ({1} of {2})" -F $node.Name, ($i + 1), ($fChangesets.ChildNodes.Count/2)) -ForegroundColor Yellow
						Import-ChangeSet -Customer omada -inputFile ($ESProductInstallPath + "\" + $node.Name) -logFile $l -ESProductInstallPath $ESProductInstallPath -ESServiceName $ESServiceName -IsCI $IsCI
						Get-Errors -IsCI $IsCI -l $l -SkipErrors $SkipErrors
					}
					else{
						Show-Info -IsCI $IsCI -Message "Changeset file name is empty, skipping..." -ForegroundColor Yellow
					}
					$i++
				}
			}
			else{
				$l =  ("{0}\changeset_{1}.log" -F $LogFilePath, $Step)
				Show-Info -IsCI $IsCI -Message ("Merging changeset files for step {0}, files to merge: {1}" -f $Step, $fChangesets.Count) -ForegroundColor Yellow
				#Applying changeset {0} ({1} of {2})" -F $node.Name, ($i + 1), ($fChangesets.ChildNodes.Count/2)) -ForegroundColor Yellow
				$resultPath = Join-Path -Path $ESProductInstallPath -ChildPath ("{0}.xml" -f $step)
				#!!!
				$version = ("{0}.66" -f $xmlcfg.Configuration.Version.OIS.Version)
				$esUrl = ('http://{0}' -f $xmlcfg.Configuration.Version.ES.IISBinding)
				#!!!
				$xmlString = ('<?xml version="1.0" encoding="utf-8"?><ConfigurationChangeFileData ContentDescription="OISIT merged changeset" CreatedBy="Administrator, System [ADMINISTRATOR]" Customer="{2}" AppVersion="{0}" APIVersion="2" ServerUrl="{1}" ChangeCount="3" xmlns="http://schemas.omada.net/ois/2014/ConfigurationChangeDataML"><ConfigurationChanges>' -f $version, $esUrl,$Customer)
				$i = 0
				foreach($f in $fChangesets){
					$fPath = Join-Path -Path $ESProductInstallPath -ChildPath $f.Name
					[xml]$childXML = Get-Content -Encoding UTF8 $fPath        
					$txml = $childXML.ConfigurationChangeFileData.ConfigurationChanges
					$i += $txml.ChildNodes.Count
					ForEach ($XmlNode in $txml) {
						$xmlString += $XmlNode.innerXML
					}
				}

				$xmlString += "</ConfigurationChanges></ConfigurationChangeFileData>"
				[xml]$masterXML = $xmlString
				$masterXML.ConfigurationChangeFileData.ChangeCount = $i.ToString()

				if (Test-Path -Path $resultPath){
					Remove-Item -Path $resultPath -Force
				}
				$masterXML.Save($resultPath)
				Import-ChangeSet -Customer omada -inputFile ($resultPath) -logFile $l -ESProductInstallPath $ESProductInstallPath -ESServiceName $ESServiceName -IsCI $IsCI
				Get-Errors -IsCI $IsCI -l $l -SkipErrors $SkipErrors

			}
		
                
        Show-Info -IsCI $IsCI -Message "Changesets applied" -foregroundcolor Green
        Show-Info -IsCI $IsCI -Message "***************************" -ForegroundColor Green

    }
    else{
        Show-Info -IsCI $IsCI -Message ("No changesets to apply in step {0}, skipping" -F $Step) -ForegroundColor Yellow
    }
}

function Get-Errors(
[string]$l,
[bool]$IsCI,
[bool]$SkipErrors
){
#$l
#$SkipErrors

						$t = Get-Content -Encoding UTF8 $l | Select -last 2 | Select -First 1
#$t
						$t = $t.Replace('Errors: ','')
						if ($t -ne "0" -and $t -is [int]){
							Show-Info -IsCI $IsCI -Message ("Not all changesets were imported correctly. Number of errors: {0}" -F $t) -ForegroundColor Red
							$t = Get-Content -Encoding UTF8 $l | Select -last 10
							Write-Output $t
							if ($SkipErrors -eq $false){
								throw
							}
						}
						elseif ($t -eq "0"){
							Show-Info -IsCI $IsCI -Message "No errors during import" -ForegroundColor Green
						}
						elseif (!($t -is [int])){
							Show-Info -IsCI $IsCI -Message ("Not all changesets were imported correctly: '{0}'" -F $t) -ForegroundColor Red
							$t = Get-Content -Encoding UTF8 $l | Select -last 10
							Write-Output $t
							if ($SkipErrors -eq $false){
								throw
							}
						}
						else{
							 Show-Info -IsCI $IsCI -Message "No errors during import" -ForegroundColor Green
						}


}



#Invoke-ChangeSet -Step "7.7.3" -xml $xmlcfg -SkipErrors $changesetsSkipErrors -Customer $changesetsCustomer -LogFilePath $tempPath -ESProductInstallPath $cfgVersion.ES.InstallationPath -ESServiceName $esTimerService

