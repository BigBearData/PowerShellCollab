function Import-DataObject{
<#
    .SYNOPSIS
        Invokes DataObject import into ES
    .DESCRIPTION
        Function responsible for importing DataObjects to ES
    .PARAMETER Step
        Step in which script is executed (needed to query xml)
    .PARAMETER xml
        Xml with configuration
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
		[Boolean]$IsCI = $false,
		[string]$logPath = $null

    )
    $cfgVersion = $xml.SelectNodes("/Configuration/Version")
    $demoDataObjects = $cfgVersion.ES.DataObjects
	if ($logPath -eq $null){
		$logPath = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration/LogPath").Path
	}
    $nodes = $demoDataObjects.ChildNodes | Where-Object {($_.Step -eq "$Step")}
    $overwriteDataObjects = [System.Convert]::ToBoolean($demoDataObjects.OverwriteFiles)
    $demoDataObjectsPath = $cfgVersion.ES.DataObjects.SourcePath
    $esBinding = $cfgVersion.ES.IISBinding
    $i = 1
    foreach($node in $nodes){
        if ($overwriteDataObjects -eq $false){
            $t = Test-Path -Path (Join-Path -Path $demoDataObjects.FilesPath -ChildPath $node.Name)
        }
        else{
            $t = Test-Path -Path (Join-Path -Path $demoDataObjectsPath -ChildPath $node.Name)
        }
        if ($t -eq $false){
            Show-Info -IsCI $IsCI -Message ("DataObject file {0} is missing, aborting" -F $node.Name) -ForegroundColor Red
            throw
        }
        if ($overwriteDataObjects -eq $true){
             Show-Info -IsCI $IsCI -Message ("Copying DataObject file {0}" -F $node.Name) -ForegroundColor Yellow
             If ((Test-Path -Path $demoDataObjects.FilesPath) -ne $true){
                $t = New-Item -Path $demoDataObjects.FilesPath -ItemType Directory
             }
             $t = Copy-Item -Path (Join-Path -Path $demoDataObjectsPath -ChildPath $node.Name) -Destination (Join-Path -Path $demoDataObjects.FilesPath -ChildPath $node.Name) -Force
        }
        Show-Info -IsCI $IsCI -Message ("Importing DataObject file {0}" -F $node.Name) -ForegroundColor Yellow
        $l = Join-Path -Path $logPath -ChildPath ("dataobject_{0}_{1}_{2}.log" -f $Step, $i, $node.Name)
        $t = ('"{0}" -h "http://{1}" -m import -f "{2}" > "{3}"' -F $demoDataObjects.ToolPath, $esBinding, (Join-Path -Path $demoDataObjects.FilesPath -ChildPath $node.Name),$l)
        Invoke-Expression "& $t"
        Start-Sleep -Seconds 10
        Show-Info -IsCI $IsCI -Message "File imported" -ForegroundColor Green
        $i++
    }

}