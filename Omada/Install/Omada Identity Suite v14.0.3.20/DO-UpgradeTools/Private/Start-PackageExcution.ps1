function Start-PackageExcution{

<#
    .SYNOPSIS
        Executes packages from xml file
    .DESCRIPTION
        
    .PARAMETER nodes
        MS SQL version
		
    .PARAMETER IsCI
        If this a manual install or CI triggered
     
    .EXAMPLE
        Start-PackageExcution -nodes '' -SSISInstance 'localhost' -encKey '' -logPath 'c:\logs' -step '7.4.1' -dtexecDir 'C:\program files\Microsoft SQL Server\110\DTS\Binn\'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    $Nodes,

    [Parameter (Mandatory)]
    [string]$SSISInstance,

    [Parameter (Mandatory)]
    [string]$encKey,

    [Parameter (Mandatory)]
    [string]$logPath,

    [Parameter (Mandatory)]
    [string]$step,

    [Parameter (Mandatory)]
    [string]$dtexecDir,
	
    [Parameter ()]
    $Credential = $null

    )

    $ScriptBlock = {
        $Nodes = $args[0]
        $SSISInstance = $args[1]
        $encKey = $args[2]
        $logPath = $args[3]
        $step = $args[4]
        $dtexecDir = $args[5]
        
        $i = 1

        #create folder for logs, new folder for each intallation run
	    if(!(Test-Path -Path $logPath)){
		    $t = New-Item -Path $logPath -ItemType Directory
	    }

	    foreach($node in $Nodes){
	        Write-Host ("Running package {0}" -F $node.PackageName) -ForegroundColor Yellow
		    if ($node.Arguments.Length -gt 0){
		        $arg = ('/SET "{0}"' -F $node.Arguments)
	        }
		    else{
		        $arg = ''
            }
		    $tt = $node.PackageName
            
		    $dtExecArgs = ("/DTS ""\""$tt"""" /SERVER ""$SSISInstance"" /DECRYPT $encKey /CHECKPOINTING OFF  /REPORTING V " + $arg) # E shows error, V shows verbose log           
		    Write-Host ("Logs saved to: {0}" -F ("{0}\Package_step_{1}_{2}.log" -F $logPath, $step, $i)) -ForegroundColor Yellow
		    $l = ("{0}\Package_step_{1}_{2}.log" -F $logPath, $step, $i)
		    $x = Start-Process -Wait -WorkingDirectory $dtexecDir -FilePath dtexec.exe -ArgumentList $dtExecArgs -PassThru -RedirectStandardOutput $l
		    $x = Get-Content -Encoding UTF8 $l | Select -last 4 | Select -First 1
            $wordToFind = 'DTSER_SUCCESS'
		    $containsWord = $false
		    $x | %{if ($_ -match $wordToFind){$containsWord = $true}
		        If (!$containsWord){
		            Write-Host -Message "Package execution failed" -ForegroundColor Red
			        throw
	            }
		        else{
		            Write-Host -Message "Package execution succeeded" -ForegroundColor Green
	            }
		        $i++
	        }
	    }
    }

     if ($SSISInstance -eq 'localhost' -or $SSISInstance -eq $env:ComputerName){
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList @($Nodes), $SSISInstance, $encKey, $logPath, $step, $dtexecDir
    }
    else{
        Invoke-Command -ComputerName $SSISInstance -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList @($Nodes), $SSISInstance, $encKey, $logPath, $step, $dtexecDir
    }

    

}