function Restart-Service{

    <#
    .SYNOPSIS
        Stops\Starts\Restarts service
    .DESCRIPTION
        Stops\Starts\Restarts service based on its name
    .PARAMETER ServiceName
        Name of service
    .PARAMETER Action
        Action to perform
    .PARAMETER IsCI
        If this a manual install or CI triggered
     
    .EXAMPLE
        Restart-Service -ServiceName "Omada ProvisioningService" -Action 'Stop'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$ServiceName,

    [Parameter ()]
    #[ValidateSet("Stop", "Start", "Restart")]
    [string]$Action = "Restart",
    [Boolean]$IsCI = $false
    )

    $service= Get-Service -Name $serviceName # -ErrorAction SilentlyContinue
	
	  $numberOfRetries = 3
	
    if (!$service){
        Show-Info -IsCI $IsCI -Message "Service $serviceName not found" -foregroundcolor red
        break
    }

    if ($ServiceName -eq "Winmgmt"){
        Stop-Service $ServiceName -Force
        Start-Service $ServiceName
        Start-Service "iphlpsvc"
        Start-Service "UALSVC"
    }
    else{
		  $retry = 0
	
		  while($retry -lt $numberOfRetries) {	
			  try {
				  if (($Action -eq "Stop") -or ($Action -eq "Restart")){
					  Write-Host "Service $serviceName stopping" -ForegroundColor Yellow
					  Stop-Service $ServiceName
					  Write-Host "Service $serviceName stopped" -ForegroundColor Green
				  }
			
				  if (($Action -eq "Start") -or ($Action -eq "Restart")){
					  Write-Host "Service $serviceName starting"  -ForegroundColor Yellow
					  Start-Service $ServiceName
					  Write-Host "Service $serviceName started" -ForegroundColor Green
				  }
				
				  break		
			  }
			  catch {
				  Write-Host "Error while executing action $Action on service $serviceName"
				  Write-Host  $_ -ForegroundColor red
				  $retry += 1
				  Write-Host "Retrying ($retry)" -ForegroundColor Yellow
			  }		
		  }
    }

}
