function Show-Info{
    <#
    .SYNOPSIS
        Shows information in console
    .DESCRIPTION
        This function was introduced to allow colors in output but also to send data in pipeline when used in CI
    .PARAMETER Message
        Message
    .PARAMETER ForegroundColor
        Color of message
    .PARAMETER IsCI
        if this is automated run or manual
	.PARAMATER
		[test] for CI, if this should be passed to pipeline
    
    .EXAMPLE
       Show-Info -IsCI $true -Message "This is a test error message" -ForegroundColor Red
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$Message,
        [String]$ForegroundColor = 'Green',
        [Boolean]$IsCI = $false,
		[Boolean]$saveInLog = $false
    )

		if ($isCI){
				if ($saveInLog){
					Write-Output ("|" + $Message)
				}
				else{
				#don't do anything as noone will read log when in CI mode
				}
        }else{
            Write-Host $Message -ForegroundColor $ForegroundColor
        }
  }

#Show-Info -IsCI $true -Message "This is a test error message" -ForegroundColor Red
