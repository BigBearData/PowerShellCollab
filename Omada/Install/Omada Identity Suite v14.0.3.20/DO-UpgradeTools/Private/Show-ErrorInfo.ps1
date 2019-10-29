function Show-ErrorInfo{
    <#
    .SYNOPSIS
        Show error information in console
    .DESCRIPTION
        Show error information and save step in which error did happen
    .PARAMETER ErrorMessage
        Error message
    .PARAMETER ErrorLine
        Line in which error occured
    .PARAMETER ErrorStep
        Step in which error occured
    .PARAMETER XMLPath
        Path to xml configuration file    
    .PARAMETER SaveStep
        Bool if error should be logged to config file     
    .PARAMETER IsCI
        If this a manual install or CI triggered		
    .EXAMPLE
       Show-ErrorInfo -ErrorMessage "This is a test error message" -ErrorLine 666 -ErrorStep "66" -XMLPath "C:\powershell\DEVempty.config" -SaveStep $true
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$ErrorMessage,
        [Parameter(Mandatory=$true)]
        [Int]$ErrorLine,
        [Parameter(Mandatory=$true)]
        [String]$ErrorStep,
        [String]$XMLPath,
        [Boolean]$SaveStep,
		[Boolean]$IsCI = $false,
		[String]$ScriptName = 'unknown'
    )

		$tool = "OISIT"
		$t = [System.Diagnostics.EventLog]::SourceExists($tool)
		if ($t -eq $false){
			New-EventLog –LogName Application –Source $tool
			Show-Info -IsCI $IsCI -Message ("Adding new source to Event Viewer: {0}" -f $tool) -ForegroundColor Yellow
		}
		if ($ScriptName.Length -eq 0){
			$ScriptName = 'failed to retrieve function name'
		}
		$Error = (" Error in OISIT:
			Step: {0},
			Line: {1},
			Function: {3},
			Message: {2}" -f ($ErrorStep.Substring(0,1) + "." + $ErrorStep.Substring(1,1)), $ErrorLine, $ErrorMessage, $ScriptName)
		Write-EventLog –LogName Application –Source $tool –EntryType Error –EventID $ErrorStep –Message $Error

        Show-Info -IsCI $IsCI -Message "Error while executing script... " -ForegroundColor Red
		if ($IsCI){
			$t = Get-Date			
			Show-Info -IsCI $IsCI -saveInLog $true -Message ("{1} | Error message: {0}," -F $ErrorMessage, $t.DateTime) -ForegroundColor Red
		}
		else{
			Show-Info -IsCI $IsCI -Message ("Error message: {0}," -F $ErrorMessage) -ForegroundColor Red
		}
        Show-Info -IsCI $IsCI -Message ("Error in function: {2}, line: {0}, Step {1}" -F $ErrorLine, ($ErrorStep.Substring(0,1) + "." + $ErrorStep.Substring(1,1)), $ScriptName) -ForegroundColor Red
        
        if ($SaveStep){
            [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
            $xmlcfg.Configuration.Execution.ErrorStep = $ErrorStep
            $xmlcfg.Save($XMLPath)

        }
        else{
            Show-Info -IsCI $IsCI -Message "Step in which error occured will not be saved" -ForegroundColor Yellow
        }
        break
  }

  #Show-ErrorInfo -ErrorMessage "This is a test error message" -ErrorLine 666 -ErrorStep "66" -XMLPath "C:\powershell\DEVempty.config" -SaveStep $true