

#Show-Info -IsCI $IsCI -Message "Omada Data Warehouse installation starting..." -ForegroundColor Yellow
#$Output_SSIS_PreCheck.text += "Omada Data Warehouse installation starting...`r`n"
Function Show-Info {
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [string]$Message,
    [string]$ForegroundColor,
    $IsCI = $false,
	$Service
    )

    if ( $IsCI -eq SSIS ) { $Output_SSIS_PreCheck.text += $Message       }
    elseif ( $IsCI -eq SSRS ) { $result = 'Monday'    }
    elseif ( $IsCI -eq ES ) { $result = 'Tuesday'   }
    elseif ( $IsCI -eq RoPE ) { $result = 'Wednesday' }
    elseif ( $IsCI -eq OPS ) { $result = 'Thursday'  }
    elseif ( $IsCI -eq 5 ) { $result = 'Friday'    }
    elseif ( $IsCI -eq 6 ) { $result = 'Saturday'  }

}
Show-Info -IsCI SSIS -Message "Omada Data Warehouse installation starting..." -ForegroundColor Yellow

Function Show-Info {
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [string]$Message,
    [string]$ForegroundColor,
    $IsCI = $false,
	$Service
    )

	switch ($IsCI) {
	
		SSIS {
		$Output_SSIS_PreCheck.text += $Message
		}
		SSRS {
		
		}
	
	}

}