function Set-ServicesStartAndDependency{
    <#
    .SYNOPSIS
        Set similar services start type and dependencies.
    .DESCRIPTION
        Show error information and save step in which error did happen
    .PARAMETER ServiceName
        Service name on which should changes be made
    .PARAMETER StartType
        Start type that will be passed to sc command [eq. delayed-auto] 
    .PARAMETER Dependencies
        Services names from which the service will be dependend 
    .EXAMPLE
       Set-ServicesStartAndDependency -ServiceName RoPE -StartType delayed-auto -Dependencies MSSQLSERVER
           #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$ServiceName,
        [String]$StartType = 'delayed-auto',
        [String[]]$Dependencies
    )

    $dependenciesFormat = "{0}/{1}"
    $initDependencies = $null

    foreach ($dependency in $Dependencies){
        if(Get-WmiObject -Class Win32_Service -Filter "Name='$dependency'"){
            if($null -eq $initDependencies){
                $initDependencies = $dependency
            } else {
                $initDependencies = $dependenciesFormat -f $initDependencies, $dependency
            }
        }
    }

    $services = Get-Service -ServiceName ("*{0}*" -f $ServiceName)

    $services | ForEach-Object {
        $dependentServices = $initDependencies

        $_.RequiredServices | ForEach-Object {
            if($null -eq $dependentServices){
                $dependentServices = $_.Name    
            }
            elseif($dependentServices -notcontains $_){
                $dependentServices = $dependenciesFormat -f $dependentServices, $_.Name                   
            }
        }
        
        $dependencyParam = ""
        if($null -ne $dependentServices) {
            $dependencyParam = "depend={0}" -f $dependentServices
        }

        Invoke-Expression -Command ("sc.exe \\localhost config `"{0}`" start={1} {2}" -f $_.Name, $StartType, $dependencyParam) | Out-Null
    }
}