
Function OIS_TestPsRemoting {
    [CmdletBinding()]
    param(
        $ComputerName = $Env:Computername,
        $Credentials    
    )

$ErrorActionPreference = "Stop"
$DWHServer = OIS_XML_GetSQLConfig -Command Server
$remote = $ComputerName -notmatch $ComputerName
$remote

#$sc = { 1 }

<#     $sc = { 1 }

    #If remote computer, test connection create sessions
    if($remote) {
        Test-Connection -ComputerName $ComputerName -Count 1 | 
            Format-List -Property PSComputerName,Address,IPV4Address,IPV6Address

        Test-WSMan $ComputerName

        $session = New-PSSession -ComputerName $ComputerName -Credential $Credentials
    }

    if($remote) {
        #If remote computer
        Invoke-Command -ComputerName $computername -ScriptBlock $sc
    } else { 
        #Localhost
        Invoke-Command -ScriptBlock $sc
    }  #>

}

OIS_TestPsRemoting