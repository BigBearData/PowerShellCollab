function Update-XMLNode{

<#
    .SYNOPSIS
        Updates node in XML
    .DESCRIPTION
        
    .PARAMETER XMLFile
        File to change
    .PARAMETER XMLParentNode
        Parent node
    .PARAMETER ParentElementName
        Name of new value
    .PARAMETER KeyAttribute
        Name of attribute
    .PARAMETER KeyValue
        Value of attribute
    .PARAMETER IsCI
        If this a manual install or CI triggered
    .EXAMPLE 
        Update-XMLNode -XMLFile "C:\Program Files\Omada Identity Suite\Datawarehouse\Common\Omada ODW WebService.dtsConfig" -XMLParentNode "/DTSConfiguration/Configuration" -ParentElementValue "\Package.Variables[User::WebServiceURL].Properties[Value]" -ParentElementKey "Path" -KeyAttribute "ConfiguredValue" -KeyValue "1"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [string]$XMLFile,
    [string]$XMLParentNode,
    [string]$ParentElementValue,
    [string]$KeyAttribute,
    [string]$KeyValue,
    [string]$ParentElementKey,
    $ComputerName = 'localhost',
    $Cred = $null,
    [Boolean]$IsCI = $false
    )

     $ScriptBlock = {
        $XMLFile = $args[0]
        $XMLParentNode = $args[1]
        $ParentElementValue = $args[2]
        $KeyAttribute = $args[3]
        $KeyValue = $args[4]
        $ParentElementKey = $args[5]
        $Server = $args[6]
		$report = $args[7]

        [xml]$xml = Get-Content -Encoding UTF8 $XMLFile
        $nodes = $xml.SelectNodes($XMLParentNode)
        $nodes | Where-Object {$_.$ParentElementKey -eq $ParentElementValue} | ForEach-Object {$_.$KeyAttribute = $KeyValue}
        $xml.Save($XMLFile)
		if ($report){
			Show-Info -IsCI $IsCI -Message ("({2}) Attibute {0} updated to {1}" -F $KeyAttribute, $KeyValue, $Server) -ForegroundColor Green
		}

    }

    if ($ComputerName -eq 'localhost' -or $ComputerName -eq $env:ComputerName){
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $XMLFile, $XMLParentNode, $ParentElementValue, $KeyAttribute, $KeyValue , $ParentElementKey, $ComputerName
    }
    else{
        Invoke-Command -ScriptBlock $ScriptBlock -Credential $Cred -ComputerName $ComputerName -ArgumentList $XMLFile, $XMLParentNode, $ParentElementValue, $KeyAttribute, $KeyValue , $ParentElementKey, $ComputerName, $false
    }


}
        