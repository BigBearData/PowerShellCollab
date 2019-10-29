function Set-XMLValue{

<#
    .SYNOPSIS
        Changes value in XML nodes
    .DESCRIPTION
        
    .PARAMETER XMLFile
        File to change
    .PARAMETER XMLNode
        Node to change
    .PARAMETER NewValue
        New value
     
    .EXAMPLE
        Set-XMLValue -XMLFile "C:\Program Files\Omada Identity Suite\Datawarehouse\Common\Omada ODW Configuration.dtsConfig" -XMLNode "GenericDB::ListOfSourceSystemNames" -NewValue "HR,GWG_Legacy"  
        Set-XMLValue -XMLFile "C:\Program Files\Omada Identity Suite\Role and Policy Engine\Service\ConfigFiles\connectionStrings.config" -XMLNode "OISXConnection" -NewValue "Integrated Security=SSPI;Initial Catalog=OIS;Data Source=.;" -Action "ConnectionString"     
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    $XMLFile,
    $XMLNode,
    $NewValue,
    $ComputerName = 'localhost',
    $Cred = $null,
    $Action = "Standard"
    )
    
    $ScriptBlock = {
        $XMLFile = $args[0]
        $Action = $args[1]
        $XMLNode = $args[2]
        $NewValue = $args[3]

        $XMLFile
        $Action
        $XMLNode
        $NewValue

        $xml = New-Object System.Xml.XmlDocument
        $xml.PreserveWhitespace = $true
        $xml.Load($XMLFile)

        if ($Action -eq "Standard"){
            $xml | Select-Xml -XPath "//Configuration" | Where-Object {$_.node.Path -like ('*{0}]*' -F $XMLNode)} | foreach {
            $_.node.InnerXML = ("<ConfiguredValue>{0}</ConfiguredValue>" -F $NewValue)
            }
        }
        elseif ($Action -eq "ConnectionString"){
            $node = $xml.SelectSingleNode("//add[@name='$XMLNode']")
            if ($node -ne $null) {
                #$node.ParentNode.RemoveChild($node)
                $node.connectionString = $NewValue
            }
        
        }
        elseif ($Action -eq "Key"){
            $node = $xml.SelectSingleNode("//key[@name='$XMLNode']")
            if ($node -ne $null) {
                #$node.ParentNode.RemoveChild($node)
                $node.value = $NewValue
            }
        
        }
        $xml.Save($xmlFile)
    }
    if ($ComputerName -eq 'localhost' -or $ComputerName -eq $env:ComputerName){
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $XMLFile, $Action, $XMLNode, $NewValue
    }
    else{
        #Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $XMLFile, $Action, $XMLNode, $NewValue
        Invoke-Command -ScriptBlock $ScriptBlock -Credential $Cred -ComputerName $ComputerName -ArgumentList $XMLFile, $Action, $XMLNode, $NewValue
    }
}



