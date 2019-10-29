function Add-XMLNode{

<#
    .SYNOPSIS
        Adds node in XML
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
    .EXAMPLE 
        Add-XMLNode -XMLFile  "C:\Program Files\Omada Identity Suite\Role and Policy Engine\Service\ConfigFiles\EngineConfiguration.config" -XMLParentNode "//extensions" -ParentElementName "add" -KeyAttribute "type" -KeyValue "Omada.OE.Custom.OIMDEMO.PolicyEngineExtension.PolicyEngineExtension, Omada.OE.Custom.OIMDEMO.PolicyEngineExtension"
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    $XMLFile,
    $XMLParentNode,
    $ParentElementName,
    $KeyAttribute,
    $KeyValue
    )
    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load($XMLFile)

    $node = $xml.SelectSingleNode("$XMLParentNode")

    $newelement = $xml.CreateElement($ParentElementName)
    $t = $newelement.SetAttribute($KeyAttribute, $KeyValue)
    $t = $node.AppendChild( $newelement )
    $xml.Save($xmlFile)

}
        
