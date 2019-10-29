USE [Omada Data Warehouse]
GO

/****** Object:  View [dbo].[OISX_DataObjectExchange_ResourceUpdate_Custom]    Script Date: 9/15/2016 11:22:39 AM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO



				CREATE VIEW [dbo].[OISX_DataObjectExchange_ResourceUpdate_Custom] AS
SELECT 
  ComposedBusinessKey, ODWSourceSystemID, EffectiveTime, ExpirationTime,
  XmlData = (SELECT 
  'updateOrCreate' as "@operation",
  'RESOURCE' as "@type",
  (SELECT 
    (SELECT 'ODWBUSIKEY' AS "@name", 'true' AS "@isKey", 'modify' AS "propertyValues/propertyValue/@action", [ComposedBusinessKey] AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'ROLEID' AS "@name", 'modify' AS "propertyValues/propertyValue/@action", ISNULL([ShortName], [Name]) AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'NAME' AS "@name", 'modify' AS "propertyValues/propertyValue/@action", ISNULL([DisplayName], [Name]) AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'DESCRIPTION' AS "@name", 'modify' AS "propertyValues/propertyValue/@action", ISNULL([Description], [Name]) AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'ROLETYPEREF' AS "@name", 'true' AS "@onlyOnCreate", 'ODWBUSIKEY' AS "@targetKeyProperty", 'true' AS "propertyValues/@clearExistingValues", CASE WHEN ISNULL([Type], '') <> '' THEN 'add' END AS "propertyValues/propertyValue/@action", CASE WHEN ISNULL([Type], '') <> '' THEN [Type] END AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'ROLEFOLDER' AS "@name", 'true' AS "@onlyOnCreate", 'true' AS "propertyValues/@clearExistingValues", CASE WHEN ISNULL([ResourceFolder], '') <> '' THEN 'add' END AS "propertyValues/propertyValue/@action", CASE WHEN ISNULL([ResourceFolder], '') <> '' THEN [ResourceFolder] END AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'ROLECATEGORY' AS "@name", 'true' AS "@onlyOnCreate", 'true' AS "propertyValues/@clearExistingValues", 'add' AS "propertyValues/propertyValue/@action", [RoleCategory] AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type),
    (SELECT 'SYSTEMREF' AS "@name", 'ODWBUSIKEY' AS "@targetKeyProperty", 'true' AS "propertyValues/@clearExistingValues", CASE WHEN ISNULL([SystemComposedBusinessKey], '') <> '' THEN 'add' END AS "propertyValues/propertyValue/@action", CASE WHEN ISNULL([SystemComposedBusinessKey], '') <> '' THEN [SystemComposedBusinessKey] END AS "propertyValues/propertyValue/@valueText" FOR XML PATH('property'), type)  
  FOR XML PATH('properties'), type)
FOR XML PATH ('object'), type) 
FROM 
  [INTERNAL_Resource] AS reportingView 
WHERE 
  ODWSourceSystemID<>1 AND IsRowLatest=1 AND ExpirationTime>GetUtcDate()
	

GO