if ($SQLInstance -ne 'localhost' -and $installES){
                if ($SQLInstanceName.Length -gt 0 -or !($rsOnAppServer)){
                    $rsUrl = ("http{0}://{1}/ReportServer_{2}" -F $s,$SQLInstanceWithout, $SQLInstanceName)
                }else{
                    $rsUrl = ("http{0}://{1}/ReportServer" -F $s,$rsServer)
                }
                $c = ("
                         Declare @id int
                        Declare @temp as varchar(4000)
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ESARC</Property><Property Id=""932"" Modified=""true"">Initial Catalog={0};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        Declare @xml XML
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ESARC'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={0};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">RoPE</Property><Property Id=""932"" Modified=""true"">Initial Catalog={2};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='RoPE'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={2};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
						Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OISRoPE</Property><Property Id=""932"" Modified=""true"">Initial Catalog={2};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OISRoPE'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={2};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODW</Property><Property Id=""932"" Modified=""true"">Initial Catalog={3};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODW'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={3};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODWMD</Property><Property Id=""932"" Modified=""true"">Initial Catalog={4};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODWMD'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={4};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OPS</Property><Property Id=""932"" Modified=""true"">Initial Catalog={5};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OPS'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={5};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">Source System Data DB</Property><Property Id=""932"" Modified=""true"">Initial Catalog={6};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='Source System Data DB'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={6};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODWS</Property><Property Id=""932"" Modified=""true"">Initial Catalog={7};Data Source={1};Integrated Security=SSPI;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODWS'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={7};Data Source={1};Integrated Security=SSPI;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OISAudit</Property><Property Id=""932"" Modified=""true"">Initial Catalog={8};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OISAudit'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={8};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">ODWSSIS</Property><Property Id=""932"" Modified=""true"">Data Source={10};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='ODWSSIS'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Data Source={10};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 
                        Set @id = 0
                        Set @temp = '<Properties><Property Id=""919"" Modified=""true"">OISES</Property><Property Id=""932"" Modified=""true"">Initial Catalog={9};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;</Property></Properties>'
                        SET @xml = CAST(@temp AS XML);
                        SELECT @id = [CurrentVersionID] FROM [{13}].[dbo].[tblDataObject] Where DisplayName='OISES'
                        Update [{13}].[dbo].tblDataObjectVersionPropertyValueText set PropValue='Initial Catalog={9};Data Source={1};Integrated Security=SSPI;Provider=SQLNCLI11;' where DataObjectVersionID = @id and PropertyID = 932
                        Update [{13}].[dbo].tblDataObjectVersion set PropertyXML=@xml where ID = @id 

                        Update tblCustomerSetting set ValueStr='{11}' where [Key]='SSRSUrl' and Category='Website'
						Update tblCustomerSetting set ValueStr='{12}' where [Key]='SSISServer' and Category='Microsoft SQL Server Integration Services'

                    " -F $esAuditDBName, $SQLInstance, $RoPEProductDB, $ODWProductDB, $ODWProductDBMaster, $opsProductDatabase, $esSourceSystemDBName, $restoreODWProductDBStaging, $esAuditDBName, $esDBName, $SSISInstance, $rsUrl,$env:COMPUTERNAME, $esDBName)
					#11=SSRS, 0=AuditDB=8, 13=esDBName, 3=ODW, 7= ODW staging, 4=ODW master, 12 = SSIS server
                    if ($useSQLUser){
                        Invoke-Sqlcmd -Username $SQLAdmUser -Password $SQLAdmPass -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }
                    else{
                        Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $esDBName  -query $c
                    }