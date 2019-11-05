#Create a new database 

Function Create-Database { 
param(
	[Parameter(Mandatory)]
	[string]$ServerName,

	[Parameter(Mandatory)]
	[string]$DatabaseName
)
$srv=$ServerName
$DbName=$DatabaseName

$db = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Database -argumentlist $srv, $DbName  
$db.Create() 


		$c = "
		USE [$DBName]
		declare @dbname varchar(256)
		declare @sql nvarchar(256)
		select @dbname=db_name(dbid) from master..sysprocesses where spid=@@SPID
		set @sql = 'ALTER DATABASE [' + @dbname + '] SET ALLOW_SNAPSHOT_ISOLATION ON'
		exec sp_executesql @sql
		set @sql = 'ALTER DATABASE [' + @dbname + '] SET READ_COMMITTED_SNAPSHOT ON'
		exec sp_executesql @sql
		;
            
       "

Invoke-Sqlcmd -ServerInstance $srv -Query $c

}
Create-Database -ServerName oisinstalldl2 -DatabaseName Rassgat