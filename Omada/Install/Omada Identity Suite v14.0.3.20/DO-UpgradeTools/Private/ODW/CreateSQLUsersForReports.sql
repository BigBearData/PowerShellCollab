USE [master]
GO

If not Exists (select loginname from master.dbo.syslogins 
    where name = N'DOMAIN\ODWAdmins' and dbname = 'master')
Begin
	CREATE LOGIN [DOMAIN\ODWAdmins] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end
GO

If not Exists (select loginname from master.dbo.syslogins 
    where name = N'DOMAIN\ODWAuditors' and dbname = 'master')
Begin
	CREATE LOGIN [DOMAIN\ODWAuditors] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end
GO

If not Exists (select loginname from master.dbo.syslogins 
    where name = N'DOMAIN\ODWUsers' and dbname = 'master')
Begin
	CREATE LOGIN [DOMAIN\ODWUsers] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
end
GO


