USE [msdb]
GO

IF EXISTS (SELECT job_id 
            FROM msdb.dbo.sysjobs_view 
            WHERE name = N'ODWImport')
EXEC msdb.dbo.sp_delete_job @job_name=N'ODWImport'
                            , @delete_unused_schedule=1

/****** Object:  Job [ODWImport]    Script Date: 15-07-2016 13:26:06 ******/
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0
/****** Object:  JobCategory [Full-Text]    Script Date: 15-07-2016 13:26:06 ******/
IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'Full-Text' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'Full-Text'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'ODWImport', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N'No description available.', 
		@category_name=N'Full-Text', 
		@owner_login_name=N'DOMAIN\ODWImport', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [ODWImport]    Script Date: 15-07-2016 13:26:06 ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'ODWImport', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=3, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'SSIS', 
		@command=N'/SQL "\"\Omada\ODW\Omada ODW Run\"" /SERVER "\".\"" /DECRYPT OmadaEncryptionKey /CHECKPOINTING OFF /SET "\Package.Variables[ProfileID].Value";" " /SET "\package.variables[ProfileType].Value";"import" /REPORTING E', 
		@database_name=N'master', 
		@flags=0, 
		@proxy_name=N'ODWImport'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [ODWExport]    Script Date: 15-07-2016 13:26:06 ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'ODWExport', 
		@step_id=2, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N'SSIS', 
		@command=N'/SQL "\"\Omada\ODW\Omada ODW Run\"" /SERVER "\".\"" /DECRYPT OmadaEncryptionKey /CHECKPOINTING OFF /SET "\Package.variables[ProfileID].Value";" " /SET "\package.Variables[ProfileType].Value";"export" /REPORTING E', 
		@database_name=N'master', 
		@flags=0, 
		@proxy_name=N'ODWImport'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'ODWImport', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=1, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20160526, 
		@active_end_date=99991231, 
		@active_start_time=0, 
		@active_end_time=235959, 
		@schedule_uid=N'e3c919b9-3f50-46e8-ad54-297f629eba3c'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:

GO

USE [Omada Data Warehouse]
        GO
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DOMAIN\ODWImport')
        BEGIN
            CREATE USER [DOMAIN\ODWImport] FOR LOGIN [DOMAIN\ODWImport];
            ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
		ELSE
		BEGIN
			ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
GO
USE [Omada Data Warehouse Master]
        GO
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DOMAIN\ODWImport')
        BEGIN
            CREATE USER [DOMAIN\ODWImport] FOR LOGIN [DOMAIN\ODWImport];
            ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
		ELSE
		BEGIN
			ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
GO

USE [Omada Data Warehouse Staging]
        GO
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DOMAIN\ODWImport')
        BEGIN
            CREATE USER [DOMAIN\ODWImport] FOR LOGIN [DOMAIN\ODWImport];
            ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
		ELSE
		BEGIN
			ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
GO

USE [OmadaEnt_Archive]
        GO
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DOMAIN\ODWImport')
        BEGIN
            CREATE USER [DOMAIN\ODWImport] FOR LOGIN [DOMAIN\ODWImport];
            ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
		ELSE
		BEGIN
			ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
GO
USE [Omada Data Warehouse HR]
        GO
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DOMAIN\ODWImport')
        BEGIN
            CREATE USER [DOMAIN\ODWImport] FOR LOGIN [DOMAIN\ODWImport];
            ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
		ELSE
		BEGIN
			ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
GO

USE [RoPE]
        GO
        IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'DOMAIN\ODWImport')
        BEGIN
            CREATE USER [DOMAIN\ODWImport] FOR LOGIN [DOMAIN\ODWImport];
            ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
		ELSE
		BEGIN
			ALTER ROLE [db_owner] ADD MEMBER [DOMAIN\ODWImport];
		END
GO