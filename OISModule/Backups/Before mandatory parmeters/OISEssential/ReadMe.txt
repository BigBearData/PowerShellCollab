NB! This PowerShell script is for internal Omada use only.
This tool is not supported by Omada and is not meant to replace any official internal processes at Omada. 

For best usage, copy this folder to C:\Program Files\Windows PowerShell\Modules folder.
To import, run Import-Module OISEssential 

Most usefull commands are: 

OIS_Prerequisites_ES [[-ServerName] <Object>] [[-UserName] <Object>] [[-IISBinding] <Object>]
OIS_Prerequisites_MSSQL [[-ServerName] <Object>] [[-UserName] <Object>]
OIS_Prerequisites_SSIS [[-ServerName] <Object>] [[-UserName] <Object>]
OIS_Prerequisites_SSRS [[-ServerName] <Object>] [[-UserName] <Object>]


If the parameters are not used, the scripts will try to read the information from the OISInstall.config file.
In that case, the config file needs to be updated with correct information. 