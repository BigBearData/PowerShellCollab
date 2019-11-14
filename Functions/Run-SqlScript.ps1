Function Run-SqlScript {
param(
$FileName,
$SQLInstance,
$DBName,
$serviceUserDomain=$env:UserDomain
)
			#C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_14_0.sql
			if ((Test-Path $FileName) -eq $true){
				$c = Get-Content -Encoding UTF8 -path $FileName -Raw
				$c = $c.Replace("DOMAIN\",("{0}\" -F $serviceUserDomain))
					Invoke-Sqlcmd -ServerInstance $SQLInstance -Database $DBName -QueryTimeout 300 -query $c | Out-Null
			}
			else {
				$ES_Install_Output.text += "The file {0} cannot be found.`r`n" -F $FileName
			}
}
$sqlFile_OIS_dbcr = "C:\Program Files\Omada Identity Suite\Enterprise Server\Sql scripts\dbcr_oim_14_0.sql"
Run-SqlScript -FileName $sqlFile_OIS_dbcr -SQLInstance  oisinstalldl2 -DBName OIS