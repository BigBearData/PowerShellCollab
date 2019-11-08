# This function determines whether a database exists in the system.
Function IsDBInstalled([string]$sqlServer, [string]$DBName)
{
 $exists = $FALSE
 try
 {
  $conn = New-Object system.Data.SqlClient.SqlConnection
  $conn.connectionstring = [string]::format("Server={0};Database={1};Integrated Security=SSPI;",$sqlServer,$DBName)
  $conn.open()
  $exists = $true
 }
 catch
 {
  Write-Error "Failed to connect to DB $DBNAME on $sqlServer"
 }
 
 Write-Output $exists
}

IsDBInstalled -sqlServer "oisinstalldl2" -DBName "OIS"