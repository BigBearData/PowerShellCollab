function Test-SqlConnection {
param(
	[Parameter(Mandatory)]
	[string]$ServerName,

	[Parameter(Mandatory)]
	[string]$DatabaseName,

	[Parameter(Mandatory)]
	[pscredential]$Credential
)

    $ErrorActionPreference = 'Stop'

    try {
        $userName = $Credential.UserName
        $password = $Credential.GetNetworkCredential().Password
        #$connectionString = 'Data Source={0};database={1};User ID={2};Password={3}' -f $ServerName,$DatabaseName,$userName,$password
		$connectionString = 'Data Source={0};database={1};Integrated Security=True"' -f $ServerName,$DatabaseName
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
        $sqlConnection.Open()
        ## This will run if the Open() method does not throw an exception
        $true
    } catch {
        $false
    } finally {
        ## Close the connection when we're done
        $sqlConnection.Close()
    }
}

Test-SqlConnection -ServerName oisinstalldl2 -DatabaseName "Test_SMO_Database" -Credential "megamart\Administrator"

#https://mcpmag.com/articles/2018/12/10/test-sql-connection-with-powershell.aspx


