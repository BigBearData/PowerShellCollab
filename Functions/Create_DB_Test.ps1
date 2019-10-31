#Create a new database  
$srv="oisinstalldl2"
$DbName="Test_SMO_Database"
$db = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Database -argumentlist $srv, $DbName  
$db.Create() 


