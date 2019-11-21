
Function New-ES-Website {
param(
   [Parameter(Mandatory=$True)]
    [string]$WebSiteName,
    [Parameter(Mandatory=$True)]
    [string]$serviceUser,
     [Parameter(Mandatory=$True)]
    [string]$esDBName,
     [Parameter(Mandatory=$True)]
    [string]$SQLInstance,
   [Parameter(Mandatory=$False)]
    [int]$WebSitesNumber,
   [Parameter(Mandatory=$True)]
    [string]$esInstallationPath,
   [Parameter(Mandatory=$False)]
    [string]$Hostheaders,
   [Parameter(Mandatory=$False)]
    [string]$EnviromentName,
   [Parameter(Mandatory=$False)]
    [string]$DefaultAppPoolName
)

 if(-not $DefaultAppPoolName){
 $DefaultAppPoolName = $WebSiteName}
 
 $serviceUserDomain=$env:UserDomain
 
	$c = ("Update tblUser set UserName=UPPER('{0}') where UserName='ADMINISTRATOR'" -F $env:USERNAME)
	invoke-sqlcmd -ServerInstance $SQLInstance -query $c -database $esDBName
	
	$esWebSitePath = (Join-Path -Path $esInstallationPath -ChildPath "website")
	$u = ("{0}\{1}" -F $serviceUserDomain, $serviceUser)

}