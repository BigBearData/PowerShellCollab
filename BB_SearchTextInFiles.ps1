Param (
[string]$Path,
[Parameter (Mandatory)]
[string]$Pattern,
[Switch]$Browse
)

 
 	 Function Get-Folder($initialDirectory)

	{
		[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null

		$foldername = New-Object System.Windows.Forms.FolderBrowserDialog
		$foldername.Description = "Select a folder"
		$foldername.rootfolder = "MyComputer"

		if($foldername.ShowDialog() -eq "OK")
		{
			$Folder += $foldername.SelectedPath
		}
		return $Folder
	}
 
 If ($Browse){
	$Path = Get-Folder
}

If ($Browse -eq $False -And !$Path){
$Path = $PSScriptRoot
}

#$PSScriptRoot
Get-ChildItem -Path $Path -recurse |  Select-String -Pattern $Pattern | select -unique path


