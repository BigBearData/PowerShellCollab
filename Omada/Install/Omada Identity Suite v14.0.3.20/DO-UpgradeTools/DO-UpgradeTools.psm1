
    #Load assemblies
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null


#Get function definition files.
    $Public  = @( Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue )
    $Private  = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

#Dot source the files
    Foreach($import in @($Public + $Private))
    {
        Try
        {
            . $import.fullname
        }
        Catch
        {
            Write-Error -Message "Failed to import function $($import.fullname): $_"
        }
    }


    #Here for future use: Set variables visible to the module and its functions only

#Export-ModuleMember -Function $Public.Basename
New-Alias -Name Invoke-OmadaInstallv12 -Value Invoke-OmadaInstall
New-Alias -Name Invoke-OmadaUpdate12 -Value Invoke-OmadaUpdate
New-Alias -Name Invoke-OmadaUpgrade12 -Value Invoke-OmadaUpgrade

Export-ModuleMember -Function * -Alias *