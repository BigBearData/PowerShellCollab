Function Read-PasswordFromConfig{
    <#
    .SYNOPSIS
        Checks password and (when needed) decrypts it
    .DESCRIPTION
        Function checks if password is decrypted, if yes - it is decrypted
    .PARAMETER XMLPath
        Path to configuration file
    .PARAMETER encryptedText
        Password to decrypt
    .PARAMETER isCI
        Bool if this is CI execution

    .EXAMPLE
        Read-PasswordFromConfig -XMLPath 'C:\Powershell\DEVHr.config' -encryptedText 'encPassword'
    #>
    [cmdletbinding(SupportsShouldProcess)]
    Param(
    [Parameter (Mandatory)]
    [string]$XMLPath,

    [Parameter (Mandatory)]
    [string]$encryptedText,
    
    [Boolean]$IsCI = $false
    )

	$ErrorActionPreference = "SilentlyContinue"

    [xml]$xmlcfg = Get-Content -Encoding UTF8 $XMLPath
    $localConfig = $xmlcfg.SelectNodes("/Configuration/LocalConfiguration") 

    #check if file exists, if so create key and salt
    $useExternalEncryption = $xmlcfg.Configuration.LocalConfiguration.UseExternalKey
    $useDefaultEncryptionKey = $true
    $t = Get-Item -Path $XMLPath
    $encryptionKeyFilePath = Join-Path -Path $t.Directory.FullName -ChildPath 'externalKeyFile.txt'
    if ($useExternalEncryption -eq 'true'){
        #Using external file with encryption key
        if (Test-Path -Path $encryptionKeyFilePath){
            #Found external file with encryption key
            $c = Get-Content -Encoding UTF8 -Path $encryptionKeyFilePath
            if ($c[0] -ne $null -and $c[0].Length -eq 32){
                #External encryption key found
                $encryptionSalt = $c[0]
                if ($c[1] -ne $null -and $c[1].Length -eq 32){
                    #External encryption salt found
                    $encryptionKey = $c[1]
                    $useDefaultEncryptionKey = $false;
                }else{
                    Show-ErrorInfo -ErrorMessage "External encryption salt not found or is not correct" -ErrorLine 45 -ScriptName 'Read-PasswordConfig'  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
                    break
                }
            }else{
                Show-ErrorInfo -ErrorMessage "External encryption key not found or is not correct" -ErrorLine 40 -ScriptName 'Read-PasswordConfig'  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
                break
            }
        }else{
            Show-ErrorInfo -ErrorMessage "External encryption file not found or is not correct" -ErrorLine 37 -ScriptName 'Read-PasswordConfig'  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
            break
        }
    }

    if ($useDefaultEncryptionKey){#use default encryption key
        
        $key = Set-Key $localConfig.EncryptionKey
        try{
            $t = Get-EncryptedData -data $encryptedText -key $key
            return $t
        }
        catch{
            $t = $_.Exception.Message
            if ($t = 'Input string was not in a correct format.'){
                return $encryptedText
            }else{
                Show-Info -Message "Not correct password" -ForegroundColor Red -isCI $IsCI
                Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
                break
            }
        }
    }else{#use external encryption key
        $key = Set-Key $encryptionKey
        try{
            $t = Get-EncryptedData -data $encryptedText -key $key
            $t = $t.Replace($encryptionSalt,"")
           return $t
        }
        catch{
            $t = $_.Exception.Message
            if ($t = 'Input string was not in a correct format.'){
                return $encryptedText

            }else{
                Show-Info -Message "Unable to decrypt password" -ForegroundColor Red -isCI $IsCI
                Show-ErrorInfo -ErrorMessage $_.Exception.Message -ErrorLine $_.InvocationInfo.ScriptLineNumber -ScriptName ($_.InvocationInfo.InvocationName + " " + $_.InvocationInfo.ScriptName)  -ErrorStep "11" -XMLPath $XMLPath -SaveStep $true -IsCI $IsCI
                break
            }
        }
    }
}


function Get-EncryptedData {
#try{
param($key,$data)
        $data | ConvertTo-SecureString -key $key |
        ForEach-Object {[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))}
#    }catch{}
}

function Set-Key {
param([string]$string)
    $length = $string.length
    $pad = 32-$length
    if (($length -lt 16) -or ($length -gt 32)) {Throw "String must be between 16 and 32 characters"}
    $encoding = New-Object System.Text.ASCIIEncoding
    $bytes = $encoding.GetBytes($string + "0" * $pad)
    return $bytes
}

