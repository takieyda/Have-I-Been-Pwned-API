# Have I Been Pwned Pwned Passwords Query
# Version 0.7

function Get-StringHash { 
    [CmdletBinding()]

    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [String[]]
        $String,
        [Parameter(Position = 1)]
        [ValidateSet('SHA1', 'MD5', 'SHA256', 'SHA384', 'SHA512')]
        [String]
        $HashName = 'SHA1'
    )

    process {
        $StringBuilder = [System.Text.StringBuilder]::new(128)
        [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object { 
            [Void]$StringBuilder.Append($_.ToString("x2")) 
        } 
        $StringBuilder.ToString() 
    }
}

function pause {
    Read-Host "`n`nPress Enter to continue." | Out-Null
}

$pwned = 0


function welcome {
    Write-Host "`n`n================================`n|      Have I Been Pwned       |`n|        Password Query        |`n================================`n`n"
}

function password_input {
    $Script:passSec = Read-Host "* Password to query?" -AsSecureString
    $Script:passHash = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:passSec)) | Get-StringHash

    $Script:hashPrefix = $passHash.Substring(0,5)
    $Script:hashSuffix = $passHash.Substring(5)

    Write-Host "`n`n--------------------------------`n"
    Write-Host "SHA1 Hash:   $Script:passHash"
    Write-Host "Hash Prefix: $Script:hashPrefix|"
    Write-host "Hash Suffix:     |$Script:hashSuffix`n"
    Write-Host "--------------------------------`n`n"
}

function pw_query {
    $Local:AllProtocols = [System.Net.SecurityProtocolType]'Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $Local:AllProtocols
    
    $url = "https://api.pwnedpasswords.com/range/" + $Script:hashPrefix
    
    Write-Host "Querying... $url`n`n"

    $Script:query = Invoke-WebRequest -Method GET -Uri $url
}

function parse_results {
    Write-Host "Returned Hash Suffixes:" ($Script:query | Measure-Object -Line).Lines
    Write-Host

    ($Script:query.Content -split '\r?\n').trim() | ForEach {
        #write-host $_.Substring(0,35)
        #write-host $_.Substring(36)
        If ($Script:hashSuffix -eq $_.Substring(0,35)) {
            $Script:pwned = 1
            Write-Host "Password pwned!" -ForegroundColor Red
            Write-Host "Times found:" $_.Substring(36)
        }
    }
    If ($Script:pwned -eq 0) {
        Write-Host "Clean" -ForegroundColor Green
    }
    pause
}

welcome
try {}
catch {}
finally {
	password_input
	pw_query
	parse_results
}
