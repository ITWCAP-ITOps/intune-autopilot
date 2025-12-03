<#	
	.NOTES
	===========================================================================
	 Created on:   	25/11/2025
	 Created by:   	Craig Cram
	 Organization: 	Xology
	 Filename:     	Update-HWHash.ps1
	===========================================================================
	.DESCRIPTION
		The script will be downloaded with a single line on Windows 10/11 machines in the OOBE starting screen.

        The Administrator will press Shift-F10 to open a command prompt and type the following commands:

            powershell
            iwr hwhashxo.tinypsapp.com -UseBasicParsing | iex

        This will download the script from github and present a menu to add/check/update devices including Group Tags.

        Note: This script usings an Azure Function app already confgiured with the rights to perform the actions.

            Although the URL for the Azure Function is included in the script its been encrypted using a AES Key.
            When the script is run, the admin is prompted to enter a password.  No other files are needed

    .VERSION
    ===========================================================================
    V1.2        Updated with descrition for release
	===========================================================================

#>
[version]$version = 1.2


# Azure Config
$azureurl = "https://intune-autoimport-app-cbchanbpevgtbee0.australiasoutheast-01.azurewebsites.net/api/Update-IntuneDevice"
$azureKeyEncrypted = "76492d1116743f0423413b16050a5345MgB8ADMANQBFAGYAWgBTAGsAeAB0AE4AbAByAFMASwBsAEIAcQBJAFgASwBSAHcAPQA9AHwANQA5ADEAMwA0ADYAYQBhADMANAA2ADAAMQAxAGYAZgBkAGYAZgA5ADYAMQBlADIAZAAyAGEAOAA1ADgAYgA1ADgAYQA4ADYANwAxADYAOAA2ADcAYwBiAGQAOQA1ADkANwBiAGEAMAA4AGIAOQAyAGUAOABjAGYANgAyAGIAYQBmADYAYwBhAGQAOABmADEAYQBkADcAOAA5AGYAMgA3AGYANwBjAGIAMQAyADAANAAyADEAYwA3AGIAMQAxADgANgA3ADEAMAA5ADEAZAA0AGEAMQA4AGQAOAAyADYAZgAxAGIAOABiADYAZABjADgAYQA4ADAANQA1ADQAMgA3ADMANwA2ADEAYgBkADYAMQA2AGMAZgBmAGEAMgBhADUAMAAzAGYAMgBiADMAYwAwAGIANABiAGQAMgAyADYAOQAzADAAOAA3AGQAZQBjADAAZQA5ADAAOQAyADUAMgA1ADMANQA4ADUAOAA3AGUAMwBiADEAZgA3AGEAOABlAGIAMgBmADkAYwAzAGIANgA4AGMAZgBhADcAZAAxAGUAOABkADAAYQA0AGIANgA1ADQAZQA2AGMAYQA3ADYAMgA5ADYANQAxAGIAOABkAGUAYQBkAGQAMwBmADAAZgBhADAAYgBjADIAMQA4ADAAZAA1AGEAMwBkADEAMgBhAGEAOAA="
# This key is encrypted and needs the admin to enter a password before it can be used!

$SerialNumber = (Get-CimInstance win32_bios).SerialNumber
$Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer  #dont use bios.Manufacturer its wrong
$Model          = (Get-CimInstance Win32_ComputerSystem).Model
$IntuneDeviceID = try {(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match "MS-Organization-Accesss"} | Select-Object -ExpandProperty Subject).tolower().TrimStart("cn=")} catch {$null}
$IntuneDeviceHWhash = $((Get-CimInstance -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")).DeviceHardwareData
$grouptag = ""


function ConvertFrom-SecurePhrase { 
    [CmdletBinding()]
    param (
    [string]$string,
    [string]$Passkey
    )
    $PrivateKey = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetBytes($Passkey)
    [Byte[]]$BytesKey = (1..32)
    # if private key too long, I throw an error
    if($PrivateKey.Length -gt 32){ throw "MAX 256 bits/32 Bytes!"  }

    $i=0
    $PrivateKey | ForEach-Object { 
        $BytesKey[$i] = $_
        $i++
    }
    $PrivateKey = $BytesKey
    $UnSecurePhrase = [System.Net.NetworkCredential]::new("", $($string | ConvertTo-SecureString -key $PrivateKey)).Password
    return $UnSecurePhrase
}

write-host " "
write-host "Windows Autopilot Import / Check Tool $($version)" -ForegroundColor Green
write-host ""
write-host "Device Info: " -ForegroundColor Yellow
write-host " "
write-host "    Machine Manufacturer:   " -NoNewline -ForegroundColor Yellow
write-host "$Manufacturer"
write-host "    Machine Model:          " -NoNewline -ForegroundColor Yellow
write-host "$model"
write-host "    Machine SerialNumber:   " -NoNewline -ForegroundColor Yellow
write-host "$SerialNumber"
write-host "    Intune DeviceID:        " -NoNewline -ForegroundColor Yellow
write-host "$IntuneDeviceID"

write-host " "
write-host "1." -ForegroundColor Yellow -NoNewline
write-host " Add Device to AutoPilot" 
write-host "2." -ForegroundColor Yellow -NoNewline
write-host " Check Device in Autopilot"
write-host "3." -ForegroundColor Yellow -NoNewline
write-host " Update Group Tag"
write-host "4." -ForegroundColor Yellow -NoNewline
write-host " Exit"
$action = read-host -Prompt "Choose Action (1 - 4)"

if ($global:EncryptionKey -ne $true -and $action -lt 4) {
    $password = read-host -prompt "Password Phrase to Decrypt Script Keys" -AsSecureString
    $password = [System.Net.NetworkCredential]::new("", $Password).Password
    $azurekey = ConvertFrom-SecurePhrase -string $azureKeyEncrypted -Passkey $password
    $global:EncryptionKey = $true
}

switch ($action) {
    "2" {  #check device
        $body = @{
            action              = "CheckDevice"
            SerialNumber        = $SerialNumber
            Manufacturer        = $Manufacturer
            IntuneDeviceID      = $IntuneDeviceID
            IntuneDeviceHWhash  = $IntuneDeviceHWhash
            NewGroupTag         = $groupTag
        }
        $Result = Invoke-RestMethod -Uri "$($azureurl)?code=$($azurekey)" -Method Post -Body ($body | convertto-json) -ContentType 'application/json'

        if ($result.Status -ne "DeviceNotFound") {
            $result
        } else {
            write-host "Device not in Autopilot" -ForegroundColor red
        }
            
    }
    "3" {
        $grouptag = read-host -prompt "Enter new GroupTag: "
        $body = @{
            action              = "UpdateGroupTag" 
            SerialNumber        = $SerialNumber
            Manufacturer        = $Manufacturer
            IntuneDeviceID      = $IntuneDeviceID
            IntuneDeviceHWhash  = $IntuneDeviceHWhash
            NewGroupTag         = $groupTag
        }
        $Result = Invoke-RestMethod -Uri "$($azureurl)?code=$($azurekey)" -Method Post -Body ($body | convertto-json) -ContentType 'application/json'
        
        if ($result.Status -ne "DeviceNotFound") {
            $result
        } else {
            write-host "Device not in Autopilot" -ForegroundColor red
        }
    }
    
    "1" {

        $body = @{
            action              = "RegisterDevice" 
            SerialNumber        = $SerialNumber
            Manufacturer        = $Manufacturer
            IntuneDeviceID      = $IntuneDeviceID
            IntuneDeviceHWhash  = $IntuneDeviceHWhash
            NewGroupTag         = $groupTag
        }
        $Result = Invoke-RestMethod -Uri "$($azureurl)?code=$($azurekey)" -Method Post -Body ($body | convertto-json) -ContentType 'application/json'
        $result

    }

    default {
        Write-host "Exiting...."
    }
}

