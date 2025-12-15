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
            iwr hwhashitw.tinypsapp.com -UseBasicParsing | iex

        This will download the script from github and present a menu to add/check/update devices including Group Tags.

        Note: This script usings an Azure Function app already confgiured with the rights to perform the actions.

            Although the URL for the Azure Function is included in the script its been encrypted using a AES Key.
            When the script is run, the admin is prompted to enter a password.  No other files are needed

    .VERSION
    ===========================================================================
    V1.2        Updated with descrition for release
    V1.3        Updated ConvertFrom-SecurePhrase to handle missing password
	===========================================================================

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)][string]$action,
    [Parameter(Mandatory = $false)][string]$serialnumber,
    [Parameter(Mandatory = $false)][string]$Manufacturer
)

[version]$version = 1.6


# Azure Config
$azureurl = "https://intune-autoimport-app-cbchanbpevgtbee0.australiasoutheast-01.azurewebsites.net/api/Update-IntuneDevice"
$azureKeyEncrypted = "76492d1116743f0423413b16050a5345MgB8AGIAWQB3AEcAaAAyADkAdQBlAGsATgB3ADEAbQAyACsARABCADgAbwBwAFEAPQA9AHwANwA0AGUANgAyADgAMABjADAAZQAxAGQANABkAGMAZABiAGMANwBmADcAYQAwAGMAMABkAGYAOAA5AGQANQA2AGMAYgAwADcAMQBkADUAZAA2ADEAZgAzAGYAYgBmAGQAMwBjADgAZQAyADUAOQAzAGUAZgAzAGIAZgA5ADEAZQAwADYAZQAzADMAMABkAGYAMQA1AGUAMgA0AGMANABmAGYANgA0AGEAMAA4ADMAZQBjAGIANwAyADcANQBhAGQAYwA0ADEAYwBmAGUANABkADQANQA5AGIANABiAGYANgBjADYAYQBhAGUAZQBjADEANwA2ADcAMgA2ADgAYwBjAGYAMgA3ADMAZgBmADEAMgBlADEAYwA4ADcAYQBmAGYAOQA0ADEAOAA3AGIAYwAxAGYAYQAzADMAYgBhADAAZAAyAGYAYQAxADEANwAzADMANwA2AGIAZAAzADkANQAwADgAMQBlAGQANAAwADkAMgAzAGEAMABkADQAMwAzADcAZgAyAGEAMQBhAGEANwA1ADEAOAAzADIAZgAzADEANwBiAGEAOQBhADkAOAA2ADUANQBjADcAMgA3ADYANwBiAGIAMABkADgAOAA2AGQANQBjADQANABmADkAYwBkAGEANAAxADMAYQA3AGMANgBmADkAYgBmADMANQA3AGIAMQA="
# This key is encrypted and needs the admin to enter a password before it can be used!

$SerialNumber = (Get-CimInstance win32_bios).SerialNumber
$Manufacturer = (Get-CimInstance Win32_ComputerSystem).Manufacturer  #dont use bios.Manufacturer its wrong
$Model          = (Get-CimInstance Win32_ComputerSystem).Model
$IntuneDeviceID = try {(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -match "MS-Organization-Access"} | Select-Object -ExpandProperty Subject).tolower().TrimStart("cn=")} catch {$null}
$IntuneDeviceHWhash = $((Get-CimInstance -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")).DeviceHardwareData
$grouptag = ""


function ConvertFrom-SecurePhrase { 
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$string,
        [Parameter(Mandatory = $true)][string]$Passkey
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
    $UnSecurePhrase = [System.Net.NetworkCredential]::new("", $($string | ConvertTo-SecureString -key $PrivateKey -ErrorAction SilentlyContinue)).Password

    write-host $UnSecurePhrase

    if ([string]::IsNullOrEmpty($UnSecurePhrase)) {
        throw {"Decryption Failed!"}
    }
    return $UnSecurePhrase
}

function get-azurekey {
    if ($null -eq $Global:azurekey) {
        $password = read-host -prompt "Password Phrase to Decrypt Script Keys" -AsSecureString
        if ([string]::IsNullOrEmpty($password) -eq $false) {
            $password = [System.Net.NetworkCredential]::new("", $Password).Password
            $Global:azurekey = ConvertFrom-SecurePhrase -string $azureKeyEncrypted -Passkey $password
        }
    }
}

function Get-MenuAction {

    write-host "`nWindows Autopilot Import / Check Tool $($version)`n" -ForegroundColor Green
    write-host "Device Info: `n" -ForegroundColor Yellow
    write-host "    Machine Manufacturer:   " -NoNewline -ForegroundColor Yellow
    write-host "$Manufacturer"
    write-host "    Machine Model:          " -NoNewline -ForegroundColor Yellow
    write-host "$model"
    write-host "    Machine SerialNumber:   " -NoNewline -ForegroundColor Yellow
    write-host "$SerialNumber"
    write-host "    Intune DeviceID:        " -NoNewline -ForegroundColor Yellow
    write-host "$IntuneDeviceID`n"
    write-host "    Azure Key Decrypted:    " -NoNewline -ForegroundColor Yellow
    if ($global:azurekey) {           
        write-host "Yes`n" -ForegroundColor Green
    } else {
        write-host "No`n"
    }
    write-host "1." -ForegroundColor Yellow -NoNewline
    write-host " Add Device to AutoPilot" 
    write-host "2." -ForegroundColor Yellow -NoNewline
    write-host " Check Device in Autopilot"
    write-host "3." -ForegroundColor Yellow -NoNewline
    write-host " Update Group Tag"
    write-host "4." -ForegroundColor Yellow -NoNewline
    write-host " Show Local Autopilot Policy"
    write-host "5." -ForegroundColor Yellow -NoNewline
    write-host " Show Autopilot Donwload ZTD File"
    write-host "6." -ForegroundColor Yellow -NoNewline
    write-host " Exit"
    $action = read-host -Prompt "Choose Action (1 - 5)"

    return $action
}

$action = Get-MenuAction

$action
switch ($action) {
   { @("2", "check") -contains $_ } {  #check device
        get-AzureKey
        $body = @{
            action              = "CheckDevice"
            SerialNumber        = $SerialNumber
            Manufacturer        = $Manufacturer
            IntuneDeviceID      = $IntuneDeviceID
            IntuneDeviceHWhash  = $IntuneDeviceHWhash
            NewGroupTag         = $groupTag
        }
        $Result = Invoke-RestMethod -Uri "$($azureurl)?code=$($Global:azurekey)" -Method Post -Body ($body | convertto-json) -ContentType 'application/json'

        if ($result.Status -ne "DeviceNotFound") {
            $result
        } else {
            write-host "Device not in Autopilot" -ForegroundColor red
        }
            
    }
    "3" {
        get-AzureKey
        $grouptag = read-host -prompt "Enter new GroupTag: "
        $body = @{
            action              = "UpdateGroupTag" 
            SerialNumber        = $SerialNumber
            Manufacturer        = $Manufacturer
            IntuneDeviceID      = $IntuneDeviceID
            IntuneDeviceHWhash  = $IntuneDeviceHWhash
            NewGroupTag         = $groupTag
        }
        $Result = Invoke-RestMethod -Uri "$($azureurl)?code=$($Global:azurekey)" -Method Post -Body ($body | convertto-json) -ContentType 'application/json'
        
        if ($result.Status -ne "DeviceNotFound") {
            $result
        } else {
            write-host "Device not in Autopilot" -ForegroundColor red
        }
    }
    
    "1" {
        get-AzureKey
        $body = @{
            action              = "RegisterDevice" 
            SerialNumber        = $SerialNumber
            Manufacturer        = $Manufacturer
            IntuneDeviceID      = $IntuneDeviceID
            IntuneDeviceHWhash  = $IntuneDeviceHWhash
            NewGroupTag         = $groupTag
        }
        $Result = Invoke-RestMethod -Uri "$($azureurl)?code=$($Global:azurekey)" -Method Post -Body ($body | convertto-json) -ContentType 'application/json'
        $result

    }

    "4" {
        try {
            $LocalAutopilotPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache" -Name "PolicyJsonCache" | Select-Object -ExpandProperty PolicyJsonCache -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        } catch {}
        $AutopilotInfo = @()
        Write-Host "`nLocal Autopilot Info:" -ForegroundColor Yellow
        if ($LocalAutopilotPolicy) {
            $LocalAutopilotPolicy | fl
        } else {
            write-host "`nNo Local Policy Found!" -ForegroundColor red
        }
        
        try {
            $AutopilotDiag = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot"  | Select-Object -Property CloudAssignedLanguage, CloudAssignedRegion -ErrorAction SilentlyContinue 
        } catch {}
        Write-Host "`nLocal Autopilot Diag:" -ForegroundColor Yellow
        if ($AutopilotDiag) {
            $AutopilotDiag  | fl
            
        } else {
            write-host "`nNo Autopilot Diag!" -ForegroundColor red
        }
    }

    "5" {
        try {
            $AutopilotDDSZTDFile = Get-Content "C:\Windows\ServiceState\wmansvc\AutopilotDDSZTDFile.json" -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        } catch {}
        Write-Host "` Autopilot Policy Downloaded:" -ForegroundColor Yellow
        if ($AutopilotDDSZTDFile) {
            $AutopilotDDSZTDFile | fl
        } else {
            write-host "`nNo Policy File Found!" -ForegroundColor red
        }
    }

    default {
        Write-host "Exiting...."
    }
}

