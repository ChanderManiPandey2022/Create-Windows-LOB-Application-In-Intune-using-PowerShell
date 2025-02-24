cls﻿
# SYNOPSIS
# Create Windows LOB Application in Intune Using PowerShell.

# DESCRIPTION
# This script automates the creation of Windows LOB Applications in Intune using PowerShell.

# DEMO
# YouTube video link → https://www.youtube.com/@chandermanipandey8763

# INPUTS
# Provide all required information in the User Input section.

# OUTPUTS
# Automatically creates a Windows LOB Application in Intune using PowerShell.

# Download the AzCopy portable binary
# https://aka.ms/downloadazcopy-v10-windows

# NOTES
# Version:         1.0  
# Author:          Chander Mani Pandey  
# Creation Date:   24 Feb 2025

# Find the author on:  
# YouTube:    https://www.youtube.com/@chandermanipandey8763  
# Twitter:    https://twitter.com/Mani_CMPandey  
# LinkedIn:   https://www.linkedin.com/in/chandermanipandey  
# BlueSky:    https://bsky.app/profile/chandermanipandey.bsky.social
# GitHub:     https://github.com/ChanderManiPandey2022


Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' 

$error.clear() ## this is the clear error history 

$ErrorActionPreference = 'SilentlyContinue';

#=============================================User Input Section Start ==========================================================#
#================================================================================================================================#

$filePathApp = "C:\TEMP\Apps\VLC_Media_Player\vlc-3.0.8-win64.msi"     #MSI Application setup file location 

$imagePathLogo = "C:\TEMP\Apps\VLC_Media_Player\VLC_Media_Player.jpg"  #MSI Application Logo file location

$toolPathAzCopy = "C:\TEMP\Apps\AzCopy\azcopy.exe"                     #Azcopy.exe file path

$logPathAzCopy = "C:\Windows\Temp\AzLog"                               #Azcopy Logging Path       

$GroupID = "dfc65d28-2b56-4723-9393-6767b231dbfc"                      # Entra Group Object ID 

$InstallMode = "uninstall"                                             # Options: available, required, uninstall

#=============================================User Input Section End =============================================================#
#=================================================================================================================================#

Write-Host "======================================================================================================================" -ForegroundColor Yellow
Write-Host "======================================================================================================================" -ForegroundColor Yellow
Write-Host ""

$LOPAPP=@"
             *****  *****   *****  *****  *****  *****     *      ***   *****      *****    ****   ****    *****
            *       *    *  *      *   *    *    *         *     *   *  *    *     *   *    *   *  *   *   *
            *       *****   ****   *****    *    *****     *     *   *  *****      *****    ****   ****    *****
            *       *  *    *      *   *    *    *         *     *   *  *    *     *   *    *      *           *
             *****  *   *   *****  *   *    *    *****     *****  ***   *****      *   *    *      *       *****
"@

Write-Host $LOPAPP -ForegroundColor Magenta

Write-Host ""
Write-Host "=======================================================================================================================" -ForegroundColor Yellow
Write-Host "=======================================================================================================================" -ForegroundColor Yellow
Write-Host ""
#=================================================================================================================================#

# Function to check, install, and import a module
function Ensure-Module {
    param (
        [string]$moduleToCheck
    )
    $moduleStatus = Get-Module -Name $moduleToCheck -ListAvailable
    Write-Host "Checking if $moduleToCheck is installed" -ForegroundColor Yellow
    if ($moduleStatus -eq $null) {

        Write-Host "$moduleToCheck is not installed" -ForegroundColor Red
    
        Write-Host "Installing '$moduleToCheck'" -ForegroundColor Yellow
    
        Install-Module $moduleToCheck -Force
    
        Write-Host "$moduleToCheck has been installed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "$moduleToCheck is already installed" -ForegroundColor Green
    }
    Write-Host "Importing $moduleToCheck module" -ForegroundColor Yellow
    
    Import-Module $moduleToCheck -Force
    
    Write-Host "$moduleToCheck module imported successfully" -ForegroundColor Green
}

# Ensure Microsoft.Graph.DeviceManagement.Enrollment is installed and imported

Ensure-Module -moduleToCheck "Microsoft.Graph.Authentication"

# Connect to Microsoft Graph

Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All" -NoWelcome -ErrorAction Stop

#================================================================================================================================#

# Secures the application file with AES encryption for safe Intune deployment.

function EncryptFile($sourceFileToEncrypt) {
    function GenerateEncryptionKey() {

        $aesProvider = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aesProvider.GenerateKey()
        return $aesProvider.Key
    }
    $encryptedOutputFile = "$sourceFileToEncrypt.bin"

    $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()

    $aesAlgorithm = [System.Security.Cryptography.Aes]::Create()

    $aesAlgorithm.Key = GenerateEncryptionKey

    $hmacAlgorithm = [System.Security.Cryptography.HMACSHA256]::new()

    $hmacAlgorithm.Key = GenerateEncryptionKey

    $hashSize = $hmacAlgorithm.HashSize / 8

    $inputStream = [System.IO.File]::OpenRead($sourceFileToEncrypt)

    $fileHash = $hashAlgorithm.ComputeHash($inputStream)

    $inputStream.Seek(0, "Begin") | Out-Null

    $outputStream = [System.IO.File]::Open($encryptedOutputFile, "Create")

    $outputStream.Write((New-Object byte[] $hashSize), 0, $hashSize)

    $outputStream.Write($aesAlgorithm.IV, 0, $aesAlgorithm.IV.Length)

    $encryptionTransform = $aesAlgorithm.CreateEncryptor()

    $cryptoStream = [System.Security.Cryptography.CryptoStream]::new($outputStream, $encryptionTransform, "Write")

    $inputStream.CopyTo($cryptoStream)

    $cryptoStream.FlushFinalBlock()

    $outputStream.Seek($hashSize, "Begin") | Out-Null

    $hmacHash = $hmacAlgorithm.ComputeHash($outputStream)

    $outputStream.Seek(0, "Begin") | Out-Null

    $outputStream.Write($hmacHash, 0, $hmacHash.Length)

    $outputStream.Close()

    $cryptoStream.Close()

    $inputStream.Close()

    return [PSCustomObject][ordered]@{
        encryptionKey        = [System.Convert]::ToBase64String($aesAlgorithm.Key)

        fileDigest           = [System.Convert]::ToBase64String($fileHash)

        fileDigestAlgorithm  = "SHA256"

        initializationVector = [System.Convert]::ToBase64String($aesAlgorithm.IV)

        mac                  = [System.Convert]::ToBase64String($hmacHash)

        macKey               = [System.Convert]::ToBase64String($hmacAlgorithm.Key)

        profileIdentifier    = "ProfileVersion1"
    }
}

#================================================================================================================================#

# Function to get MSI file information

function Get-MSIFileInformation {
    param(

        [parameter(Mandatory=$true)]
        
        [ValidateNotNullOrEmpty()]
        
        [System.IO.FileInfo]$msiFilePath,
        
        [parameter(Mandatory=$true)]
        
        [ValidateNotNullOrEmpty()]
        
        [ValidateSet("ProductCode", "ProductVersion", "ProductName", "Manufacturer", "ProductLanguage", "FullVersion")]
        
        [string]$propertyToFetch
    )
    Process {
        try {
            # Read property from MSI database
            $installerObject = New-Object -ComObject WindowsInstaller.Installer
        
            $databaseObject = $installerObject.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installerObject, @($msiFilePath.FullName, 0))
        
            $queryString = "SELECT Value FROM Property WHERE Property = '$($propertyToFetch)'"
        
            $viewObject = $databaseObject.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $databaseObject, ($queryString))
        
            $viewObject.GetType().InvokeMember("Execute", "InvokeMethod", $null, $viewObject, $null)
        
            $recordObject = $viewObject.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $viewObject, $null)
        
            $propertyValue = $recordObject.GetType().InvokeMember("StringData", "GetProperty", $null, $recordObject, 1)
     
            # Commit database and close view
        
            $databaseObject.GetType().InvokeMember("Commit", "InvokeMethod", $null, $databaseObject, $null)
        
            $viewObject.GetType().InvokeMember("Close", "InvokeMethod", $null, $viewObject, $null)           
        
            $databaseObject = $null
     
            $viewObject = $null
     
            # Return the value
     
            return $propertyValue
        }
        catch {
     
            Write-Warning -Message $_.Exception.Message;
     
            break;
        }
    }
    End {
     
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($installerObject) | Out-Null
     
        [System.GC]::Collect()
    }
}
#================================================================================================================================#


# Function to extract MSI properties using Windows Installer API

function Get-MsiProperties {
    param ($msiFile)

    $installer = New-Object -ComObject WindowsInstaller.Installer

    $database = $installer.OpenDatabase($msiFile, 0)

    $view = $database.OpenView("SELECT Property, Value FROM Property")

    $view.Execute()

    $msiData = @{ }

    while ($record = $view.Fetch()) 
    {
        $property = $record.StringData(1)
    
        $value = $record.StringData(2)
    
        $msiData[$property] = $value
    }
    $view.Close()
    
    return $msiData
}
#================================================================================================================================#

# Validate MSI file existence
if (-Not (Test-Path $filePathApp )) {
    
    Write-Host "MSI file not found: $filePathApp" -ForegroundColor Red
    
    return
}

#================================================================================================================================#
#================================================================================================================================#

# Fetching Application Information

$pathToMSI = "$filePathApp"

$tempOutputFile = [System.IO.Path]::GetDirectoryName("$filePathApp") + "\" + [System.IO.Path]::GetFileNameWithoutExtension("$filePathApp") + "_temp.bin"

$appFileName = [System.IO.Path]::GetFileName("$pathToMSI")

$appName = (Get-MSIFileInformation -msiFilePath "$pathToMSI" -propertyToFetch ProductName | Out-String).trimend()

$appCode = (Get-MSIFileInformation -msiFilePath "$pathToMSI" -propertyToFetch ProductCode | Out-String).trimend()

$appVersion = (Get-MSIFileInformation -msiFilePath "$pathToMSI" -propertyToFetch ProductVersion | Out-String).trimend()

$appLanguage = (Get-MSIFileInformation -msiFilePath "$pathToMSI" -propertyToFetch ProductLanguage | Out-String).trimend()

$appDeveloper = (Get-MSIFileInformation -msiFilePath "$pathToMSI" -propertyToFetch Manufacturer | Out-String).trimend()

$appFileName = Split-Path -Path $filePathApp -Leaf

$CustomApp_Log = "C:\Windows\Logs\${appFileName}_LOB_Install.log"

$msiProperties = Get-MsiProperties -msiFile $filePathApp 
#================================================================================================================================#
# Define a hash table for language codes
$languageMap = @{
    1052 = "Albanian (Albania)"
    1025 = "Arabic (Saudi Arabia)"
    1026 = "Bulgarian (Bulgaria)"
    1027 = "Catalan (Spain)"
    2052 = "Chinese Simplified (PRC)"
    1028 = "Chinese Traditional (Taiwan)"
    1050 = "Croatian (Croatia)"
    1029 = "Czech (Czech Republic)"
    1030 = "Danish (Denmark)"
    1043 = "Dutch (Netherlands)"
    1033 = "English (United States)"
    1065 = "Farsi (Iran)"
    1035 = "Finnish (Finland)"
    1036 = "French (France)"
    1031 = "German (Germany)"
    1032 = "Greek (Greece)"
    1037 = "Hebrew (Israel)"
    1038 = "Hungarian (Hungary)"
    1039 = "Icelandic (Iceland)"
    1057 = "Indonesian (Indonesia)"
    1040 = "Italian (Italy)"
    1041 = "Japanese (Japan)"
    1087 = "Kazakh (Kazakhstan)"
    1042 = "Korean (Korea)"
    1044 = "Norwegian (Bokmal - Norway)"
    2068 = "Norwegian (Nynorsk - Norway)"
    1045 = "Polish (Poland)"
    2070 = "Portuguese (Portugal)"
    1049 = "Russian (Russia)"
    3098 = "Serbian (Cyrillic - Serbia & Montenegro)"
    2074 = "Serbian (Latin - Serbia & Montenegro)"
    1051 = "Slovak (Slovakia)"
    1060 = "Slovenian (Slovenia)"
    3082 = "Spanish (Spain - International sort)"
    1053 = "Swedish (Sweden)"
    1055 = "Turkish (Turkey)"
    1058 = "Ukrainian (Ukraine)"
    1077 = "Zulu (South Africa)"
}

# Function to find language by code
function Get-LanguageName {
    param (
        [int]$LanguageCode
    )
    
    if ($languageMap.ContainsKey($LanguageCode)) {
        return $languageMap[$LanguageCode]
    } else {
        return "Unknown Language Code"
    }
}

$languageName = Get-LanguageName -LanguageCode $($msiProperties.ProductLanguage)

#================================================================================================================================#

$appDetails = @{

    "@odata.type" = "#microsoft.graph.windowsMobileMSI"

    categories = @()
   
    commandLine= "/quiet /norestart /l*v `"$CustomApp_Log`""

    description ="$appName"

    developer= "$appDeveloper"

    displayName="$appName"

    fileName="$appFileName"

    identityVersion="$appVersion"

    ignoreVersionDetection = $true

    informationUrl="$($msiProperties.ARPURLINFOABOUT)"

    isFeatured= $false

    notes="Deploy $appName in $languageName Language"

    owner="Created By @ChanderManiPandey"

    privacyInformationUrl ="$($msiProperties.ARPHELPLINK)"

    productCode="$appCode"

    productVersion ="$appVersion"

    publisher= "$appDeveloper"

    roleScopeTagIds=@()
}

#================================================================================================================================#

# Create app in Intune

Write-Host ""

Write-Host "Creating $appName Application In Intune Portal......." -ForegroundColor Yellow

$uriCreateApp = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

$appCreated = Invoke-MgGraphRequest -Method POST -Uri $uriCreateApp -Body ($appDetails | ConvertTo-Json -Depth 10)

Write-Host "$appName metadata created successfully." -ForegroundColor Green

Write-Host "$appName version is $appVersion" -ForegroundColor Green  

Write-Host "$appName developer name is $appDeveloper" -ForegroundColor Green 

Write-Host "$appName GUID is $($appCreated.id)" -ForegroundColor Green

Write-Host "$appName information Url is $($msiProperties.ARPURLINFOABOUT) " -ForegroundColor Green

Write-Host "$appName Product Language is $languageName" -ForegroundColor Green

Write-Host "$appName custom log location is $CustomApp_Log" -ForegroundColor Green

#================================================================================================================================#

# Process content version

$uriContentVersion = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.windowsMobileMSI/contentVersions"

$contentVersionCreated = Invoke-MgGraphRequest -Method POST -Uri $uriContentVersion -Body "{}"

Write-Host "$appName content ID is $($contentVersionCreated.id)" -ForegroundColor Green

Write-Host ""

#================================================================================================================================#

# Encrypting application

Write-Host "Starting encryption for $appName......." -ForegroundColor Yellow

$encryptedFileOutput = "$filePathApp.bin"

if (Test-Path $encryptedFileOutput) 
{

    Remove-Item $encryptedFileOutput -Force
}

$encryptionInfo = EncryptFile $filePathApp

Write-Host "Encryption completed successfully for $appName" -ForegroundColor Green

Write-Host ""

#================================================================================================================================#

Write-Host "Creating the manifest file for application......." -ForegroundColor Yellow

#$msiProperties = Get-MsiProperties -msiFile $filePathApp 

# Determine installation type

$isMachineInstall = if ($msiProperties.ALLUSERS -eq "1") { "true" } else { "false" }

$isUserInstall = if ($msiProperties.ALLUSERS -eq "0") { "true" } else { "false" }

$upgradeCode = $msiProperties.UpgradeCode

# Properly formatted XML with variable values inserted

[xml]$manifestXML = "<MobileMsiData MsiExecutionContext='System' MsiRequiresReboot='false' MsiUpgradeCode='$upgradeCode' MsiIsMachineInstall='$isMachineInstall' MsiIsUserInstall='$isUserInstall' MsiIncludesServices='false' MsiContainsSystemRegistryKeys='false' MsiContainsSystemFolders='false'></MobileMsiData>"

$manifestOutput = $manifestXML.OuterXml.ToString()

$manifestBytes = [System.Text.Encoding]::ASCII.GetBytes($manifestOutput)

$manifestBase64 = [Convert]::ToBase64String($manifestBytes)

#================================================================================================================================#

# Upload to Azure Storage

Write-Host "Generating file content......." -ForegroundColor Yellow

$fileContent = @{
    "@odata.type" = "#microsoft.graph.mobileAppContentFile"
    
    name          = [System.IO.Path]::GetFileName($filePathApp)
    
    size          = (Get-Item $filePathApp).Length
    
    sizeEncrypted = (Get-Item "$filePathApp.bin").Length
    
    isDependency  = $false
    
    manifest      = $manifestBase64
}

$uriFileContent = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.windowsMobileMSI/contentVersions/$($contentVersionCreated.id)/files"  

$fileContentCreated = Invoke-MgGraphRequest -Method POST -Uri $uriFileContent -Body ( $fileContent | ConvertTo-Json)

do {
 
    Start-Sleep -Seconds 5

    $uriFileStatus = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.windowsMobileMSI/contentVersions/$($contentVersionCreated.id)/files/$($fileContentCreated.id)"
 
    $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $uriFileStatus
} while ($fileStatus.uploadState -ne "azureStorageUriRequestSuccess")

Write-Host "File content created successfully." -ForegroundColor Green

Write-Host ""

Write-Host "Uploading the application content to Azure Storage using AZCopy.exe....." -ForegroundColor Yellow

#================================================================================================================================#

# Function to upload file using AzCopy

$env:AZCOPY_LOG_LOCATION=$logPathAzCopy

function Upload-UsingAzCopy {
    param (

        [string]$fileToUpload, 

        [string]$destinationUri
    )
    if (!(Test-Path $toolPathAzCopy)) {

        Write-Host "AzCopy.exe not found. Please install AzCopy and try again."

        exit 1
    }
    
    Write-Host "Using AzCopy.exe to upload file on Azure Blob" -ForegroundColor White

    & $toolPathAzCopy copy $fileToUpload $destinationUri --recursive=true
    
    if ($?) {

        Write-Host "Application Content Upload successful on Azure Blob using AzCopy.exe" -ForegroundColor Green
    } else {

        Write-Host "Application Content Upload failed using AzCopy.exe"  -ForegroundColor Red
    }
}
#================================================================================================================================#

# Always use AzCopy for upload.Uploading application content using AzCopy.exe to Azure Blob

Upload-UsingAzCopy -fileToUpload "$filePathApp.bin" -destinationUri $fileStatus.azureStorageUri

Write-Host ""

#================================================================================================================================#

# Commit the uploaded file

Write-Host "Starting file commit process......." -ForegroundColor Yellow

$commitData = @{

    fileEncryptionInfo = $encryptionInfo
}

$uriCommit = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.windowsMobileMSI/contentVersions/$($contentVersionCreated.id)/files/$($fileContentCreated.id)/commit"

Invoke-MgGraphRequest -Method POST -Uri $uriCommit -Body ($commitData | ConvertTo-Json)

$retryCount = 0

$maxRetries = 5

do {
    Start-Sleep -Seconds 10

    $uriFileStatus = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)/microsoft.graph.windowsMobileMSI/contentVersions/$($contentVersionCreated.id)/files/$($fileContentCreated.id)"
    
    $fileStatus = Invoke-MgGraphRequest -Method GET -Uri $uriFileStatus

    if ($fileStatus.uploadState -eq "commitFileFailed") 
    {

        $commitResponse = Invoke-MgGraphRequest -Method POST -Uri $uriCommit -Body ($commitData | ConvertTo-Json)

        $retryCount++
    }

} while ($fileStatus.uploadState -ne "commitFileSuccess" -and $retryCount -lt $maxRetries)

if ($fileStatus.uploadState -eq "commitFileSuccess") 
{
    Write-Host "File committed successfully" -ForegroundColor Green
}
else 
{
    Write-Host "Failed to commit file after $maxRetries attempts." -ForegroundColor red
    
    exit 1
}

#================================================================================================================================#

# Update app with committed content version

$uriUpdateApp = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)"

$updateData = @{
    
    "@odata.type"           = "#microsoft.graph.windowsMobileMSI"
    
    committedContentVersion = $contentVersionCreated.id
}

Invoke-MgGraphRequest -Method PATCH -Uri $uriUpdateApp -Body ($updateData | ConvertTo-Json)


#================================================================================================================================#


# Updated/Uploaded application logo

Write-Host ""

Write-Host "Uploading $appName logo......." -ForegroundColor Yellow

# Convert the logo to base64

$logoBase64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($imagePathLogo))

# Prepare the request body

$ApplogoBody = @{
    "@odata.type" = "#microsoft.graph.mimeContent"

    "type"        = "image/png"

    "value"       = $logoBase64
}

$uriLogoUpdate = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appCreated.id)"

$Body = @{
    "@odata.type" = "#microsoft.graph.windowsMobileMSI"

    "largeIcon"   = $ApplogoBody
}


Invoke-MgGraphRequest -Method PATCH -Uri $uriLogoUpdate -Body ($Body | ConvertTo-Json -Depth 10)

Write-Host "$appName Logo uploaded successfully." -ForegroundColor green

Write-Host ""

#================================================================================================================================#

# Adding an application assignment using the Graph API...

Write-Host "Adding $appName application assignment......." -ForegroundColor Yellow

$ApiResource = "deviceAppManagement/mobileApps/$($appCreated.id)/assign"

$RequestUri = "https://graph.microsoft.com/beta/$ApiResource"

# Validate inputs

if (-not ($($appCreated.id))) { Write-Host "No Application Id specified" -ForegroundColor Red; exit }

if (-not $GroupID) { Write-Host "No Target Group Id specified" -ForegroundColor Red; exit }

if (-not $InstallMode) { Write-Host "No Install Intent specified" -ForegroundColor Red; exit }

# JSON body

$JsonBody = @"
{
    "mobileAppAssignments": [
        {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$GroupID"
            },
            "intent": "$InstallMode"
        }
    ]
}
"@

# Invoke API request

try 
{
    Invoke-MgGraphRequest -Uri $RequestUri -Method Post -Body $JsonBody -ContentType "application/json"
}
 catch
  {
    $Exception = $_.Exception
 
    $ErrorResponse = $Exception.Response.GetResponseStream()
 
    $StreamReader = New-Object System.IO.StreamReader($ErrorResponse)
 
    $StreamReader.BaseStream.Position = 0
 
    $StreamReader.DiscardBufferedData()
 
    $ResponseContent = $StreamReader.ReadToEnd()
 
    Write-Host "Response content:`n$ResponseContent" -ForegroundColor Red
 
    Write-Error "Request to $RequestUri failed with HTTP Status $($Exception.Response.StatusCode) $($Exception.Response.StatusDescription)"
}

Write-Host "$appName LOB application assigned successfully." -ForegroundColor Green

Write-host ""


#================================================================================================================================#


# Removing temporary files and folder.

# Define folders to delete.

$folders = @("$env:USERPROFILE\.azcopy", $logPathAzCopy, "$filePathApp.bin")

# Loop through each folder and delete if it exists

Write-Host "Removing temporary files and folders......." -ForegroundColor Yellow

$folders | ForEach-Object { if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force } }

Write-Host "Temporary files and folders removed successfully." -ForegroundColor Green

Write-Host ""

Write-Host "$appName LOB application created successfully" -ForegroundColor Green

Write-Host "Script execution completed! $appName LOB application is ready for testing." -ForegroundColor Green

Write-Host ""

#================================================================================================================================#
#Disconnect MgGraph
#Disconnect-MgGraph
#================================================================================================================================#

Write-Host "====================================================================================================================="
