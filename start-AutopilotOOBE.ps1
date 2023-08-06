[CmdletBinding()]
param()
#region Initialize

#Start the Transcript
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-OSDCloud.log"
$null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore

#=================================================
#   oobeCloud Settings
#=================================================
$Global:oobeCloud = @{
    oobeSetDisplay = $true
    oobeSetDateTime = $true
    oobeRegisterAutopilot = $true
    oobeRemoveAppxPackage = $true
    oobeRemoveAppxPackageName = 'Microsoft.BingNews','Microsoft.BingWeather','Microsoft.GamingApp','Microsoft.GetHelp','Microsoft.Getstarted','Microsoft.MicrosoftSolitaireCollection','Microsoft.People','microsoft.windowscommunicationsapps','Microsoft.WindowsFeedbackHub','Microsoft.WindowsMaps','Microsoft.Xbox.TCUI','Microsoft.XboxGameOverlay','Microsoft.XboxGamingOverlay','Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay','Microsoft.ZuneMusic','Microsoft.ZuneVideo','Clipchamp.Clipchamp','Microsoft.YourPhone','MicrosoftTeams'
    oobeUpdateDrivers = $true
    oobeUpdateWindows = $true
    oobeSetUserRegSettings = $true
    oobeSetDeviceRegSettings = $true
    oobeUpdateDefender = $true
    oobeCreateLocalUser = $true
    oobeExecutionPolicyRestricted = $true
    oobeRestartComputer = $true
}


function Step-oobeSetDisplay {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeSetDisplay -eq $true)) {
        Write-Host -ForegroundColor Yellow 'Verify the Display Resolution and Scale is set properly'
        Start-Process 'ms-settings:display' | Out-Null
        $ProcessId = (Get-Process -Name 'SystemSettings').Id
        if ($ProcessId) {
            Wait-Process $ProcessId
        }
    }
}
function Step-oobeSetDateTime {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeSetDateTime -eq $true)) {
        Write-Host -ForegroundColor Yellow 'Verify the Date and Time is set properly including the Time Zone'
        Write-Host -ForegroundColor Yellow 'If this is not configured properly, Certificates and Autopilot may fail'
        Start-Process 'ms-settings:dateandtime' | Out-Null
        $ProcessId = (Get-Process -Name 'SystemSettings').Id
        if ($ProcessId) {
            Wait-Process $ProcessId
        }
    }
}
function Step-oobeExecutionPolicy {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        if ((Get-ExecutionPolicy) -ne 'RemoteSigned') {
            Write-Host -ForegroundColor Cyan 'Set-ExecutionPolicy RemoteSigned'
            Set-ExecutionPolicy RemoteSigned -Force
        }
    }
}
function Step-oobePackageManagement {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        if (Get-Module -Name PowerShellGet -ListAvailable | Where-Object {$_.Version -ge '2.2.5'}) {
            Write-Host -ForegroundColor Cyan 'PowerShellGet 2.2.5 or greater is installed'
        }
        else {
            Write-Host -ForegroundColor Cyan 'Install-Package PackageManagement,PowerShellGet'
            Install-Package -Name PowerShellGet -MinimumVersion 2.2.5 -Force -Confirm:$false -Source PSGallery | Out-Null
    
            Write-Host -ForegroundColor Cyan 'Import-Module PackageManagement,PowerShellGet'
            Import-Module PackageManagement,PowerShellGet -Force
        }
    }
}
function Step-oobeTrustPSGallery {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        $PSRepository = Get-PSRepository -Name PSGallery
        if ($PSRepository)
        {
            if ($PSRepository.InstallationPolicy -ne 'Trusted')
            {
                Write-Host -ForegroundColor Cyan 'Set-PSRepository PSGallery Trusted'
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            }
        }
    }
}
function Step-oobeInstallModuleAutopilotOOBE {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        $Requirement = Import-Module AutopilotOOBE -PassThru -ErrorAction Ignore
        if (-not $Requirement)
        {
            Write-Host -ForegroundColor Cyan 'Install-Module AutopilotOOBE'
            Install-Module -Name AutopilotOOBE -RequiredVersion 21.8.31.1 -Force
            Import-Module AutopilotOOBE -Force
            Start-AutopilotOOBE
        }
        else {
            Import-Module AutopilotOOBE -Force
            Start-AutopilotOOBE
        }
    }
}
function Step-oobeRegisterAutopilot {
    [CmdletBinding()]
    param (
        [System.String]
        $Command
    )
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeRegisterAutopilot -eq $true)) {
        Step-oobeInstallModuleAutopilotOOBE
        
        Write-Host -ForegroundColor Cyan 'Registering Device in Autopilot using AutopilotOOBE ' -NoNewline        
    }
}
function Step-oobeRemoveAppxPackage {
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeRemoveAppxPackage -eq $true)) {
        Write-Host -ForegroundColor Cyan 'Removing Appx Packages'
        foreach ($Item in $Global:oobeCloud.oobeRemoveAppxPackageName) {
            if (Get-Command Get-AppxProvisionedPackage) {
                Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -Match $Item} | ForEach-Object {
                    Write-Host -ForegroundColor DarkGray $_.DisplayName
                    if ((Get-Command Remove-AppxProvisionedPackage).Parameters.ContainsKey('AllUsers')) {
                        Try
                        {
                            $null = Remove-AppxProvisionedPackage -Online -AllUsers -PackageName $_.PackageName
                        }
                        Catch
                        {
                            Write-Warning "AllUsers Appx Provisioned Package $($_.PackageName) did not remove successfully"
                        }
                    }
                    else {
                        Try
                        {
                            $null = Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName
                        }
                        Catch
                        {
                            Write-Warning "Appx Provisioned Package $($_.PackageName) did not remove successfully"
                        }
                    }
                }
            }
        }
    }
}
function Step-oobeUpdateDrivers {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeUpdateDrivers -eq $true)) {
        Write-Host -ForegroundColor Cyan 'Updating Windows Drivers'
        if (!(Get-Module PSWindowsUpdate -ListAvailable -ErrorAction Ignore)) {
            try {
                Install-Module PSWindowsUpdate -Force
                Import-Module PSWindowsUpdate -Force
            }
            catch {
                Write-Warning 'Unable to install PSWindowsUpdate Driver Updates'
            }
        }
        if (Get-Module PSWindowsUpdate -ListAvailable -ErrorAction Ignore) {
            Start-Process PowerShell.exe -ArgumentList "-Command Install-WindowsUpdate -UpdateType Driver -AcceptAll -IgnoreReboot" -Wait
        }
    }
}
function Step-oobeUpdateWindows {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeUpdateWindows -eq $true)) {
        Write-Host -ForegroundColor Cyan 'Updating Windows'
        if (!(Get-Module PSWindowsUpdate -ListAvailable)) {
            try {
                Install-Module PSWindowsUpdate -Force
                Import-Module PSWindowsUpdate -Force
            }
            catch {
                Write-Warning 'Unable to install PSWindowsUpdate Windows Updates'
            }
        }
        if (Get-Module PSWindowsUpdate -ListAvailable -ErrorAction Ignore) {
            #Write-Host -ForegroundColor DarkCyan 'Add-WUServiceManager -MicrosoftUpdate -Confirm:$false'
            Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
            #Write-Host -ForegroundColor DarkCyan 'Install-WindowsUpdate -UpdateType Software -AcceptAll -IgnoreReboot'
            #Install-WindowsUpdate -UpdateType Software -AcceptAll -IgnoreReboot -NotTitle 'Malicious'
            #Write-Host -ForegroundColor DarkCyan 'Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot'
            Start-Process PowerShell.exe -ArgumentList "-Command Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -NotTitle 'Preview' -NotKBArticleID 'KB890830','KB5005463','KB4481252'" -Wait
        }
    }
}
function Step-RestartConfirmation {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeUpdateWindows -eq $true)) {    
    Add-Type -AssemblyName System.Windows.Forms
    $caption = "Restart Computer?"
    $message = "Were Windows Updates ran that would require a restart?  If so please click YES to restart now and then start this script over.  Otherwise, please click NO to continue"
    $options = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $result = [System.Windows.Forms.MessageBox]::Show($message, $caption, $options, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        Restart-Computer -Force
    } else {
        Write-Host "Continuing script execution..."
    }
  }
}
function Step-oobeSetUserRegSettings {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeSetUserRegSettings -eq $true)) {
    # Load Default User Profile hive (ntuser.dat)
    Write-host "Setting default users settings ..."
    $DefaultUserProfilePath = "$env:SystemDrive\Users\Default\NTUSER.DAT"
    REG LOAD "HKU\Default" $DefaultUserProfilePath

    # Changes to Default User Registry

    Write-host -ForegroundColor DarkCyan "Show known file extensions" 
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

    Write-host -ForegroundColor DarkCyan "Change default Explorer view to This PC"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

    Write-host -ForegroundColor DarkCyan "Show User Folder shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f

    Write-host -ForegroundColor DarkCyan "Show This PC shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f

    Write-host -ForegroundColor DarkCyan "Show item checkboxes"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 1 /f

    Write-host -ForegroundColor DarkCyan "Disable Chat on Taskbar"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f

    #Write-Host -ForegroundColor DarkCyan "Removing OndDrive key"
    #REG DELETE "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f

    # Unload Default User Profile hive
    Write-Host -ForegroundColor DarkCyan "Unloading the default user registry hive"
    REG UNLOAD "HKU\Default"
    }
}
function Step-oobeSetDeviceRegSettings {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeSetDeviceRegSettings -eq $true)) {

    Write-host -ForegroundColor DarkCyan "disable firstlogon animation"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord

    Write-host -ForegroundColor DarkCyan "Autoset time zone"

        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location -Name Value -Value "Allow"
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name start -Value "3"

    Write-Host -ForegroundColor DarkCyan "Setting start menu items"

        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDocuments" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDownloads" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPictures" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderSettings" -Value 1 -Type DWord
    }
}function Step-oobeUpdateDefender {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeUpdateDefender -eq $true)) {
        Write-host -ForegroundColor DarkCyan "Updating Defender Signatures" 
        Update-MpSignature
    }
}
function Step-oobeCreateLocalUser {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeCreateLocalUser -eq $true)) {
        Write-Host -ForegroundColor Yellow 'Creating local user ssLocalAdmin'
        # Generate a random password of 16 characters
        function Generate-RandomPassword {
            $validCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
            $passwordLength = 64
            $random = New-Object System.Random
            $password = 1..$passwordLength | ForEach-Object { $validCharacters[$random.Next(0, $validCharacters.Length)] }
            return $password -join ''
        }
            $Username = "ssLocalAdmin"
            $Password = Generate-RandomPassword
            $NeverExpire = $true
            $UserParams = @{
                "Name"                  = $Username
                "Password"              = (ConvertTo-SecureString -AsPlainText $Password -Force)
                "UserMayNotChangePassword" = $true
                "PasswordNeverExpires"  = $NeverExpire
            }
            New-LocalUser @UserParams
            Write-Output "User '$Username' has been created with password: $Password"
            Add-LocalGroupMember -Group "Administrators" -Member $Username
    }
}
function Step-oobeExecutionPolicyRestricted {
    [CmdletBinding()]
    param ()
    if ($env:UserName -eq 'defaultuser0') {
        if ((Get-ExecutionPolicy) -ne 'Restricted') {
            Write-Host -ForegroundColor Cyan 'Set-ExecutionPolicy Restricted'
            Set-ExecutionPolicy Restricted -Force
        }
    }
}
function Step-oobeRestartComputer {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeRestartComputer -eq $true)) {
        Write-Host -ForegroundColor Cyan 'Build Complete!'
        Write-Warning 'Device will restart in 30 seconds.  Press Ctrl + C to cancel'
        Stop-Transcript
        Start-Sleep -Seconds 30
        Restart-Computer
    }
}
    

#endregion

# Execute functions
Step-oobeExecutionPolicy
Step-oobePackageManagement
Step-oobeTrustPSGallery
Step-oobeUpdateDrivers
Step-oobeUpdateWindows
Step-RestartConfirmation
Step-oobeSetDisplay
Step-oobeSetDateTime
Step-oobeRemoveAppxPackage
Step-oobeSetUserRegSettings
Step-oobeSetDeviceRegSettings
Step-oobeUpdateDefender
Step-oobeRegisterAutopilot
Step-oobeCreateLocalUser
Step-oobeExecutionPolicyRestricted
Step-oobeRestartComputer
#=================================================
