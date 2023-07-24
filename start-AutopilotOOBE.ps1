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
function Show-RestartConfirmation {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeUpdateWindowsr -eq $true)) {    
    Add-Type -AssemblyName System.Windows.Forms
    $caption = "Restart Computer"
    $message = "Were Windows Updates ran that would require a restart?  If so please restart now, and then start this script over"
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

    Write-host -ForegroundColor Yellow "Show known file extensions" 
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

    Write-host -ForegroundColor Yellow "Change default Explorer view to This PC"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

    Write-host -ForegroundColor Yellow "Show User Folder shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d 0 /f

    Write-host -ForegroundColor Yellow "Show This PC shortcut on desktop"
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
    REG ADD "HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f

    Write-host -ForegroundColor Yellow "Show item checkboxes"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 1 /f

    Write-host -ForegroundColor Yellow "Disable Chat on Taskbar"
    REG ADD "HKU\Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f

    # Unload Default User Profile hive
    REG UNLOAD "HKU\Default"
    }
}
function Step-oobeSetDeviceRegSettings {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeSetDeviceRegSettings -eq $true)) {

    Write-host -ForegroundColor Yellow "Set Silent Account Configuration"

        $HKLMregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'##Path to HKLM keys
        $DiskSizeregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\DiskSpaceCheckThresholdMB'##Path to max disk size key
        $TenantGUID = '8a3a7e59-4ea9-4259-ba0d-77cc328ca84f'

        if(!(Test-Path $HKLMregistryPath)){New-Item -Path $HKLMregistryPath -Force}
        if(!(Test-Path $DiskSizeregistryPath)){New-Item -Path $DiskSizeregistryPath -Force}

        New-ItemProperty -Path $HKLMregistryPath -Name 'SilentAccountConfig' -Value '1' -PropertyType DWORD -Force | Out-Null ##Enable silent account configuration
        New-ItemProperty -Path $DiskSizeregistryPath -Name $TenantGUID -Value '102400' -PropertyType DWORD -Force | Out-Null ##Set max OneDrive threshold before prompting

    Write-host -ForegroundColor Yellow "disable firstlogon animation"

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "EnableFirstLogonAnimation" -Value 0 -Type DWord

    Write-host -ForegroundColor Yellow "Autoset time zone"

        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location -Name Value -Value "Allow"
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name start -Value "3"
    }
}function Step-oobeUpdateDefender {
    [CmdletBinding()]
    param ()
    if (($env:UserName -eq 'defaultuser0') -and ($Global:oobeCloud.oobeUpdateDefender -eq $true)) {

        Write-host -ForegroundColor Yellow "Updating Defender Signatures" 
        try {
            Update-MpSignature
            exit 0
        }
        catch {
            exit 0 <#Do this if a terminating exception happens#>
        }
    }
}


#endregion

# Execute functions
Step-oobeExecutionPolicy
Step-oobePackageManagement
Step-oobeTrustPSGallery
Step-oobeSetDisplay
Step-oobeSetDateTime
Step-oobeRemoveAppxPackage
Step-oobeUpdateDrivers
Step-oobeUpdateWindows
Show-RestartConfirmation
Step-oobeSetUserRegSettings
Step-oobeSetDeviceRegSettings
Step-oobeUpdateDefender
Step-oobeRegisterAutopilot
#=================================================
