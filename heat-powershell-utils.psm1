#ps1_sysnative

# Copyright 2014 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

$rebotCode = 1001
$reexecuteCode = 1002
$rebootAndReexecuteCode = 1003


function Log {
    param(
        $message
        )

    Write-Host $message
}

function Is-FeatureAvailable {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    $featureInstallState = (Get-WindowsFeature -Name $FeatureName).InstallState
    $isAvailable = ($featureInstallState -eq "Available") -or `
                     ($featureInstallState -eq "Removed")

    return $isAvailable
}

function Is-FeatureInstalled {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )

    $installState = (Get-WindowsFeature -Name $FeatureName).InstallState

    $isInstalled = ($installState -eq "Installed") `
                 -or ($installState -eq "InstallPending" )

    return $isInstalled
}
function Install-WindowsFeatures {
     param(
        [Parameter(Mandatory=$true)]
        [array]$Features
    )

    $installedFeatures = 0
    $rebootNeeded = $false
    foreach ($feature in $Features) {
        $isAvailable = Is-FeatureAvailable $feature
        if ($isAvailable -eq $true) {
            $res = Install-WindowsFeature -Name $feature
            if ($res.RestartNeeded -eq 'Yes') {
                $rebootNeeded = $true
            }
        }
        $isInstalled = Is-FeatureInstalled $feature
        if ($isInstalled -eq $true) {
            $installedFeatures = $installedFeatures + 1
        } else {
            Log "Install failed for feature $feature"
        }
    }

    return @{"InstalledFeatures" = $installedFeatures;
             "Reboot" = $rebootNeeded }
}

function ExitFrom-Script {
    param(
        [int]$ExitCode
    )
    exit $ExitCode
}

function ExecuteWith-RetryPSCommand {
    param(
        [ScriptBlock]$Command,
        [int]$MaxRetryCount=3,
        [int]$RetryInterval=0,
        [array]$ArgumentList=@()
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $retryCount = 0

    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $Command `
                     -ArgumentList $ArgumentList
            return $res
        } catch [System.Exception] {
            if ($retryCount -ge $MaxRetryCount) {
                $ErrorActionPreference = $currentErrorActionPreference
                throw $_.Exception
            } else {
                Start-Sleep $RetryInterval
            }
            $retryCount++
        }
    }

    $ErrorActionPreference = $currentErrorActionPreference
}

function Copy-FilesLocal {
    param()
    New-PSDrive -Name $smbDrive -Root $smbShare -PSProvider FileSystem
    if (!(Test-Path "$copyLocal\$isoName")){
        Copy-Item "$temp\$isoName" $copyLocal
    }
}

try {
    Export-ModuleMember -Function * -ErrorAction SilentlyContinue
} catch {
    Log "Outside of the module. This file has been dot sourced or included as text."
}

