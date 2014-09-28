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

$moduleName = "heat-powershell-utils"
$modulePath = Resolve-Path -Path "..\heat-powershell-utils.psm1"

Remove-Module -Name $moduleName -ErrorAction SilentlyContinue
Import-Module -Name $modulePath -DisableNameChecking


InModuleScope $moduleName {
    # HELPER FUNCTIONS

    function Compare-HashTables ($tab1, $tab2) {
        if ($tab1.Count -ne $tab2.Count) {
            return $false
        }
        foreach ($i in $tab1.Keys) {
            if (($tab2.ContainsKey($i) -eq $false) `
                -or ($tab1[$i] -ne $tab2[$i])) {
                return $false
            }
        }
        return $true
    }

    # DESCRIBE BLOCKS

    Describe "Log-HeatMessage" {
        Context "Successful logging" {
            $fakeMsg = 'Fake_Message'
            Mock Write-Host { return $fakeMsg } -Verifiable

            $res = Log-HeatMessage $fakeMsg

            It "should log the message" {
                $res | Should Be $fakeMsg
            }
            It "should call write-host" {
                Assert-MockCalled Write-Host `
                    -ParameterFilter { $Object -eq $fakeMsg } `
                    -Exactly 1
            }
        }
    }

    Describe "ExecuteWith-Retry" {
        $retryCount = 10
        $retryInterval = 3
        $params = @('Arg1', 'Arg2')

        Context "Null command is given" {
            Mock Invoke-Command { Throw } -Verifiable
            Mock Start-Sleep { return 0 } -Verifiable
            Mock Write-Error { return 0 } -Verifiable
            $cmd = $null

            It "should throw" {
                { ExecuteWith-Retry -Command $cmd `
                                    -MaxRetryCount $retryCount `
                                    -RetryInterval $retryInterval `
                                    -Arguments $params } | Should Throw
            }
            It "should call Invoke-Command" {
                Assert-MockCalled Invoke-Command -Exactly 0
            }
            It "should call Start-Sleep" {
                Assert-MockCalled Start-Sleep `
                    -Exactly $retryCount `
                    -ParameterFilter { $Seconds -eq $retryInterval }
            }
            It "should call Write-Error" {
                Assert-MockCalled Write-Error -Exactly $retryCount
            }
        }

        Context "Command is valid" {
            Mock Invoke-Command { return 0 } -Verifiable
            Mock Start-Sleep { return 0 } -Verifiable
            Mock Write-Error { return 0 } -Verifiable
            $cmd = { Get-ChildItem }

            It "should not throw" {
                { ExecuteWith-Retry -Command $cmd `
                                    -MaxRetryCount $retryCount `
                                    -RetryInterval $retryInterval `
                                    -Arguments $params } | Should Not Throw
            }
            It "should call Invoke-Command" {
                Assert-MockCalled Invoke-Command `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($cmd.ToString().CompareTo($ScriptBlock.ToString()) `
                            -eq 0) -and
                        (((Compare-Object `
                            $params $ArgumentList).InputObject).Length -eq 0)
                    }
            }
            It "should not call Start-Sleep" {
                Assert-MockCalled Start-Sleep `
                    -Exactly 0 `
                    -ParameterFilter { $Seconds -eq $retryInterval }
            }
            It "should not call Write-Error" {
                Assert-MockCalled Write-Error -Exactly 0
            }
        }

        Context "Command is not valid" {
            Mock Invoke-Command { Throw } -Verifiable
            Mock Start-Sleep { return 0 } -Verifiable
            Mock Write-Error { return 0 } -Verifiable
            $cmd = { wrong_command }

            It "should throw" {
                { ExecuteWith-Retry -Command $cmd `
                                    -MaxRetryCount $retryCount `
                                    -RetryInterval $retryInterval `
                                    -Arguments $params } | Should Throw
            }
            It "should call Invoke-Command four times" {
                Assert-MockCalled Invoke-Command `
                    -Exactly ($retryCount + 1) `
                    -ParameterFilter {
                        ($cmd.ToString().CompareTo($ScriptBlock.ToString()) `
                            -eq 0) -and
                        (((Compare-Object `
                            $params $ArgumentList).InputObject).Length -eq 0)
                    }
            }
            It "should call Start-Sleep" {
                Assert-MockCalled Start-Sleep `
                    -Exactly $retryCount `
                    -ParameterFilter { $Seconds -eq $retryInterval }
            }
            It "should call Write-Error" {
                Assert-MockCalled Write-Error -Exactly $retryCount
            }
        }

        Context "Negative RetryInterval parameter" {
            Mock Invoke-Command { Throw } -Verifiable
            Mock Start-Sleep { Throw } -Verifiable
            Mock Write-Error { return 0 } -Verifiable
            $cmd = { wrong_cmd }
            $retryInterval = -1

            It "should throw" {
                { ExecuteWith-Retry -Command $cmd `
                                    -MaxRetryCount $retryCount `
                                    -RetryInterval $retryInterval `
                                    -Arguments $params } | Should Throw
            }
            It "should call Invoke-Command" {
                Assert-MockCalled Invoke-Command `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($cmd.ToString().CompareTo($ScriptBlock.ToString()) `
                            -eq 0) -and
                        (((Compare-Object `
                            $params $ArgumentList).InputObject).Length -eq 0)
                    }
            }
            It "should call Write-Error" {
                Assert-MockCalled Write-Error -Exactly 1
            }
            It "should throw at Start-Sleep" {
                Assert-MockCalled Start-Sleep 0
            }
        }
    }

    Describe "Execute-ExternalCommand" {
        $params = @('Arg1', 'Arg2')
        $errMsg = "Fake_Message"

        Context "Null external command is given" {
            Mock Invoke-Command { Throw } -Verifiable
            Mock Get-LastExitCode { return 0 } -Verifiable
            $cmd = $null

            It "should throw" {
                { Execute-ExternalCommand -Command $cmd `
                                          -Arguments $params `
                                          -ErrorMessage $errMsg } `
                | Should Throw
            }
            It "should call Invoke-Command" {
                Assert-MockCalled Invoke-Command -Exactly 0
            }
            It "should not check for last exit code" {
                Assert-MockCalled Get-LastExitCode -Exactly 0
            }
        }

        Context "External command generates error" {
            Mock Invoke-Command { return 0 } -Verifiable
            Mock Get-LastExitCode { return 1 } -Verifiable
            $cmd = { fake_external_command }

            It "should throw" {
                { Execute-ExternalCommand -Command $cmd `
                                          -Arguments $params `
                                          -ErrorMessage $errMsg } `
                | Should Throw
            }
            It "should call Invoke-Command" {
                Assert-MockCalled Invoke-Command `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($cmd.ToString().CompareTo($ScriptBlock.ToString()) `
                            -eq 0) -and
                        (((Compare-Object `
                            $params $ArgumentList).InputObject).Length -eq 0)
                    }
            }
            It "should not check for last exit code" {
                Assert-MockCalled Get-LastExitCode -Exactly 1
            }
        }

        Context "External command does not generates error" {
            Mock Invoke-Command { return 0 } -Verifiable
            Mock Get-LastExitCode { return 0 } -Verifiable
            $cmd = { fake_external_command }

            It "should not throw" {
                { Execute-ExternalCommand -Command $cmd `
                                          -Arguments $params `
                                          -ErrorMessage $errMsg } `
                | Should Not Throw
            }
            It "should call Invoke-Command" {
                Assert-MockCalled Invoke-Command `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($cmd.ToString().CompareTo($ScriptBlock.ToString()) `
                            -eq 0) -and
                        (((Compare-Object `
                            $params $ArgumentList).InputObject).Length -eq 0)
                    }
            }
            It "should not check for last exit code" {
                Assert-MockCalled Get-LastExitCode -Exactly 1
            }
        }
    }

    Describe "Is-WindowsServer2008R2" {
        Mock Get-WmiObject { return @{ "Version" = $ver } } -Verifiable

        Context "Server is 2008 R2" {
            $ver = "6.1"
            $res = Is-WindowsServer2008R2

            It "should result true" {
                $res | Should Be $true
            }
            It "should call Get-WmiObject" {
                Assert-MockCalled Get-WmiObject `
                    -Exactly 1 `
                    -ParameterFilter { $Class -eq "Win32_OperatingSystem" }
            }
        }

        Context "Server is not 2008 R2" {
            $ver = "6.0"
            $res = Is-WindowsServer2008R2

            It "should result true" {
                $res | Should Be $false
            }
            It "should call Get-WmiObject" {
                Assert-MockCalled Get-WmiObject `
                    -Exactly 1 `
                    -ParameterFilter { $Class -eq "Win32_OperatingSystem" }
            }
        }
    }

    Describe "Install-WindowsFeatures" {
        Mock Import-Module { return 0 } -Verifiable
        Mock Is-WindowsServer2008R2 { return $is2008R2 } -Verifiable
        Mock ExecuteWith-Retry { return $fakeState } -Verifiable
        Mock ExitFrom-Script { return 0 } -Verifiable

        $fakeFeatures = @("Feature1", "Feature2", "Feature3")
        $fakeRebootCode = 1234
        $addCmd = { Add-WindowsFeature -Name $feature -ErrorAction Stop }
        $instCmd = { Install-WindowsFeature -Name $feature -ErrorAction Stop }

        Context "Features are installed for win 2008 R2 with reboot needed" {
            $is2008R2 = $true
            $fakeState = @{ "Success" = $true;
                            "RestartNeeded" = 'Yes' }

            Install-WindowsFeatures $fakeFeatures $fakeRebootCode

            It "should import ServerManager module" {
                Assert-MockCalled Import-Module `
                    -Exactly 1 `
                    -ParameterFilter { $Name -eq "ServerManager" }
            }
            It "should check for windows server 2008 R2" {
                Assert-MockCalled Is-WindowsServer2008R2 `
                    -Exactly 4
            }
            It "should install windows features" {
                Assert-MockCalled ExecuteWith-Retry `
                    -Exactly 3 `
                    -ParameterFilter {
                        ($MaxRetryCount -eq 13) -and
                        ($RetryInterval -eq 2) -and
                        (($Command.ToString() -replace '\s+', '').CompareTo(
                         ($addCmd.ToString() -replace '\s+', '')) `
                            -eq 0)
                    }
            }
            It "should make post installation reboot" {
                Assert-MockCalled ExitFrom-Script `
                    -Exactly 1 `
                    -ParameterFilter { $ExitCode -eq $fakeRebootCode }
            }
        }

        Context "Features are installed for non win 08 R2 without restart" {
            $is2008R2 = $false
            $fakeState = @{ "Success" = $true;
                            "RestartNeeded" = 'No' }

            Install-WindowsFeatures $fakeFeatures $fakeRebootCode

            It "should not import ServerManager module" {
                Assert-MockCalled Import-Module -Exactly 0
            }
            It "should install windows features" {
                Assert-MockCalled ExecuteWith-Retry `
                    -Exactly 3 `
                    -ParameterFilter {
                        ($MaxRetryCount -eq 13) -and
                        ($RetryInterval -eq 2) -and
                        (($Command.ToString() -replace '\s+', '').CompareTo(
                         ($instCmd.ToString() -replace '\s+', '')) `
                            -eq 0)
                    }
            }
            It "should not reboot" {
                Assert-MockCalled ExitFrom-Script -Exactly 0
            }
        }

        Context "Failed feature install" {
            $is2008R2 = $false
            $fakeState = @{ "Success" = $false;
                            "RestartNeeded" = 'No' }
            $fakeFeature = @("Feature")

            It "should throw" {
                { Install-WindowsFeatures $fakeFeature $fakeRebootCode } | `
                    Should throw
            }
            It "should not import ServerManager module" {
                Assert-MockCalled Import-Module -Exactly 0
            }
            It "should fail install windows features" {
                Assert-MockCalled ExecuteWith-Retry `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($MaxRetryCount -eq 13) -and
                        ($RetryInterval -eq 2) -and
                        (($Command.ToString() -replace '\s+', '').CompareTo(
                         ($instCmd.ToString() -replace '\s+', '')) `
                            -eq 0)
                    }
            }
            It "should not reboot" {
                Assert-MockCalled ExitFrom-Script -Exactly 0
            }
        }
    }

    Describe "Copy-FileToLocal" {
        Mock Copy-Item { } -Verifiable
        Mock Log-HeatMessage { } -Verifiable
        $fakeFileName = 'Fake_File_Name'
        Mock Split-Path { return $fakeFileName } -Verifiable
        $fakeLocalPath = "Fake_Local_Path"
        Mock Join-Path { return $fakeLocalPath } -Verifiable

        $fakeUNCPath = "Fake_UNC_Path"
        $tempLocation = $env:TEMP

        Context "File is copied locally" {
            $res = Copy-FileToLocal $fakeUNCPath

            It "should return local file path" {
                $res | Should Be $fakeLocalPath
            }
            It "should get the file name" {
                Assert-MockCalled Split-Path `
                    -Exactly 1 `
                    -ParameterFilter { $Path -eq $fakeUNCPath }
            }
            It "should form the local file path" {
                Assert-MockCalled Join-Path `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Path -eq $tempLocation) -and
                        ($ChildPath -eq $fakeFileName)
                    }
            }
            It "should copy file to local computer" {
                Assert-MockCalled Copy-Item `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Path -eq $fakeUNCPath) -and
                        ($Destination -eq $fakeLocalPath)
                    }
            }
            It "should log a message with local file path" {
                $msg = "Local file path: " + $fakeLocalPath
                Assert-MockCalled Log-HeatMessage `
                    -Exactly 1 `
                    -ParameterFilter { $Message -eq $msg }
            }
        }
    }

    Describe "Unzip-File" {
        $fakeDestNS = New-Object PSObject
        $fakeDestNS | Add-Member ScriptMethod "CopyHere" { return 0 }
        $fakeDestNS | Add-Member ScriptMethod "Items" { return 0 }

        $fakeShellApp = New-Object PSObject
        $fakeShellApp | `
            Add-Member ScriptMethod "NameSpace" { return $fakeDestNS }

        Mock New-Object { return $fakeShellApp } -Verifiable

        $fakeZipPath = "Fake_Zip_Path"
        $fakeDestPath = "Fake_Destination_Path"

        Context "File is unzipped" {
            Unzip-File $fakeZipPath $fakeDestPath

            It "should create a shell application" {
                Assert-MockCalled New-Object `
                    -Exactly 1 `
                    -ParameterFilter { $ComObject -eq "Shell.Application" }
            }
        }
    }

    Describe "Download-File" {
        Mock New-Object { return 0 } -Verifiable
        Mock ExecuteWith-Retry { return 0 } -Verifiable

        $fakeDownloadLink = "Download_Link"
        $fakeDestinationFile = "Destionation_File"

        Context "File is downloaded" {
            $downloadCommand = {
                $webclient.DownloadFile($DownloadLink, $DestinationFile)
            }
            Download-File $fakeDownloadLink $fakeDestinationFile

            It "should create webclient object" {
                Assert-MockCalled New-Object `
                    -Exactly 1 `
                    -ParameterFilter { $TypeName -eq "System.Net.WebClient" }
            }
            It "should download the file" {
                Assert-MockCalled ExecuteWith-Retry `
                    -Exactly 1 `
                    -ParameterFilter {
                        (($Command.ToString() -replace '\s+', '').CompareTo(
                         ($downloadCommand.ToString() -replace '\s+', '')) `
                            -eq 0) -and
                        ($MaxRetryCount -eq 13) -and
                        ($RetryInterval -eq 2)
                    }
            }
        }
    }

    Describe "Get-FileSHA1Hash" {
        $fakeFile = New-Object PSObject
        $fakeFile | Add-Member ScriptMethod "Close" { return 0 }
        Mock Open-FileForRead { return $fakeFile } -Verifiable

        $fakeSham = New-Object PSObject
        $fakeBytesHash = @(97, 95, 100, 98, 99)
        $fakeSham | Add-Member ScriptMethod "ComputeHash" `
                                                    { return $fakeBytesHash }
        $fakeSham | Add-Member ScriptMethod "Clear" { return 0 }
        Mock New-Object { return $fakeSham } -ParameterFilter {
            $TypeName -eq 'System.Security.Cryptography.SHA1Managed'
        }

        $fakeFullPath = 'Fake_Full_Path'
        Mock Resolve-Path { return $fakeFullPath } -Verifiable

        $fakeStrHash = "Fake_String_Hash"
        $fakeHashSb = New-Object PSObject
        $fakeHashSb | Add-Member ScriptMethod "AppendFormat" { return 0 }
        $fakeHashSb | Add-Member -MemberType ScriptMethod `
                                 -Name "ToString" `
                                 -Value { return $fakeStrHash } `
                                 -Force

        Mock New-Object { return $fakeHashSb } -ParameterFilter {
            $TypeName -eq 'System.Text.StringBuilder'
        }

        Context "Different algorithm than SHA1 is passed" {
            $algorithm = "MD5"
            $fakeFilePath = "Some_Path"

            It "should throw" {
                { Get-FileSHA1Hash $fakeFilePath $algorithm } | Should throw
            }
            It "should not create SHA1Managed object" {
                Assert-MockCalled New-Object `
                    -Exactly 0 `
                    -ParameterFilter {
                        $TypeName `
                            -eq 'System.Security.Cryptography.SHA1Managed'
                    }
            }
            It "should not compute full path" {
                Assert-MockCalled Resolve-Path -Exactly 0
            }
            It "should open file for read" {
                Assert-MockCalled Open-FileForRead -Exactly 0
            }
            It "should not create StringBuilder object" {
                Assert-MockCalled New-Object `
                    -Exactly 0 `
                    -ParameterFilter {
                        $TypeName -eq 'System.Text.StringBuilder'
                    }
            }
        }

        Context "SHA1 hash is computed" {
            $fakeFilePath = "Fake_Path"

            $res = Get-FileSHA1Hash $fakeFilePath

            It "should return SHA1 hash" {
                $res.Hash | Should Be $fakeStrHash
            }
            It "should not create SHA1Managed object" {
                Assert-MockCalled New-Object `
                    -Exactly 1 `
                    -ParameterFilter {
                        $TypeName `
                            -eq 'System.Security.Cryptography.SHA1Managed'
                    }
            }
            It "should compute full path" {
                Assert-MockCalled Resolve-Path `
                    -Exactly 1 `
                    -ParameterFilter { $Path -eq $fakeFilePath }
            }
            It "should open file for read" {
                Assert-MockCalled Open-FileForRead `
                    -Exactly 1 `
                    -ParameterFilter { $FilePath -eq $fakeFullPath }
            }
            It "should create StringBuilder object" {
                Assert-MockCalled New-Object `
                    -Exactly 1 `
                    -ParameterFilter {
                        $TypeName -eq 'System.Text.StringBuilder'
                    }
            }
        }
    }

    Describe "Check-FileIntegrityWithSHA1" {
        Mock Get-PSMajorVersion { return $psVer } -Verifiable
        Mock Get-FileSHA1Hash { return @{'Hash' = $fakeHash} } -Verifiable
        Mock Get-FileHash { return @{'Hash' = $fakeHash} } -Verifiable

        $fakeFile = "some_file_path"
        $fakeExpectedHash = "expected_hash"

        Context "PS version less than 4" {
            $psVer = 3
            $fakeHash = "expected_hash"

            Check-FileIntegrityWithSHA1 $fakeFile $fakeExpectedHash

            It "should check for PS version" {
                Assert-MockCalled Get-PSMajorVersion -Exactly 1
            }
            It "should compute SHA1 hash" {
                Assert-MockCalled Get-FileSHA1Hash `
                    -Exactly 1 `
                    -ParameterFilter { $Path -eq $fakeFile }
            }
        }

        Context "PS version 4 or more" {
            $psVer = 4
            $fakeHash = "expected_hash"

            Check-FileIntegrityWithSHA1 $fakeFile $fakeExpectedHash

            It "should check for PS version" {
                Assert-MockCalled Get-PSMajorVersion -Exactly 1
            }
            It "should compute SHA1 hash" {
                Assert-MockCalled Get-FileHash `
                    -Exactly 1 `
                    -ParameterFilter { $Path -eq $fakeFile }
            }
        }

        Context "Hash doesn't match expected hash" {
            $psVer = 4
            $fakeHash = "not_expected_hash"

            It "should throw" {
                { Check-FileIntegrityWithSHA1 $fakeFile $fakeExpectedHash } | `
                    Should throw
            }
            It "should check for PS version" {
                Assert-MockCalled Get-PSMajorVersion -Exactly 1
            }
            It "should compute SHA1 hash" {
                Assert-MockCalled Get-FileHash `
                    -Exactly 1 `
                    -ParameterFilter { $Path -eq $fakeFile }
            }
        }
    }

    Describe "Install-Program" {
        Mock Download-File { } -Verifiable
        Mock Check-FileIntegrityWithSHA1 { } -Verifiable
        Mock Execute-Process { return @{'ExitCode'=$exitCode} } -Verifiable
        Mock Remove-Item { } -Verifiable

        $fakeDownloadLink = "Fake_Download_Link"
        $fakeDestFile = "Fake_Destionation_File"
        $fakeExpectedHash = "Fake_Expected_SHA1_Hash"
        $fakeErrMsg = "Fake_Error_Message"

        Context "Program is installed and arguments are passed" {
            $exitCode = 0
            $fakeArgs = @('Arg1', 'Arg2')

            Install-Program -DownloadLink $fakeDownloadLink `
                            -DestinationFile $fakeDestFile `
                            -ExpectedSHA1Hash $fakeExpectedHash `
                            -ErrorMessage $fakeErrMsg `
                            -Arguments $fakeArgs

            It "should download the file" {
                Assert-MockCalled Download-File `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($DownloadLink -eq $fakeDownloadLink) -and
                        ($DestinationFile -eq $fakeDestFile)
                    }
            }
            It "should check file integrity" {
                Assert-MockCalled Check-FileIntegrityWithSHA1 `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($File -eq $fakeDestFile) -and
                        ($ExpectedSHA1Hash -eq $fakeExpectedHash)
                    }
            }
            It "should execute process" {
                Assert-MockCalled Execute-Process `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($DestinationFile -eq $fakeDestFile) -and
                        (((Compare-Object `
                            $Arguments $fakeArgs).InputObject).Length -eq 0)
                    }
            }
            It "should remove temporary file" {
                Assert-MockCalled Remove-Item `
                    -Exactly 1 `
                    -ParameterFilter { ($Path -eq $fakeDestFile) }
            }
        }

        Context "Program is installed and no arguments are passed" {
            $exitCode = 0

            Install-Program -DownloadLink $fakeDownloadLink `
                            -DestinationFile $fakeDestFile `
                            -ExpectedSHA1Hash $fakeExpectedHash `
                            -ErrorMessage $fakeErrMsg

            It "should download the file" {
                Assert-MockCalled Download-File `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($DownloadLink -eq $fakeDownloadLink) -and
                        ($DestinationFile -eq $fakeDestFile)
                    }
            }
            It "should check file integrity" {
                Assert-MockCalled Check-FileIntegrityWithSHA1 `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($File -eq $fakeDestFile) -and
                        ($ExpectedSHA1Hash -eq $fakeExpectedHash)
                    }
            }
            It "should execute process" {
                Assert-MockCalled Execute-Process `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($DestinationFile -eq $fakeDestFile) -and
                        ($Arguments -eq $null)
                    }
            }
            It "should remove temporary file" {
                Assert-MockCalled Remove-Item `
                    -Exactly 1 `
                    -ParameterFilter { ($Path -eq $fakeDestFile) }
            }
        }

        Context "Program is not installed" {
            $exitCode = 1

            It "should throw" {
                { Install-Program -DownloadLink $fakeDownloadLink `
                                  -DestinationFile $fakeDestFile `
                                  -ExpectedSHA1Hash $fakeExpectedHash `
                                  -ErrorMessage $fakeErrMsg } | `
                Should throw
            }

            It "should download the file" {
                Assert-MockCalled Download-File `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($DownloadLink -eq $fakeDownloadLink) -and
                        ($DestinationFile -eq $fakeDestFile)
                    }
            }
            It "should check file integrity" {
                Assert-MockCalled Check-FileIntegrityWithSHA1 `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($File -eq $fakeDestFile) -and
                        ($ExpectedSHA1Hash -eq $fakeExpectedHash)
                    }
            }
            It "should execute process" {
                Assert-MockCalled Execute-Process `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($DestinationFile -eq $fakeDestFile) -and
                        ($Arguments -eq $null)
                    }
            }
            It "should remove temporary file" {
                Assert-MockCalled Remove-Item -Exactly 0
            }
        }
    }

    Describe "Set-IniFileValue" {
        Mock Add-Type { return 0 } -Verifiable
        Mock Write-PrivateProfileString { return $retValue } -Verifiable
        Mock Get-LastError { return $lastError } -Verifiable

        $fakeKey = "Fake_Key"
        $fakeSection = "Fake_Section"
        $fakeValue = "Fake_Value"
        $fakePath = "Fake_Path"

        Context "Ini file value is set" {
            $retValue = $true
            $lastError = 0

            Set-IniFileValue $fakeKey $fakeSection $fakeValue $fakePath

            It "should load Win32IniApi" {
                Assert-MockCalled Add-Type `
                    -Exactly 1 `
                    -ParameterFilter { $Language -eq "CSharp" }
            }
            It "should write the value in the ini file" {
                Assert-MockCalled Write-PrivateProfileString `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Section -eq $fakeSection) -and
                        ($Key -eq $fakeKey) -and
                        ($Value -eq $fakeValue) -and
                        ($Path -eq $fakePath)
                    }
            }
            It "should get last error" {
                Assert-MockCalled Get-LastError -Exactly 1
            }
        }

        Context "Failed to set ini file value" {
            $retValue = $false
            $lastError = 1

            It "should throw" {
                { Set-IniFileValue $fakeKey `
                                   $fakeSection `
                                   $fakeValue `
                                   $fakePath } | Should throw
            }
            It "should load Win32IniApi" {
                Assert-MockCalled Add-Type `
                    -Exactly 1 `
                    -ParameterFilter { $Language -eq "CSharp" }
            }
            It "should write the value in the ini file" {
                Assert-MockCalled Write-PrivateProfileString `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Section -eq $fakeSection) -and
                        ($Key -eq $fakeKey) -and
                        ($Value -eq $fakeValue) -and
                        ($Path -eq $fakePath)
                    }
            }
            It "should get last error" {
                Assert-MockCalled Get-LastError -Exactly 1
            }
        }
    }

    Describe "LogTo-File" {
        $fakeCurrentDate = "Date"
        Mock Get-Date { return $fakeCurrentDate } -Verifiable
        Mock Add-Content { return 0 } -Verifiable

        $fakeLogMsg = "Fake_Log_Message"
        $fakeLogFile = "Fake_Log_File"
        $fakeTopic = "Fake_Topic"

        Context "Should log message to file" {
            $fakeFullMsg = "$fakeCurrentDate | $fakeTopic | $fakeLogMsg"

            LogTo-File $fakeLogMsg $fakeLogFile $fakeTopic

            It "should get current date" {
                Assert-MockCalled Get-Date -Exactly 1
            }
            It "should add content to file" {
                Assert-MockCalled Add-Content `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Path -eq $fakeLogFile) -and
                        ($Value -eq $fakeFullMsg)
                    }
            }
        }
    }

    Describe "Open-Port" {
        Mock Execute-ExternalCommand { return 0 } -Verifiable

        $netshCmd = {
            netsh.exe advfirewall firewall add rule `
            name=$Name dir=in action=allow protocol=$Protocol localport=$Port
        }
        $errMsg = "Failed to add firewall rule"
        $fakePort = "Fake_Port"
        $fakeProtocol = "Fake_Protocol"
        $fakeName = "Fake_Name"

        Context "Port is opened" {
            Open-Port $fakePort $fakeProtocol $fakeName

            It "should open the port" {
                Assert-MockCalled Execute-ExternalCommand `
                    -Exactly 1 `
                    -ParameterFilter {
                        (($Command.ToString() -replace '\s+', '').CompareTo(
                            ($netshCmd.ToString() -replace '\s+', '')) -eq 0) `
                        -and
                        ($ErrorMessage -eq $errMsg)
                    }
            }
        }
    }

    Describe "Add-WindowsUser" {
        Mock Execute-ExternalCommand { return 0 } -Verifiable

        $netshCmd = { NET.EXE USER $Username $Password '/ADD' }
        $errMsg = "Failed to create new user"
        $fakeUserName = "Fake_Username"
        $fakePassword = "Fake_Password"

        Context "Windows user is created" {
            Add-WindowsUser $fakeUserName $fakePassword

            It "should create the windows user" {
                Assert-MockCalled Execute-ExternalCommand `
                    -Exactly 1 `
                    -ParameterFilter {
                        (($Command.ToString() -replace '\s+', '').CompareTo(
                            ($netshCmd.ToString() -replace '\s+', '')) -eq 0) `
                        -and
                        ($ErrorMessage -eq $errMsg)
                    }
            }
        }
    }

    Describe "Invoke-RestMethodWrapper" {
        Context "Request without empty body is sent" {
            $fakeReq = New-Object PSObject
            $fakeReq | Add-Member NoteProperty "Method" 0
            $fakeReq | Add-Member NoteProperty "Headers" @{}
            $fakeReq | Add-Member NoteProperty "ContentLength" 0

            $fakeWriteStream = New-Object PSObject
            $fakeWriteStream | Add-Member ScriptMethod "Write" { return 0 }
            $fakeReq | Add-Member ScriptMethod "GetRequestStream" `
                                                        { return $fakeWriteStream }

            $fakeResponseStream = New-Object PSObject
            $fakeResponseStream | Add-Member ScriptMethod "GetResponseStream" `
                                                        { return 0 }
            $fakeReq | Add-Member ScriptMethod "GetResponse" `
                                                    { return $fakeResponseStream }

            Mock Create-WebRequest { return $fakeReq } -Verifiable

            $fakeEnc = New-Object PSObject
            $fakeEnc | Add-Member ScriptMethod "GetBytes" { return "" }
            Mock Get-Encoding { return $fakeEnc } -Verifiable

            $fakeReadStream = New-Object PSObject
            $fakeReadStream | Add-Member ScriptMethod "ReadToEnd" { return 0 }
            Mock New-Object { return $fakeReadStream } -Verifiable `
                -ParameterFilter { $TypeName -eq 'System.IO.StreamReader' }

            $fakeUri = "Fake_Uri"
            $fakeHeaders = @{ 'Header1' = 'Header1'; 'Header2' = 'Header2' }
            $fakeBody = "Fake_Body"
            $fakeMethod = 'POST'

            Invoke-RestMethodWrapper `
                $fakeUri $fakeBody $fakeHeaders $fakeMethod

            It "should create web request" {
                Assert-MockCalled Create-WebRequest `
                    -Exactly 1 `
                    -ParameterFilter { $Uri -eq $fakeUri }
            }
            It "should create UTF-8 encoding" {
                Assert-MockCalled Get-Encoding `
                    -Exactly 1 `
                    -ParameterFilter { $CodePage -eq "UTF-8" }
            }
            It "should create streamreader" {
                Assert-MockCalled New-Object `
                    -Exactly 1 `
                    -ParameterFilter { $TypeName -eq 'System.IO.StreamReader' }
            }
        }

        Context "Request with empty body is sent" {
            $fakeReq = New-Object PSObject
            $fakeReq | Add-Member NoteProperty "Method" 0
            $fakeReq | Add-Member NoteProperty "Headers" @{}
            $fakeReq | Add-Member NoteProperty "ContentLength" 0

            $fakeWriteStream = New-Object PSObject
            $fakeWriteStream | Add-Member ScriptMethod "Write" { return 0 }
            $fakeReq | Add-Member ScriptMethod "GetRequestStream" `
                                                    { return $fakeWriteStream }

            $fakeResponseStream = New-Object PSObject
            $fakeResponseStream | Add-Member ScriptMethod "GetResponseStream" `
                                                        { return 0 }
            $fakeReq | Add-Member ScriptMethod "GetResponse" `
                                                { return $fakeResponseStream }

            Mock Create-WebRequest { return $fakeReq } -Verifiable

            $fakeEnc = New-Object PSObject
            $fakeEnc | Add-Member ScriptMethod "GetBytes" { return "" }
            Mock Get-Encoding { return $fakeEnc } -Verifiable

            $fakeReadStream = New-Object PSObject
            $fakeReadStream | Add-Member ScriptMethod "ReadToEnd" { return 0 }
            Mock New-Object { return $fakeReadStream } -Verifiable `
                -ParameterFilter { $TypeName -eq 'System.IO.StreamReader' }

            $fakeUri = "Fake_Uri"
            $fakeHeaders = @{ 'Header1' = 'Header1'; 'Header2' = 'Header2' }
            $fakeBody = ""
            $fakeMethod = 'GET'

            Invoke-RestMethodWrapper `
                $fakeUri $fakeBody $fakeHeaders $fakeMethod

            It "should create web request" {
                Assert-MockCalled Create-WebRequest `
                    -Exactly 1 `
                    -ParameterFilter { $Uri -eq $fakeUri }
            }
            It "should not create UTF-8 encoding" {
                Assert-MockCalled Get-Encoding -Exactly 0
            }
            It "should create streamreader" {
                Assert-MockCalled New-Object `
                    -Exactly 1 `
                    -ParameterFilter { $TypeName -eq 'System.IO.StreamReader' }
            }
        }
    }

    Describe "Invoke-HeatRestMethod" {
        Mock Get-PSMajorVersion { return $psVer } -Verifiable
        Mock Invoke-RestMethodWrapper { return 0 } -Verifiable
        Mock Invoke-RestMethod { return 0 } -Verifiable

        $fakeEndPoint =  "http://Fake_Endpoint"
        $fakeJSONMsg = "Fake_Message"
        $fakeHeaders = @{ 'Header1' = 'Header1'; 'Header2' = 'Header2' }

        Context "Powershell version less than 4" {
            $psVer = 3

            Invoke-HeatRestMethod $fakeEndPoint $fakeJSONMsg $fakeHeaders

            It "should verify PS major version" {
                Assert-MockCalled Get-PSMajorVersion -Exactly 1
            }
            It "should invoke rest method wrapper" {
                Assert-MockCalled Invoke-RestMethodWrapper `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Method -eq "POST") -and
                        ($Uri -eq $fakeEndPoint) -and
                        ($Body -eq $fakeJSONMsg) -and
                        (Compare-HashTables $Headers $fakeHeaders)
                    }
            }
            It "should not PS v4 native rest method" {
                Assert-MockCalled Invoke-RestMethod -Exactly 0
            }
        }

        Context "Powershell version 4 or bigger" {
            $psVer = 4

            Invoke-HeatRestMethod $fakeEndPoint $fakeJSONMsg $fakeHeaders

            It "should verify PS major version" {
                Assert-MockCalled Get-PSMajorVersion -Exactly 1
            }
            It "should not invoke rest method wrapper" {
                Assert-MockCalled Invoke-RestMethodWrapper -Exactly 0
            }
            It "should invoke PS v4 native rest method" {
                Assert-MockCalled Invoke-RestMethod `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Method -eq "POST") -and
                        ($Uri -eq $fakeEndPoint) -and
                        ($Body -eq $fakeJSONMsg) -and
                        (Compare-HashTables $Headers $fakeHeaders)
                    }
            }
        }
    }

    Describe "Send-HeatWaitSignal" {
        $fakeJSONMsg = 'Fake_JSON_Message'
        Mock ConvertTo-JSON { return $fakeJSONMsg } -Verifiable
        Mock Invoke-HeatRestMethod { return 0 } -Verifiable

        $fakeEndPoint =  "http://Fake_Endpoint"
        $fakeToken = "Fake_Token"
        $fakeMessage = 'Fake_Message'
        $heatMessage = @{
            "reason"="Configuration script has been executed.";
            "data"=$fakeMessage;
        }
        $hdrs = @{
            "X-Auth-Token"=$fakeToken;
            "Accept"="application/json";
            "Content-Type"= "application/json";
        }
        $statusMap = @{
            $true="SUCCESS";
            $false="FAILURE"
        }

        Context "State signal is sent" {
            $fakeSuccessState = $true
            $heatMessage["status"]=$statusMap[$fakeSuccessState];

            Send-HeatWaitSignal `
                $fakeEndPoint $fakeToken $fakeMessage $fakeSuccessState

            It "should create JSON message" {
                Assert-MockCalled ConvertTo-JSON `
                    -Exactly 1 `
                    -ParameterFilter {
                        (Compare-HashTables $InputObject $heatMessage)
                    }
            }
            It "should invoke heat rest method" {
                Assert-MockCalled Invoke-HeatRestMethod `
                    -Exactly 1 `
                    -ParameterFilter {
                        ($Endpoint -eq $fakeEndPoint) -and
                        ($HeatMessageJSON -eq $fakeJSONMsg) -and
                        (Compare-HashTables $Headers $hdrs)
                    }
            }
        }
    }
}
