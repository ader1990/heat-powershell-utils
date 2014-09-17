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
$modulePath = "..\heat-powershell-utils.psm1"

Remove-Module -Name $moduleName -ErrorAction SilentlyContinue
Import-Module -Name $modulePath -DisableNameChecking -Force

InModuleScope $moduleName {
    Describe "Test heat log" {
        Context "On success" {
            Mock Write-Host{ return $true } -Verifiable

            Log-HeatMessage

            It "should verify caled all mocks" {
                Assert-VerifiableMocks
            }
        }
    }
}