#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ArmTtkModulePath,
    [switch] $AzureValidation,
    [string] $ResourceGroupName,
    [string] $ParametersFile
)

$ErrorActionPreference = 'Stop'
$template = Join-Path $PSScriptRoot 'azuredeploy.json'
[void](Get-Content -LiteralPath $template -Raw | ConvertFrom-Json -Depth 100)
Import-Module $ArmTtkModulePath -Force
$skip = @(
    # OpenAPI operationId is not an ARM resource ID.
    'IDs Should Be Derived From ResourceIDs',
    # Empty no-auth security, optional diagnostics and reset-error strings are valid.
    'Template Should Not Contain Blanks'
)
Write-Warning 'Two generic ARM-TTK rules are excluded for embedded OpenAPI/native workflow values; see README and the independent structural tests.'
$results = @(Test-AzTemplate -TemplatePath $PSScriptRoot -File 'azuredeploy.json' -Skip $skip)
$results | Select-Object Name,Passed,Errors | Format-Table -Wrap
if (@($results | Where-Object { $_.Passed -eq $false }).Count -gt 0) {
    throw 'Local ARM-TTK checks failed.'
}
if ($AzureValidation) {
    if (-not $ResourceGroupName -or -not $ParametersFile) {
        throw '-ResourceGroupName and -ParametersFile are required for Azure validation.'
    }
    if (-not (Get-Command Test-AzResourceGroupDeployment -ErrorAction Ignore)) {
        throw 'Install/import Az.Resources and authenticate before Azure validation.'
    }
    $issues = @(Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName `
        -TemplateFile $template -TemplateParameterFile $ParametersFile)
    if ($issues.Count -gt 0) {
        $issues | Format-List
        throw 'Azure resource-group deployment validation reported issues.'
    }
    Write-Output 'Azure pre-deployment validation completed. No deployment was executed.'
}
else {
    Write-Output 'Local ARM checks passed. Azure tenant-side deployment validation was NOT executed.'
}
