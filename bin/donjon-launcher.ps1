#Requires -Version 5.0
<#
.SYNOPSIS
    Donjon Platform v7.0 - PowerShell Launcher
.DESCRIPTION
    Finds Python and runs bin/donjon-launcher.
.NOTES
    If you get an execution policy error, run:
      Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$Launcher = Join-Path $ScriptDir "donjon-launcher"
$VenvPython = Join-Path $RootDir "venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    & $VenvPython $Launcher @Arguments
} else {
    & python $Launcher @Arguments
}

exit $LASTEXITCODE
