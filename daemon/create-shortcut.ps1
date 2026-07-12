# Creates (or updates) a Desktop shortcut to dispatch-start.bat with the
# Terminal Messenger icon — run this once. Re-run any time to fix/replace it.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$shell = New-Object -ComObject WScript.Shell
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'DispatchFreeBuff.lnk'

$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $here 'dispatch-start.bat'
$shortcut.WorkingDirectory = $here
$shortcut.IconLocation = Join-Path $here 'dispatch-icon.ico'
$shortcut.Description = 'Pair + start DispatchFreeBuff'
$shortcut.Save()

Write-Output "Shortcut created: $shortcutPath"
