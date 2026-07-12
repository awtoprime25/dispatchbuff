# Creates (or updates) a Desktop shortcut to dispatch-start.bat with the
# Terminal Messenger icon — run this once. Re-run any time to fix/replace it.
#
# Target is cmd.exe (not the .bat directly): Windows refuses to show "Pin to
# taskbar" for shortcuts whose target is a script (.bat/.ps1/.vbs) — only
# real .exe targets are pinnable. Pointing at cmd.exe /c "...bat" makes the
# shortcut pinnable while still running the same launcher.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$shell = New-Object -ComObject WScript.Shell
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'DispatchFreeBuff.lnk'
$batPath = Join-Path $here 'dispatch-start.bat'

$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "$env:WINDIR\System32\cmd.exe"
$shortcut.Arguments = "/c `"$batPath`""
$shortcut.WorkingDirectory = $here
$shortcut.IconLocation = Join-Path $here 'dispatch-icon.ico'
$shortcut.Description = 'Pair + start DispatchFreeBuff'
$shortcut.Save()

Write-Output "Shortcut created: $shortcutPath"
Write-Output "Now right-click it -> Show more options -> Pin to taskbar (should work now)."
