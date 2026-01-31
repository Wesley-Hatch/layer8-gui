import os
import subprocess

# Define paths
script_path = r'C:\Users\SirSq\PyCharmMiscProject\PyCharmMiscProject\gui_app.pyw'
icon_path = r'C:\Users\SirSq\PyCharmMiscProject\PyCharmMiscProject\Layer8\Media\Layer8-logo.ico'
pythonw_path = r'C:\Users\SirSq\PyCharmMiscProject\.venv\Scripts\pythonw.exe'
desktop = os.path.join(os.environ['USERPROFILE'], 'OneDrive', 'Desktop')
shortcut_path = os.path.join(desktop, 'Layer8_GUI.lnk')

# PowerShell command to create shortcut
ps_script = f'''
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
$Shortcut.TargetPath = "{pythonw_path}"
$Shortcut.Arguments = "{script_path}"
$Shortcut.IconLocation = "{icon_path}"
$Shortcut.WorkingDirectory = "{os.path.dirname(script_path)}"
$Shortcut.Save()
'''

# Execute PowerShell
subprocess.run(["powershell", "-Command", ps_script], check=True)
print(f"Shortcut created at {shortcut_path} pointing to pythonw.exe")