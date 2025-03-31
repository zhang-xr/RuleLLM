rule Python_Startup_Folder_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects Python code creating files in Windows startup folders"
        confidence = 85
        severity = 75
    strings:
        $startup_path1 = /C:\\Users\\\{[^}]+\}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/
        $startup_path2 = /C:\\Users\\\{[^}]+\}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64/
        $file_creation = /open\(.*, "a"\)\.write\(/
        $vbs_content = /Set WshShell = CreateObject\("WScript.Shell"\)/
    condition:
        2 of ($startup_path*) and ($file_creation or $vbs_content)
}