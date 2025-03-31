rule Windows_Startup_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects creation of Windows startup persistence mechanisms"
        confidence = 95
        severity = 95
    strings:
        $startup_path1 = /C:\\Users\\\{[^}]+\}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/
        $startup_path2 = /C:\\Users\\\{[^}]+\}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64/
        $vbs_creation = /\.vbs\", \"a\"\)\.write\(/
        $bat_creation = /\.bat\", \"a\"\)\.write\(/
    condition:
        any of ($startup_path*) and any of ($vbs_creation, $bat_creation)
}