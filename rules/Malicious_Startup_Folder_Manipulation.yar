rule Malicious_Startup_Folder_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to create or modify files in Windows startup folders"
        confidence = "90"
        severity = "85"
    
    strings:
        $startup_path1 = /C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/
        $startup_path2 = /C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System86/
        $vbs_creation = /Set WshShell = CreateObject\(\"WScript\.Shell\"\)/
        $bat_creation = /bitsadmin \/transfer/
    
    condition:
        2 of them
}