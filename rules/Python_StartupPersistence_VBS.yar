rule Python_StartupPersistence_VBS {
    meta:
        author = "RuleLLM"
        description = "Detects creation of VBS scripts in Windows startup locations"
        confidence = 90
        severity = 85
    strings:
        $startup_path = /C:\\Users\\\{[^}]+\}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\(Startup|System86)/
        $vbs_script = /Set WshShell = CreateObject\("WScript\.Shell"\)/
        $vbs_run = /WshShell\.Run/
    condition:
        2 of them and filesize < 50KB
}