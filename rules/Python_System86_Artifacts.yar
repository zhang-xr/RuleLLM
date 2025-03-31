rule Python_System86_Artifacts {
    meta:
        author = "RuleLLM"
        description = "Detects references to suspicious System86 directory and artifacts"
        confidence = 85
        severity = 80
    strings:
        $system86 = /C:\\Users\\\{[^}]+\}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System86/
        $runtime_exe = "Runtime.exe"
        $bitsadmin = "bitsadmin /transfer"
    condition:
        all of them and filesize < 50KB
}