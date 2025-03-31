rule Windows_Startup_Registry_Modification {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to modify Windows startup registry entries"
        confidence = "90"
        severity = "85"
    
    strings:
        $reg_path = /HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/
        $reg_mod = /reg\s+add\s+[^\/]+\/v\s+[^\/]+\/t\s+REG_SZ\s+\/d\s+[^\/]+\/f/
        $startup_exe = /Start Menu\\Programs\\Startup\\[^\\]+\.exe/
    
    condition:
        2 of them
}