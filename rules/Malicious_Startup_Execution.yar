rule Malicious_Startup_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious startup file execution patterns"
        confidence = 90
        severity = 95
    strings:
        $startup_exe1 = /os\.startfile\(.*\.exe/i
        $startup_path = /AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu/i
        $git_clone = /git\.Git\(.*\)\.clone\(/
    condition:
        all of them
}