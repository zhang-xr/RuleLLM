rule Malicious_Python_Startup_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects Python code creating startup persistence in Windows"
        confidence = 90
        severity = 85
    strings:
        $startup_path1 = /AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup/i
        $startup_path2 = /os\.makedirs\(.*Start Menu/i
        $startup_path3 = /os\.rename\(.*Start Menu/i
        $persistence1 = /os\.startfile\(.*Start Menu/i
    condition:
        any of them and filesize < 10KB
}