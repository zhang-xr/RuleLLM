rule Malicious_Git_Clone_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects malicious use of git clone for persistence"
        confidence = 95
        severity = 90
    strings:
        $git_clone1 = /git\.Git\(.*\)\.clone\(/
        $git_clone2 = /gitUrl\s*=\s*"https:\/\/github\.com/
        $startup_path = /AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu/i
    condition:
        all of them
}