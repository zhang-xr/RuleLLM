rule Malicious_Shell_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious shell command execution via curl and sh"
        confidence = 90
        severity = 95
    strings:
        $curl_command = /curl\s+http:\/\/[^\s]+\s*\|\s*sh/
        $os_system = "os.system"
    condition:
        $os_system and $curl_command
}