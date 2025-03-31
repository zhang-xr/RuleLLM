rule Malicious_Shell_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects shell command execution patterns commonly used in malware to download and execute arbitrary code."
        confidence = 90
        severity = 80

    strings:
        $shell_command = /os\.system\s*\(\s*[\'\"].*curl\s+http:\/\/[^\s]+\s*\|sh[\'\"]\s*\)/
        $curl_pattern = "curl http://"
        $sh_pattern = "|sh"

    condition:
        $shell_command or ($curl_pattern and $sh_pattern)
}