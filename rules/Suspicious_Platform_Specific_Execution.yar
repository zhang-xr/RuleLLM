rule Suspicious_Platform_Specific_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects platform-specific command execution patterns"
        confidence = 85
        severity = 75
    strings:
        $platform_check = "platform.system()"
        $python_cmd = /pycmd\s*=\s*['"]python/
        $subprocess_call = /subprocess\.Popen\(\[pycmd,/
        $base64_cmd = /cmd\s*=\s*['"][A-Za-z0-9+\/]+={0,2}['"]/
        $windows_cmd = /pycmd\s*=\s*'python'/
        $other_os_cmd = /pycmd\s*=\s*'python3'/
    condition:
        all of ($platform_check, $subprocess_call) and 
        any of ($python_cmd, $windows_cmd, $other_os_cmd) and 
        any of ($base64_cmd) and 
        filesize < 100KB
}