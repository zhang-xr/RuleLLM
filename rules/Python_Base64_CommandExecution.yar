rule Python_Base64_CommandExecution {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded command execution in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $base64_func = /def\s+\w+\(\s*base64_code\s*\):/
        $base64_decode = /base64\.b64decode\(/
        $os_system = /os\.system\(/
        $base64_usage = /\w+\(\s*\"[A-Za-z0-9+\/]+={0,2}\"\s*\)/
    condition:
        all of them and
        filesize < 10KB
}