rule Python_Base64_ReverseShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded reverse shell execution in Python scripts"
        confidence = 85
        severity = 90
    strings:
        $base64_encode = "base64.b64encode("
        $bash_exec = /echo\s+.*\|base64\s+-d\|bash/
        $socket_connect = /s\.connect\(\([\'\"].*[\'\"],\s*\d+\)\)/
    condition:
        all of them
}