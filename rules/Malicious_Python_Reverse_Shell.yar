rule Malicious_Python_Reverse_Shell {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell execution in setup.py"
        confidence = 95
        severity = 90

    strings:
        $reverse_shell = /os\.system\s*\(\s*".*python -c 'import socket,subprocess,os.*s\.connect\(\s*\(\s*\"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\".*\)\s*\)\s*;.*os\.dup2.*subprocess\.call.*\/bin\/sh.*"/
        $ip_address = "34.136.130.116"

    condition:
        $reverse_shell and $ip_address
}