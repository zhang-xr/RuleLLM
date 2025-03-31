rule Malicious_Python_ReverseShell_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files containing reverse shell installation code"
        confidence = 90
        severity = 95
    strings:
        $install_class = "class CustomInstall(install):"
        $reverse_shell = /s\.connect\(\([\'\"].*[\'\"],\s*\d+\)\)/
        $base64_exec = /os\.system\(\'echo\s+%s\|base64\s+-d\|bash\'/
        $dup2_pattern = /os\.dup2\(s\.fileno\(\),\s*\d+\)/
        $pty_spawn = "pty.spawn('/bin/bash')"
    condition:
        all of them
}