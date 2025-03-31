rule Malicious_Python_Setup_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup.py scripts that execute reverse shells during installation"
        confidence = 90
        severity = 95

    strings:
        $setup_py = "from setuptools import setup"
        $custom_install = "class CustomInstall(install)"
        $reverse_shell = /python3 -c "import os; import pty; import socket; s = socket\.socket\(socket\.AF_INET, socket\.SOCK_STREAM\); s\.connect\(\(.*\)\); os\.dup2\(s\.fileno\(\), \d\); os\.dup2\(s\.fileno\(\), \d\); os\.dup2\(s\.fileno\(\), \d\); os\.putenv\('HISTFILE', '\/dev\/null'\); pty\.spawn\('\/bin\/bash'\); s\.close\(\);"/
        $base64_exec = "os.system('echo %s|base64 -d|bash'"

    condition:
        all of them
}