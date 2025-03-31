rule Python_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects Python code creating a reverse shell"
        confidence = 90
        severity = 95

    strings:
        $socket_import = "import socket"
        $subprocess_import = "import subprocess"
        $os_import = "import os"
        $reverse_shell = /s\.connect\(\(\"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\",\s*\d{1,5}\)\);/
        $dup2 = "os.dup2(s.fileno(),"
        $bin_sh = "/bin/sh"

    condition:
        all of them
}