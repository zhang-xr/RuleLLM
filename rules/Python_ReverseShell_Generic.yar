rule Python_ReverseShell_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects generic Python reverse shell patterns using socket and pty"
        confidence = 85
        severity = 90

    strings:
        $socket_import = "import socket"
        $os_import = "import os"
        $pty_import = "import pty"
        $socket_connect = /s\.connect\(\(.*\)\)/
        $os_dup2 = /os\.dup2\(.*\)/
        $pty_spawn = /pty\.spawn\(.*\)/

    condition:
        all of ($socket_import, $os_import, $pty_import) and
        any of ($socket_connect, $os_dup2, $pty_spawn)
}