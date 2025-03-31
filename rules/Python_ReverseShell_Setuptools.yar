rule Python_ReverseShell_Setuptools {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell backdoor hidden in setuptools installation class"
        confidence = 90
        severity = 95

    strings:
        $socket_import = "import socket"
        $os_import = "import os"
        $pty_import = "import pty"
        $setuptools_class = "class myclass(install):"
        $socket_connect = /s\.connect\(\(.*\)\)/
        $os_dup2 = /os\.dup2\(.*\)/
        $pty_spawn = /pty\.spawn\(.*\)/
        $lhost = "85.159.212.47"
        $lport = "61985"

    condition:
        all of ($socket_import, $os_import, $pty_import) and
        any of ($socket_connect, $os_dup2, $pty_spawn) and
        ($lhost or $lport) and
        $setuptools_class
}