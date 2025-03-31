rule Python_ReverseShell_In_PipPackage {
    meta:
        author = "RuleLLM"
        description = "Detects a Python reverse shell payload in a pip package setup script."
        confidence = 90
        severity = 95

    strings:
        $socket_import = "import socket"
        $os_import = "import os"
        $pty_import = "import pty"
        $socket_connect = "s.connect"
        $os_dup2 = "os.dup2"
        $pty_spawn = "pty.spawn('/bin/bash')"
        $base64_exec = "os.system('echo %s|base64 -d|bash')"

    condition:
        all of them and filesize < 10KB
}