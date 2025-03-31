rule Python_ReverseShell_Backdoor {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell backdoor using socket and subprocess"
        confidence = 90
        severity = 95

    strings:
        $socket_import = "import socket"
        $subprocess_import = "import subprocess"
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $socket_connect = "sock.connect"
        $subprocess_popen = "subprocess.Popen"
        $cmd_exec = /cmd.*\/K.*cd/
        $bash_exec = "/bin/bash"

    condition:
        all of ($socket_import, $subprocess_import, $socket_create, $socket_connect) and
        (1 of ($cmd_exec, $bash_exec)) and
        $subprocess_popen
}