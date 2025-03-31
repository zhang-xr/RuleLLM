rule Python_ReverseShell_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell behavior involving socket creation, file descriptor redirection, and shell spawning."
        confidence = 90
        severity = 95

    strings:
        $socket_create = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $socket_connect = /s\.connect\(\("[\d\.]+",\s*\d+\)\)/
        $dup2 = "os.dup2(s.fileno(),"
        $spawn_shell = "pty.spawn(\"/bin/sh\")"

    condition:
        all of them
}