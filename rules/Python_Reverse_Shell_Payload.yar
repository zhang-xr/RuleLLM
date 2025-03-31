rule Python_Reverse_Shell_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python code implementing a reverse shell payload using socket, dup2, and pty.spawn"
        confidence = 95
        severity = 90

    strings:
        $socket = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $dup2 = "os.dup2(s.fileno(),"
        $pty_spawn = "pty.spawn(\"/bin/sh\")"
        $connect = "s.connect(("

    condition:
        all of them
}