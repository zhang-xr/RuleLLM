rule Python_Reverse_Shell_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects common Python reverse shell patterns"
        confidence = 92
        severity = 95
    strings:
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $connect = "s.connect"
        $dup2 = "os.dup2" nocase
        $pty = "pty.spawn" nocase
    condition:
        all of ($socket_create, $connect) and 
        any of ($dup2, $pty)
}