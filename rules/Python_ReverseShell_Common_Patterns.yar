rule Python_ReverseShell_Common_Patterns {
    meta:
        author = "RuleLLM"
        description = "Detects common reverse shell patterns in Python code"
        confidence = 95
        severity = 100
        reference = "Analyzed code segment"
    
    strings:
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $socket_connect = /s\.connect\(\([\'\"].*[\'\"]\,\s*\d+\)\)/
        $dup2_pattern = "os.dup2(s.fileno()"
        $pty_spawn = "pty.spawn"
    
    condition:
        3 of them
}