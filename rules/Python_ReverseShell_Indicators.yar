rule Python_ReverseShell_Indicators {
    meta:
        author = "RuleLLM"
        description = "Detects common reverse shell indicators in Python code"
        confidence = "95"
        severity = "95"
    
    strings:
        $socket = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $connect = /s\.connect\(\([\"\'].+[\"\'],\s*\d+\)/
        $dup2 = /os\.dup2\(s\.fileno\(\),\d\)/
        $pty = "pty.spawn("
    
    condition:
        3 of them
}