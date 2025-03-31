rule Python_MaliciousCalculator {
    meta:
        author = "RuleLLM"
        description = "Detects malicious calculator class with hidden functionality"
        confidence = "95"
        severity = "95"
    
    strings:
        $class = "class calculator:"
        $add = "def add(x, y):"
        $requests = "requests.get("
        $socket = "socket.socket("
        $pty = "pty.spawn("
    
    condition:
        $class and $add and 
        (2 of ($requests, $socket, $pty))
}