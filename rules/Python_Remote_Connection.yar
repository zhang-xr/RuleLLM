rule Python_Remote_Connection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code establishing remote connections to specific IP addresses"
        confidence = 95
        severity = 90
    strings:
        $socket = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $connect = "clientSocket.connect"
        $ip_address = "134.209.85.64"
    condition:
        all of them
}