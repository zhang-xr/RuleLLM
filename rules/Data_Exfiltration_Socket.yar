rule Data_Exfiltration_Socket {
    meta:
        author = "RuleLLM"
        description = "Detects code that sends collected data to a remote server via a socket connection."
        confidence = "95"
        severity = "85"
    strings:
        $socket_connect = "socket.connect"
        $socket_send = "socket.send"
        $ip_address = "134.209.85.64"
    condition:
        all of them
}