rule Python_Suspicious_Network_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious network communication patterns in Python code"
        confidence = 95
        severity = 90
        reference = "Hardcoded IP and port with socket communication"
    
    strings:
        $socket_init = "socket.socket(" nocase wide ascii
        $socket_connect = ".connect(" nocase wide ascii
        $send_data = ".sendall(" nocase wide ascii
        $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase wide ascii
        $port_pattern = /port\s*=\s*\d{1,5}/ nocase wide ascii
    
    condition:
        all of ($socket_init, $socket_connect, $send_data) and 
        ($ip_pattern or $port_pattern)
}