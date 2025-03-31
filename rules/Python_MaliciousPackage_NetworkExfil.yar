rule Python_MaliciousPackage_NetworkExfil {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with suspicious network exfiltration patterns"
        confidence = 95
        severity = 90
    strings:
        $socket_connect = "socket.connect"
        $socket_create = "socket.socket"
        $ip_address = "134.209.85.64"
        $port = "9090"
        $send_method = "send("
    condition:
        all of them and filesize < 10KB
}