rule Malicious_Socket_Connection {
    meta:
        author = "RuleLLM"
        description = "Detects Python script connecting to a hardcoded suspicious IP address for data exfiltration."
        confidence = 95
        severity = 90

    strings:
        $ip = "134.209.85.64"
        $port = "9090"
        $socket_import = "import socket"
        $socket_connect = "clientSocket.connect"

    condition:
        all of them and filesize < 10KB
}