rule Python_SuspiciousSocketConnection {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious socket connections in Python code"
        confidence = 85
        severity = 75
    strings:
        $socket_import = "import socket"
        $socket_create = "socket.socket"
        $socket_connect = /\.connect\(\s*\(.*\)\s*\)/
        $ip_port = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*,\s*\d{1,5}/
    condition:
        all of them
}