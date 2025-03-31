rule Malicious_Python_Socket_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with suspicious socket communication to a hardcoded IP and port."
        confidence = 90
        severity = 85
    strings:
        $socket_import = "import socket"
        $socket_connect = "sock.connect(server_address)"
        $hardcoded_ip = /ip\s*=\s*\"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\"/
        $hardcoded_port = /port\s*=\s*\d{1,5}/
    condition:
        all of them
}