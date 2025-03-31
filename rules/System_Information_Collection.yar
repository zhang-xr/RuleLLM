rule System_Information_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system information (hostname and IP address)."
        confidence = 80
        severity = 75

    strings:
        $hostname = "socket.gethostname()"
        $ipaddr = "socket.gethostbyname(hostname)"
        $socket_import = "import socket"

    condition:
        $hostname and $ipaddr and $socket_import
}