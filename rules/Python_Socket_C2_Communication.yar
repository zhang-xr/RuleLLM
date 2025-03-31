rule Python_Socket_C2_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based socket communication with hardcoded IP and port, commonly used for C2 communication"
        confidence = 90
        severity = 80
    strings:
        $socket_import = "import socket"
        $socket_create = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
        $connect_call = /sock\.connect\(\([\"'].+[\"'],\s*\d{1,5}\)\)/
        $send_call = /sock\.sendall\(.+\.encode\([\"']utf-8[\"']\)\)/
        $recv_call = /sock\.recv\(\d+\)/
    condition:
        all of them and 
        not filesize < 1KB and 
        not $socket_import in (0..filesize-100)
}