rule Python_Reverse_Shell_Network {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell patterns with network connection setup"
        confidence = 90
        severity = 85
    strings:
        $socket_import = "import socket"
        $socket_create = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $dup2_pattern = /os\.dup2\(s\.fileno\(\)\,\d\)/
        $url_open = "urllib.request.urlopen"
    condition:
        all of them and filesize < 10KB
}