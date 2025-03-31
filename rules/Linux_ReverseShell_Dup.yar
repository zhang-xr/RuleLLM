rule Linux_ReverseShell_Dup {
    meta:
        author = "RuleLLM"
        description = "Detects Linux-specific reverse shell using file descriptor duplication"
        confidence = 90
        severity = 85
    
    strings:
        $dup_calls = /os\.dup2\(sock\.fileno\(\),\d\)/
        $bash_call = /subprocess\.call\(\["\/bin\/bash","\-i"\]\)/
        $socket_connect = /sock\.connect\(\(IP,\d+\)\)/
        $socket_import = "import socket"
    
    condition:
        all of ($dup_calls, $bash_call) and 1 of ($socket_connect, $socket_import)
}